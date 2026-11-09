#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "warden.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define S_IFMT  00170000
#define S_IFREG 0100000
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)

/* Ring buffer for asynchronous event emission to user space */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024); /* 1MB buffer */
} events SEC(".maps");

/* Configuration parameters tunable from user space */
volatile const __u32 cfg_target_agent_tgid = 0;
volatile const __u32 cfg_backend_mode = BACKEND_HASH;

/* Warden-Hash State Maps */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32); /* tgid */
    __type(value, struct prov_state_t);
} hash_task_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct inode_key_t);
    __type(value, struct prov_state_t);
} hash_inode_map SEC(".maps");

/* Warden-Local State Map (Task Local Storage) */
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct prov_state_t);
} local_task_map SEC(".maps");

/* In-flight context for rename operations */
#define RENAME_NAME_LEN 128
struct rename_ctx_t {
    char oldname[RENAME_NAME_LEN];
    char newname[RENAME_NAME_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64); /* pid_tgid */
    __type(value, struct rename_ctx_t);
} inflight_renames SEC(".maps");

/* Per-CPU scratch space for rename temp context to keep stack lean */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rename_ctx_t);
} rename_scratch SEC(".maps");

/* -------------------------------------------------------------
 * Dual-Backend State Access Abstraction
 * ------------------------------------------------------------- */
static __always_inline struct prov_state_t *get_task_prov(struct task_struct *task, __u32 tgid)
{
    struct prov_state_t *st = NULL;

    if (cfg_backend_mode == BACKEND_LOCAL && task) {
        st = bpf_task_storage_get(&local_task_map, task, 0, 0);
    } else {
        st = bpf_map_lookup_elem(&hash_task_map, &tgid);
    }

    /* Auto-mark root agent if specified by config */
    if (!st && cfg_target_agent_tgid != 0 && tgid == cfg_target_agent_tgid) {
        struct prov_state_t init_st;
        __builtin_memset(&init_st, 0, sizeof(init_st));
        init_st.marked = 1;
        init_st.agent_root_tgid = tgid;
        init_st.first_marked_ts = bpf_ktime_get_ns();
        init_st.last_event_ts = init_st.first_marked_ts;

        if (cfg_backend_mode == BACKEND_LOCAL && task) {
            st = bpf_task_storage_get(&local_task_map, task, &init_st, BPF_LOCAL_STORAGE_GET_F_CREATE);
        } else {
            bpf_map_update_elem(&hash_task_map, &tgid, &init_st, BPF_ANY);
            st = bpf_map_lookup_elem(&hash_task_map, &tgid);
        }
    }
    return st;
}

static __always_inline void set_task_prov(struct task_struct *task, __u32 tgid, struct prov_state_t *st)
{
    if (cfg_backend_mode == BACKEND_LOCAL && task) {
        struct prov_state_t *local_st = bpf_task_storage_get(&local_task_map, task, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
        if (local_st) {
            *local_st = *st;
        }
    } else {
        bpf_map_update_elem(&hash_task_map, &tgid, st, BPF_ANY);
    }
}

static __always_inline void del_task_prov(struct task_struct *task, __u32 tgid)
{
    if (cfg_backend_mode == BACKEND_LOCAL && task) {
        bpf_task_storage_delete(&local_task_map, task);
    } else {
        bpf_map_delete_elem(&hash_task_map, &tgid);
    }
}

static __always_inline struct prov_state_t *get_inode_prov(struct inode *inode, __u64 dev, __u64 ino)
{
    struct inode_key_t key = { .dev = dev, .ino = ino };
    return bpf_map_lookup_elem(&hash_inode_map, &key);
}

static __always_inline void set_inode_prov(struct inode *inode, __u64 dev, __u64 ino, struct prov_state_t *st)
{
    struct inode_key_t key = { .dev = dev, .ino = ino };
    bpf_map_update_elem(&hash_inode_map, &key, st, BPF_ANY);
}

/* -------------------------------------------------------------
 * Rule 1: Process Derivation (P -> P)
 * ------------------------------------------------------------- */
SEC("tp_btf/sched_process_fork")
int BPF_PROG(on_process_fork, struct task_struct *parent, struct task_struct *child)
{
    __u32 parent_tgid = parent->tgid;
    __u32 child_tgid = child->tgid;
    __u32 child_pid = child->pid;

    struct prov_state_t *p_st = get_task_prov(parent, parent_tgid);
    if (!p_st || !p_st->marked)
        return 0;

    /* Propagate taint state to child */
    struct prov_state_t c_st;
    __builtin_memset(&c_st, 0, sizeof(c_st));
    c_st.marked = 1;
    c_st.agent_root_tgid = p_st->agent_root_tgid;
    c_st.first_marked_ts = bpf_ktime_get_ns();
    c_st.last_event_ts = c_st.first_marked_ts;
    set_task_prov(child, child_tgid, &c_st);

    /* Emit fork event to ringbuffer */
    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->op_type = WARDEN_OP_FORK;
    e->ppid = parent_tgid;
    e->pid = child_pid;
    e->tgid = child_tgid;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->dev = 0;
    e->inode_no = 0;
    e->ret_bytes = 0;
    bpf_probe_read_kernel_str(e->comm, sizeof(e->comm), parent->comm);
    bpf_probe_read_kernel_str(e->target_name, sizeof(e->target_name), child->comm);
    e->extra_info[0] = '\0';

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(on_process_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
    __u32 tgid = p->tgid;
    struct prov_state_t *st = get_task_prov(p, tgid);
    if (!st || !st->marked)
        return 0;

    st->last_event_ts = bpf_ktime_get_ns();

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->op_type = WARDEN_OP_EXEC;
    e->ppid = p->real_parent ? p->real_parent->tgid : 0;
    e->pid = p->pid;
    e->tgid = tgid;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->dev = 0;
    e->inode_no = 0;
    e->ret_bytes = 0;
    bpf_probe_read_kernel_str(e->comm, sizeof(e->comm), p->comm);

    const char *fn = BPF_CORE_READ(bprm, filename);
    if (fn) {
        bpf_probe_read_kernel_str(e->target_name, sizeof(e->target_name), fn);
    } else {
        e->target_name[0] = '\0';
    }
    e->extra_info[0] = '\0';

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* -------------------------------------------------------------
 * Rule 2: Entity Write Propagation (P -> F)
 * ------------------------------------------------------------- */
SEC("fexit/vfs_write")
int BPF_PROG(on_vfs_write, struct file *file, const char *buf, size_t count, loff_t *pos, ssize_t ret)
{
    if (ret <= 0)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    __u32 tgid = task->tgid;

    struct prov_state_t *t_st = get_task_prov(task, tgid);
    if (!t_st || !t_st->marked)
        return 0;

    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode)
        return 0;

    umode_t mode = BPF_CORE_READ(inode, i_mode);
    if (!S_ISREG(mode))
        return 0;

    __u64 ino = BPF_CORE_READ(inode, i_ino);
    __u64 dev = BPF_CORE_READ(inode, i_sb, s_dev);

    /* Mark the inode */
    struct prov_state_t i_st;
    __builtin_memset(&i_st, 0, sizeof(i_st));
    i_st.marked = 1;
    i_st.agent_root_tgid = t_st->agent_root_tgid;
    i_st.first_marked_ts = bpf_ktime_get_ns();
    i_st.last_event_ts = i_st.first_marked_ts;
    set_inode_prov(inode, dev, ino, &i_st);

    /* Emit write propagation event */
    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->op_type = WARDEN_OP_WRITE;
    e->ppid = task->real_parent ? task->real_parent->tgid : 0;
    e->pid = task->pid;
    e->tgid = tgid;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->dev = dev;
    e->inode_no = ino;
    e->ret_bytes = ret;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    if (dentry) {
        const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
        if (name)
            bpf_probe_read_kernel_str(e->target_name, sizeof(e->target_name), name);
        else
            e->target_name[0] = '\0';
    } else {
        e->target_name[0] = '\0';
    }
    e->extra_info[0] = '\0';

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* -------------------------------------------------------------
 * Rule 3: Entity Read Back-Propagation (F -> P)
 * ------------------------------------------------------------- */
SEC("fexit/vfs_read")
int BPF_PROG(on_vfs_read, struct file *file, char *buf, size_t count, loff_t *pos, ssize_t ret)
{
    if (ret <= 0)
        return 0;

    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode)
        return 0;

    umode_t mode = BPF_CORE_READ(inode, i_mode);
    if (!S_ISREG(mode))
        return 0;

    __u64 ino = BPF_CORE_READ(inode, i_ino);
    __u64 dev = BPF_CORE_READ(inode, i_sb, s_dev);

    /* Check if target inode is tainted */
    struct prov_state_t *i_st = get_inode_prov(inode, dev, ino);
    if (!i_st || !i_st->marked)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    __u32 tgid = task->tgid;

    struct prov_state_t *t_st = get_task_prov(task, tgid);
    int newly_marked = 0;
    if (!t_st || !t_st->marked) {
        /* Unmarked process reads marked file: propagate taint back to process */
        struct prov_state_t new_t_st;
        __builtin_memset(&new_t_st, 0, sizeof(new_t_st));
        new_t_st.marked = 1;
        new_t_st.agent_root_tgid = i_st->agent_root_tgid;
        new_t_st.first_marked_ts = bpf_ktime_get_ns();
        new_t_st.last_event_ts = new_t_st.first_marked_ts;
        set_task_prov(task, tgid, &new_t_st);
        newly_marked = 1;
    }

    /* Emit read propagation event */
    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->op_type = WARDEN_OP_READ;
    e->ppid = task->real_parent ? task->real_parent->tgid : 0;
    e->pid = task->pid;
    e->tgid = tgid;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->dev = dev;
    e->inode_no = ino;
    e->ret_bytes = ret;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    if (dentry) {
        const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
        if (name)
            bpf_probe_read_kernel_str(e->target_name, sizeof(e->target_name), name);
        else
            e->target_name[0] = '\0';
    } else {
        e->target_name[0] = '\0';
    }
    if (newly_marked)
        bpf_probe_read_kernel_str(e->extra_info, sizeof(e->extra_info), "TAINT_ACQUIRED");
    else
        e->extra_info[0] = '\0';

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* -------------------------------------------------------------
 * Rule 4: Exit-Triggered Causal Aggregation (P -> P)
 * ------------------------------------------------------------- */
SEC("tp_btf/sched_process_exit")
int BPF_PROG(on_process_exit, struct task_struct *p)
{
    __u32 tgid = p->tgid;
    __u32 pid = p->pid;

    /* Focus on main thread termination */
    if (pid != tgid)
        return 0;

    struct prov_state_t *st = get_task_prov(p, tgid);
    if (!st || !st->marked)
        return 0;

    struct task_struct *parent = p->real_parent;
    __u32 parent_tgid = 0;
    if (parent) {
        parent_tgid = parent->tgid;
        /* Conservative aggregation: propagate to parent if not marked */
        struct prov_state_t *parent_st = get_task_prov(parent, parent_tgid);
        if (!parent_st || !parent_st->marked) {
            struct prov_state_t agg_st;
            __builtin_memset(&agg_st, 0, sizeof(agg_st));
            agg_st.marked = 1;
            agg_st.agent_root_tgid = st->agent_root_tgid;
            agg_st.first_marked_ts = bpf_ktime_get_ns();
            agg_st.last_event_ts = agg_st.first_marked_ts;
            set_task_prov(parent, parent_tgid, &agg_st);
        }
    }

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->timestamp_ns = bpf_ktime_get_ns();
        e->op_type = WARDEN_OP_EXIT;
        e->ppid = parent_tgid;
        e->pid = pid;
        e->tgid = tgid;
        e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        e->dev = 0;
        e->inode_no = 0;
        e->ret_bytes = 0;
        bpf_probe_read_kernel_str(e->comm, sizeof(e->comm), p->comm);
        e->target_name[0] = '\0';
        bpf_probe_read_kernel_str(e->extra_info, sizeof(e->extra_info), "EXIT_AGGREGATED");
        bpf_ringbuf_submit(e, 0);
    }

    /* Explicit reclamation for Warden-Hash */
    if (cfg_backend_mode == BACKEND_HASH) {
        del_task_prov(p, tgid);
    }
    return 0;
}

/* -------------------------------------------------------------
 * Namespace Alteration: Rename tracking
 * ------------------------------------------------------------- */
SEC("tracepoint/syscalls/sys_enter_renameat2")
int trace_renameat2_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    struct prov_state_t *st = get_task_prov(task, tgid);
    if (!st || !st->marked)
        return 0;

    __u32 zero = 0;
    struct rename_ctx_t *rctx = bpf_map_lookup_elem(&rename_scratch, &zero);
    if (!rctx)
        return 0;

    const char *oldname = (const char *)ctx->args[1];
    const char *newname = (const char *)ctx->args[3];

    bpf_probe_read_user_str(rctx->oldname, sizeof(rctx->oldname), oldname);
    bpf_probe_read_user_str(rctx->newname, sizeof(rctx->newname), newname);

    bpf_map_update_elem(&inflight_renames, &pid_tgid, rctx, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_renameat2")
int trace_renameat2_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct rename_ctx_t *rctx = bpf_map_lookup_elem(&inflight_renames, &pid_tgid);
    if (!rctx)
        return 0;

    long ret = ctx->ret;
    if (ret == 0) {
        struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->timestamp_ns = bpf_ktime_get_ns();
            e->op_type = WARDEN_OP_RENAME;
            e->ppid = 0;
            e->pid = (__u32)pid_tgid;
            e->tgid = (__u32)(pid_tgid >> 32);
            e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
            e->dev = 0;
            e->inode_no = 0;
            e->ret_bytes = 0;
            bpf_get_current_comm(e->comm, sizeof(e->comm));
            bpf_probe_read_kernel_str(e->target_name, sizeof(e->target_name), rctx->newname);
            bpf_probe_read_kernel_str(e->extra_info, sizeof(e->extra_info), rctx->oldname);
            bpf_ringbuf_submit(e, 0);
        }
    }

    bpf_map_delete_elem(&inflight_renames, &pid_tgid);
    return 0;
}
