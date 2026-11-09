#ifndef __WARDEN_H
#define __WARDEN_H

#define MAX_PATH_LEN 256
#define TASK_COMM_LEN 16

/* Operation types representing the causal flow transitions */
enum op_type_t {
    WARDEN_OP_UNKNOWN   = 0,
    WARDEN_OP_FORK      = 1, /* P -> P: Process derivation (sched_process_fork) */
    WARDEN_OP_EXEC      = 2, /* P -> P: Image replacement / version continuity (sched_process_exec) */
    WARDEN_OP_WRITE     = 3, /* P -> F: Entity write propagation (vfs_write, ret > 0) */
    WARDEN_OP_READ      = 4, /* F -> P: Entity read back-propagation (vfs_read, ret > 0) */
    WARDEN_OP_EXIT      = 5, /* P -> P: Exit-triggered causal aggregation (sched_process_exit) */
    WARDEN_OP_RENAME    = 6, /* Namespace alteration preserving inode mark */
    WARDEN_OP_AGGREGATE = 7, /* Explicit causal aggregation edge */
};

/* State backend selection */
enum backend_mode_t {
    BACKEND_HASH  = 0, /* Warden-Hash: PID & Inode hash maps */
    BACKEND_LOCAL = 1, /* Warden-Local: BPF task/inode local storage */
};

/* Inode identifier key for Warden-Hash */
struct inode_key_t {
    __u64 dev;
    __u64 ino;
};

/* Unified event structure emitted to user space via BPF RingBuffer */
struct event_t {
    __u64 timestamp_ns;
    __u32 op_type;
    __u32 ppid;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u64 dev;
    __u64 inode_no;
    __s64 ret_bytes;
    char comm[TASK_COMM_LEN];
    char target_name[MAX_PATH_LEN];
    char extra_info[MAX_PATH_LEN];
};

/* Provenance state stored in task/inode local storage or hash map */
struct prov_state_t {
    __u32 marked;             /* 1 if marked as part of tracked agent lineage */
    __u32 agent_root_tgid;    /* The root agent TGID that initiated the lineage */
    __u64 first_marked_ts;    /* Timestamp when first marked */
    __u64 last_event_ts;      /* Timestamp of latest causal event */
};

#endif /* __WARDEN_H */
