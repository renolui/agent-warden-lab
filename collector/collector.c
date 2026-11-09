#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "../ebpf/warden.h"
#include "../ebpf/warden.skel.h"

/* ANSI Colors for terminal logs */
#define COLOR_RESET   "\033[0m"
#define COLOR_BOLD    "\033[1m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_WHITE   "\033[37m"

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int sig)
{
    exiting = 1;
}

/* In-memory Graph Representation */
#define MAX_NODES 2048
#define MAX_EDGES 4096

enum node_kind {
    NODE_PROCESS = 1,
    NODE_FILE    = 2,
};

struct graph_node {
    char id[512];        /* Unique ID: "proc_1234" or "file_ino_5678" */
    char label[512];     /* Human-readable label: "Agent\n(PID:1001)" */
    enum node_kind kind;
    int is_root;
    uint32_t pid;
    uint64_t inode;
};

struct graph_edge {
    char src_id[512];
    char dst_id[512];
    char label[128];      /* "P->P Fork", "P->F Write", "F->P Read", "Exit Aggregation" */
    char color[32];      /* e.g. "red", "blue", "orange" */
    char style[32];      /* "solid", "dashed" */
};

struct provenance_graph {
    struct graph_node nodes[MAX_NODES];
    int node_count;
    struct graph_edge edges[MAX_EDGES];
    int edge_count;
    uint32_t root_pid;
};

static struct provenance_graph g_graph;

static struct graph_node *find_node(const char *id)
{
    for (int i = 0; i < g_graph.node_count; i++) {
        if (strcmp(g_graph.nodes[i].id, id) == 0)
            return &g_graph.nodes[i];
    }
    return NULL;
}

static struct graph_node *add_node(const char *id, const char *label, enum node_kind kind, uint32_t pid, uint64_t inode, int is_root)
{
    struct graph_node *n = find_node(id);
    if (n) {
        if (is_root)
            n->is_root = 1;
        return n;
    }
    if (g_graph.node_count >= MAX_NODES)
        return NULL;

    n = &g_graph.nodes[g_graph.node_count++];
    strncpy(n->id, id, sizeof(n->id) - 1);
    strncpy(n->label, label, sizeof(n->label) - 1);
    n->kind = kind;
    n->is_root = is_root;
    n->pid = pid;
    n->inode = inode;
    return n;
}

static void add_edge(const char *src_id, const char *dst_id, const char *label, const char *color, const char *style)
{
    /* Check for duplicate edge */
    for (int i = 0; i < g_graph.edge_count; i++) {
        if (strcmp(g_graph.edges[i].src_id, src_id) == 0 &&
            strcmp(g_graph.edges[i].dst_id, dst_id) == 0 &&
            strcmp(g_graph.edges[i].label, label) == 0) {
            return;
        }
    }
    if (g_graph.edge_count >= MAX_EDGES)
        return;

    struct graph_edge *e = &g_graph.edges[g_graph.edge_count++];
    strncpy(e->src_id, src_id, sizeof(e->src_id) - 1);
    strncpy(e->dst_id, dst_id, sizeof(e->dst_id) - 1);
    strncpy(e->label, label, sizeof(e->label) - 1);
    strncpy(e->color, color ? color : "black", sizeof(e->color) - 1);
    strncpy(e->style, style ? style : "solid", sizeof(e->style) - 1);
}

/* Event processing callback */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event_t *e = data;
    time_t raw_time = time(NULL);
    struct tm *lt = localtime(&raw_time);
    char time_str[32];
    strftime(time_str, sizeof(time_str), "%H:%M:%S", lt);

    char proc_id[512], child_id[512], file_id[512], parent_id[512];
    char proc_lbl[512], child_lbl[512], file_lbl[512], parent_lbl[512];

    snprintf(proc_id, sizeof(proc_id), "proc_%u", e->tgid);
    snprintf(proc_lbl, sizeof(proc_lbl), "%s\\n(PID: %u)", e->comm, e->tgid);

    int is_root = (g_graph.root_pid != 0 && e->tgid == g_graph.root_pid);
    add_node(proc_id, proc_lbl, NODE_PROCESS, e->tgid, 0, is_root);

    switch (e->op_type) {
    case WARDEN_OP_FORK:
        printf("%s[%s]%s %s[P->P FORK]%s Parent: " COLOR_CYAN "%s" COLOR_RESET " (PID:%u) -> Child: " COLOR_CYAN "%s" COLOR_RESET " (PID:%u)\n",
               COLOR_BOLD, time_str, COLOR_RESET, COLOR_BLUE, COLOR_RESET,
               e->comm, e->ppid, e->target_name[0] ? e->target_name : "child", e->tgid);

        snprintf(parent_id, sizeof(parent_id), "proc_%u", e->ppid);
        snprintf(parent_lbl, sizeof(parent_lbl), "%s\\n(PID: %u)", e->comm, e->ppid);
        add_node(parent_id, parent_lbl, NODE_PROCESS, e->ppid, 0, (g_graph.root_pid == e->ppid));

        add_edge(parent_id, proc_id, "Fork", "#1E88E5", "solid");
        break;

    case WARDEN_OP_EXEC:
        printf("%s[%s]%s %s[P->P EXEC]%s Process: " COLOR_CYAN "%s" COLOR_RESET " (PID:%u) -> Executed: " COLOR_YELLOW "%s" COLOR_RESET "\n",
               COLOR_BOLD, time_str, COLOR_RESET, COLOR_CYAN, COLOR_RESET,
               e->comm, e->tgid, e->target_name);

        snprintf(child_id, sizeof(child_id), "proc_%u_exec", e->tgid);
        snprintf(child_lbl, sizeof(child_lbl), "%s\\n(PID: %u)", e->target_name, e->tgid);
        add_node(child_id, child_lbl, NODE_PROCESS, e->tgid, 0, is_root);

        add_edge(proc_id, child_id, "Exec", "#00ACC1", "solid");
        break;

    case WARDEN_OP_WRITE:
        printf("%s[%s]%s %s[P->F WRITE]%s Process: " COLOR_CYAN "%s" COLOR_RESET " (PID:%u) -> Wrote " COLOR_GREEN "%s" COLOR_RESET " (Inode:%llu, Bytes:%lld)\n",
               COLOR_BOLD, time_str, COLOR_RESET, COLOR_YELLOW, COLOR_RESET,
               e->comm, e->tgid, e->target_name, (unsigned long long)e->inode_no, (long long)e->ret_bytes);

        snprintf(file_id, sizeof(file_id), "file_ino_%llu", (unsigned long long)e->inode_no);
        snprintf(file_lbl, sizeof(file_lbl), "%s\\n(ino:%llu)", e->target_name[0] ? e->target_name : "file", (unsigned long long)e->inode_no);
        add_node(file_id, file_lbl, NODE_FILE, 0, e->inode_no, 0);

        char write_edge_lbl[64];
        snprintf(write_edge_lbl, sizeof(write_edge_lbl), "Write (%lld B)", (long long)e->ret_bytes);
        add_edge(proc_id, file_id, write_edge_lbl, "#FB8C00", "solid");
        break;

    case WARDEN_OP_READ:
        printf("%s[%s]%s %s[F->P READ]%s Process: " COLOR_CYAN "%s" COLOR_RESET " (PID:%u) <- Read " COLOR_GREEN "%s" COLOR_RESET " (Inode:%llu) %s\n",
               COLOR_BOLD, time_str, COLOR_RESET, COLOR_MAGENTA, COLOR_RESET,
               e->comm, e->tgid, e->target_name, (unsigned long long)e->inode_no,
               e->extra_info[0] ? COLOR_RED "[TAINT PROPAGATED]" COLOR_RESET : "");

        snprintf(file_id, sizeof(file_id), "file_ino_%llu", (unsigned long long)e->inode_no);
        snprintf(file_lbl, sizeof(file_lbl), "%s\\n(ino:%llu)", e->target_name[0] ? e->target_name : "file", (unsigned long long)e->inode_no);
        add_node(file_id, file_lbl, NODE_FILE, 0, e->inode_no, 0);

        add_edge(file_id, proc_id, "Read (Propagate)", "#D81B60", "solid");
        break;

    case WARDEN_OP_EXIT:
        printf("%s[%s]%s %s[P->P EXIT]%s Process: " COLOR_CYAN "%s" COLOR_RESET " (PID:%u) Exited -> Aggregated to Parent (PID:%u)\n",
               COLOR_BOLD, time_str, COLOR_RESET, COLOR_GREEN, COLOR_RESET,
               e->comm, e->tgid, e->ppid);

        if (e->ppid > 0) {
            snprintf(parent_id, sizeof(parent_id), "proc_%u", e->ppid);
            snprintf(parent_lbl, sizeof(parent_lbl), "Parent\\n(PID: %u)", e->ppid);
            add_node(parent_id, parent_lbl, NODE_PROCESS, e->ppid, 0, (g_graph.root_pid == e->ppid));

            add_edge(proc_id, parent_id, "Exit Aggregation", "#43A047", "dashed");
        }
        break;

    case WARDEN_OP_RENAME:
        printf("%s[%s]%s %s[NAMESPACE RENAME]%s Process: " COLOR_CYAN "%s" COLOR_RESET " (PID:%u) Renamed " COLOR_YELLOW "%s" COLOR_RESET " -> " COLOR_GREEN "%s" COLOR_RESET "\n",
               COLOR_BOLD, time_str, COLOR_RESET, COLOR_BLUE, COLOR_RESET,
               e->comm, e->tgid, e->extra_info, e->target_name);

        snprintf(child_id, sizeof(child_id), "rename_%s", e->target_name);
        snprintf(child_lbl, sizeof(child_lbl), "%s\\n(Renamed)", e->target_name);
        add_node(child_id, child_lbl, NODE_FILE, 0, 0, 0);

        snprintf(parent_id, sizeof(parent_id), "rename_%s", e->extra_info);
        snprintf(parent_lbl, sizeof(parent_lbl), "%s\\n(Original)", e->extra_info);
        add_node(parent_id, parent_lbl, NODE_FILE, 0, 0, 0);

        add_edge(parent_id, child_id, "Rename", "#8E24AA", "dashed");
        break;

    default:
        break;
    }
    fflush(stdout);
    return 0;
}

/* Export in-memory graph to Graphviz DOT and render PNG */
static int export_provenance_graph(const char *dot_path, const char *png_path)
{
    FILE *fp = fopen(dot_path, "w");
    if (!fp) {
        fprintf(stderr, "Failed to open %s for writing: %s\n", dot_path, strerror(errno));
        return -1;
    }

    fprintf(fp, "digraph AgentProvenance {\n");
    fprintf(fp, "    rankdir=LR;\n");
    fprintf(fp, "    fontname=\"Helvetica,Arial,sans-serif\";\n");
    fprintf(fp, "    node [fontname=\"Helvetica,Arial,sans-serif\", fontsize=10, style=\"filled,rounded\"];\n");
    fprintf(fp, "    edge [fontname=\"Helvetica,Arial,sans-serif\", fontsize=9, arrowsize=0.8];\n\n");

    /* Subgraph for processes */
    fprintf(fp, "    // Entities (Nodes)\n");
    for (int i = 0; i < g_graph.node_count; i++) {
        struct graph_node *n = &g_graph.nodes[i];
        if (n->kind == NODE_PROCESS) {
            if (n->is_root) {
                fprintf(fp, "    \"%s\" [label=\"%s\", shape=box, fillcolor=\"#FFCDD2\", color=\"#B71C1C\", penwidth=2.0];\n",
                        n->id, n->label);
            } else {
                fprintf(fp, "    \"%s\" [label=\"%s\", shape=box, fillcolor=\"#BBDEFB\", color=\"#0D47A1\", penwidth=1.5];\n",
                        n->id, n->label);
            }
        } else {
            fprintf(fp, "    \"%s\" [label=\"%s\", shape=note, fillcolor=\"#FFE0B2\", color=\"#E65100\", penwidth=1.5];\n",
                    n->id, n->label);
        }
    }

    fprintf(fp, "\n    // Causal Flow Transitions (Edges)\n");
    for (int i = 0; i < g_graph.edge_count; i++) {
        struct graph_edge *e = &g_graph.edges[i];
        fprintf(fp, "    \"%s\" -> \"%s\" [label=\" %s \", color=\"%s\", fontcolor=\"%s\", style=\"%s\", penwidth=1.5];\n",
                e->src_id, e->dst_id, e->label, e->color, e->color, e->style);
    }

    fprintf(fp, "}\n");
    fclose(fp);

    printf(COLOR_GREEN "[*] Provenance graph DOT exported to: %s" COLOR_RESET "\n", dot_path);

    /* Render PNG via system dot command */
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "dot -Tpng \"%s\" -o \"%s\"", dot_path, png_path);
    int ret = system(cmd);
    if (ret == 0) {
        printf(COLOR_GREEN "[+] Successfully rendered topology PNG to: %s" COLOR_RESET "\n", png_path);
    } else {
        fprintf(stderr, COLOR_RED "[-] Failed to render graphviz image: dot exited with %d" COLOR_RESET "\n", ret);
    }
    return ret;
}

static void print_usage(const char *prog)
{
    printf("Usage: %s [OPTIONS]\n", prog);
    printf("Options:\n");
    printf("  --mode <hash|local>     Backend mode: hash (default) or local\n");
    printf("  --agent-pid <pid>       Monitored root agent PID/TGID (optional)\n");
    printf("  --output-dot <path>     Path to output Graphviz DOT (default: graphs/provenance.dot)\n");
    printf("  --output-png <path>     Path to output PNG image (default: graphs/provenance.png)\n");
    printf("  --timeout <sec>         Watchdog timeout in seconds (optional, e.g. 30)\n");
    printf("  -h, --help              Show this help\n");
}

int main(int argc, char **argv)
{
    struct warden_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err = 0;
    uint32_t mode = BACKEND_HASH;
    uint32_t agent_pid = 0;
    int timeout_sec = 0;
    char dot_path[256] = "graphs/provenance.dot";
    char png_path[256] = "graphs/provenance.png";

    static struct option long_options[] = {
        {"mode", required_argument, 0, 'm'},
        {"agent-pid", required_argument, 0, 'p'},
        {"output-dot", required_argument, 0, 'd'},
        {"output-png", required_argument, 0, 'g'},
        {"timeout", required_argument, 0, 't'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "m:p:d:g:t:h", long_options, NULL)) != -1) {
        switch (opt) {
        case 'm':
            if (strcmp(optarg, "local") == 0)
                mode = BACKEND_LOCAL;
            else
                mode = BACKEND_HASH;
            break;
        case 'p':
            agent_pid = (uint32_t)atoi(optarg);
            break;
        case 'd':
            strncpy(dot_path, optarg, sizeof(dot_path) - 1);
            break;
        case 'g':
            strncpy(png_path, optarg, sizeof(png_path) - 1);
            break;
        case 't':
            timeout_sec = atoi(optarg);
            break;
        case 'h':
        default:
            print_usage(argv[0]);
            return 0;
        }
    }

    /* Setup signal handlers for graceful detach */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    if (timeout_sec > 0) {
        signal(SIGALRM, sig_handler);
        alarm(timeout_sec);
    }

    g_graph.root_pid = agent_pid;

    printf(COLOR_BOLD "========================================================\n" COLOR_RESET);
    printf(COLOR_BOLD "  Agent-Warden Kernel Provenance Monitor (v1.0)\n" COLOR_RESET);
    printf(COLOR_BOLD "========================================================\n" COLOR_RESET);
    printf("[*] Backend Engine : %s%s%s\n", COLOR_CYAN, (mode == BACKEND_LOCAL ? "Warden-Local (Task Storage)" : "Warden-Hash (Global Hash Maps)"), COLOR_RESET);
    if (agent_pid > 0)
        printf("[*] Root Agent PID : %s%u%s\n", COLOR_YELLOW, agent_pid, COLOR_RESET);
    else
        printf("[*] Root Agent PID : (Dynamic / Auto-detect via configuration)\n");
    if (timeout_sec > 0)
        printf("[*] Auto-Timeout   : %d seconds\n", timeout_sec);
    printf("[*] Export Path    : %s -> %s\n\n", dot_path, png_path);

    /* Open BPF skeleton */
    skel = warden_bpf__open();
    if (!skel) {
        fprintf(stderr, COLOR_RED "[-] Failed to open BPF skeleton\n" COLOR_RESET);
        return 1;
    }

    /* Configure tunable rodata constants */
    skel->rodata->cfg_backend_mode = mode;
    skel->rodata->cfg_target_agent_tgid = agent_pid;

    /* Load and verify BPF programs */
    err = warden_bpf__load(skel);
    if (err) {
        fprintf(stderr, COLOR_RED "[-] Failed to load and verify BPF skeleton: %d\n" COLOR_RESET, err);
        goto cleanup;
    }

    /* Seed initial root agent PID into hash_task_map if provided */
    if (agent_pid > 0) {
        struct prov_state_t init_st = {
            .marked = 1,
            .agent_root_tgid = agent_pid,
            .first_marked_ts = 1,
            .last_event_ts = 1,
        };
        int map_fd = bpf_map__fd(skel->maps.hash_task_map);
        bpf_map_update_elem(map_fd, &agent_pid, &init_st, BPF_ANY);
        printf("[+] Seeded root agent PID %u into provenance state map\n", agent_pid);
    }

    /* Attach BPF probes to kernel tracepoints and fexit hooks */
    err = warden_bpf__attach(skel);
    if (err) {
        fprintf(stderr, COLOR_RED "[-] Failed to attach BPF skeleton: %d\n" COLOR_RESET, err);
        goto cleanup;
    }

    /* Setup RingBuffer */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, COLOR_RED "[-] Failed to create BPF ring buffer\n" COLOR_RESET);
        err = -1;
        goto cleanup;
    }

    printf(COLOR_GREEN "[+] Agent-Warden kernel probes attached successfully! Listening for provenance events...\n" COLOR_RESET);
    printf("--------------------------------------------------------------------------------\n");

    /* Polling loop */
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* ms */);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }
    if (err == -EINTR)
        err = 0;

    printf("\n" COLOR_YELLOW "[*] Detaching probes and reconstructing causal DAG..." COLOR_RESET "\n");

    /* Export the provenance graph */
    export_provenance_graph(dot_path, png_path);
    printf(COLOR_GREEN "[+] Reconstructed %d nodes and %d causal edges\n" COLOR_RESET,
           g_graph.node_count, g_graph.edge_count);

cleanup:
    if (rb)
        ring_buffer__free(rb);
    if (skel)
        warden_bpf__destroy(skel);

    printf(COLOR_GREEN "[+] Graceful shutdown complete. Kernel probes cleanly detached.\n" COLOR_RESET);
    return err < 0 ? -err : 0;
}
