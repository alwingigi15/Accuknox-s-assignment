#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <bcc/proto.h>

BPF_HASH(process_ports, u32, u16);
BPF_HASH(allowed_pid, u32, u32);

int filter_packets(struct __sk_buff *skb) {
    u8 *cursor = 0;
    struct ethernet_t *eth = cursor_advance(cursor, sizeof(*eth));
    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));

    if (ip->nextp != IPPROTO_TCP) {
        return 0;
    }

    struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 *allowed = allowed_pid.lookup(&pid);

    if (allowed) {
        u32 key = 0;
        u16 *port = process_ports.lookup(&key);
        if (port && tcp->dst_port != *port) {
            return TC_ACT_SHOT; // Drop packet
        }
    }

    return TC_ACT_OK; // Allow packet
}

int trace_execve(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    // Update the allowed_pid map if the process name matches
    if (comm[0] == 'm' && comm[1] == 'y' && comm[2] == 'p' &&
        comm[3] == 'r' && comm[4] == 'o' && comm[5] == 'c' &&
        comm[6] == 'e' && comm[7] == 's' && comm[8] == 's') {
        u32 val = 1;
        allowed_pid.update(&pid, &val);
    }
    return 0;
}
