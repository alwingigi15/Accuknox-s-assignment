#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <bcc/proto.h>

BPF_HASH(drop_port, u32, u16);

int drop_tcp_packets(struct __sk_buff *skb) {
    u8 *cursor = 0;
    struct ethernet_t *eth = cursor_advance(cursor, sizeof(*eth));
    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));

    if (ip->nextp != IPPROTO_TCP) {
        return 0;
    }

    struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));

    u32 key = 0;
    u16 *port = drop_port.lookup(&key);
    if (port && tcp->dst_port == *port) {
        return TC_ACT_SHOT; // Drop packet
    }

    return TC_ACT_OK; // Allow packet
}
