#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>

#define FIVEM_SERVER_IP     192.168.1.1      // Replace with the IP address of your FiveM server
#define FIVEM_SERVER_PORT   30120           // Replace with the port number of your FiveM server

SEC("xdp_program")
int fivem_xdp(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if (eth + 1 > data_end) {
        return XDP_ABORTED;
    }

    // Parse IP header
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if (ip + 1 > data_end) {
        return XDP_ABORTED;
    }

    // Check if packet is UDP
    if (ip->protocol != IPPROTO_UDP) {
        return XDP_DROP;
    }

    // Parse UDP header
    struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if (udp + 1 > data_end) {
        return XDP_ABORTED;
    }

    // Check if packet is destined for the FiveM server IP and port
    if (ip->daddr != htonl(FIVEM_SERVER_IP) || udp->dest != htons(FIVEM_SERVER_PORT)) {
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "MIT";
