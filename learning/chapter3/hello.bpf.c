#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

int counter = 0;

// express data path 
SEC("xdp")
int hello(struct xdp_md *ctx) {
    bpf_printk("Hello World %d", counter);
    counter++;
    return XDP_PASS;
    // return XDP_DROP;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
The eBPF verifier checks that any program that calls a GPL-licensed BPF helper functions has a GPL-compatible license explicitly declared. (Again, this is something that BCC takes care of for you when you're using that framework.)
*/
