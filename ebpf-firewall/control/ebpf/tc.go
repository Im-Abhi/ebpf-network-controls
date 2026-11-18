package ebpf

import (
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Egress attach strings for the daemon status/status API. The egress hook is
// a cgroup/skb (BPF_CGROUP_INET_EGRESS) program attached at the root cgroup.
//
// Why cgroup/skb and not TC (clsact/tcx): the development kernel never fires
// TC egress hooks for TCP data packets (only SYN/ACK/FIN, ICMP and UDP),
// which silently disabled URL filtering — the blocklist needs the
// GET/ClientHello payload. The cgroup egress hook runs at L3 and sees every
// outbound packet, data included, on any kernel (no TCX 6.6 floor either).
// Because the hook spans the whole host, the BPF program gates on
// skb->ifindex (egress_meta, written below at attach time) to stay scoped to
// the daemon's -i interface.
const (
	// AttachModeCgroupEgress is the effective attach mode of the egress
	// program once it is attached via the cgroup/skb hook.
	AttachModeCgroupEgress = "cgroupEgress"

	// cgroupPath is the cgroup v2 root the egress classifier attaches to,
	// covering every process on the host (the BPF program scopes per
	// interface via egress_meta).
	cgroupPath = "/sys/fs/cgroup"
)

// EgressProgram owns the attach/detach lifecycle of the cgroup/skb egress
// classifier. It does NOT own the loaded eBPF objects: the program handle
// (and the shared maps) are loaded and closed by XDPProgram, which is the
// single owner of the collection. EgressProgram only manages the bpf_link,
// so detaching egress while the XDP program stays attached is possible
// without tearing down either program.
type EgressProgram struct {
	ifaceIndex int
	meta       *ebpf.Map
	prog       *ebpf.Program
	link       link.Link
}

// NewEgressProgram wraps a loaded egress classifier program for the given
// interface index. The program must remain alive for the lifetime of the
// EgressProgram (the caller owns it).
func NewEgressProgram(prog *ebpf.Program, meta *ebpf.Map, ifaceIndex int) *EgressProgram {
	return &EgressProgram{
		ifaceIndex: ifaceIndex,
		meta:       meta,
		prog:       prog,
	}
}

// Start attaches the classifier to the cgroup/skb egress path at the root
// cgroup and publishes the target ifindex into egress_meta (the datapath's
// per-packet scope gate). It is safe to call only once; subsequent calls are
// a no-op.
func (t *EgressProgram) Start() error {
	if t.link != nil {
		return nil
	}
	if t.prog == nil {
		return fmt.Errorf("egress: no classifier program loaded (regenerate bindings with `make generate`)")
	}

	// Publish the ifindex BEFORE attaching so a packet can never run the
	// program with a zeroed scope gate.
	if t.meta != nil {
		if err := t.meta.Put(uint32(0), uint32(t.ifaceIndex)); err != nil {
			return fmt.Errorf("egress: writing ifindex %d to egress_meta: %w", t.ifaceIndex, err)
		}
	}

	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: t.prog,
	})
	if err != nil {
		return fmt.Errorf("attaching cgroup egress classifier: %w", err)
	}

	t.link = l
	log.Printf("egress (cgroup/skb) attached at %s for ifindex %d", cgroupPath, t.ifaceIndex)
	return nil
}

// Attached reports whether the egress classifier is currently attached.
func (t *EgressProgram) Attached() bool {
	return t.link != nil
}

// Close detaches the egress classifier. The program object itself is owned by
// the collection and closed by XDPProgram.
func (t *EgressProgram) Close() error {
	var firstErr error
	if t.link != nil {
		if err := t.link.Close(); err != nil {
			firstErr = err
		}
		t.link = nil
	}
	if t.meta != nil {
		if err := t.meta.Put(uint32(0), uint32(0)); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
