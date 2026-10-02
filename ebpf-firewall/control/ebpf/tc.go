package ebpf

import (
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// TC egress attach strings for the daemon status/status API. The egress hook
// is a SCHED_CLS classifier on the TC egress path, attached with the modern
// TCX bpf_link API (no clsact qdisc management needed).
const (
	// AttachModeTCXEgress is the effective attach mode of the TC egress
	// program once it is attached via TCX.
	AttachModeTCXEgress = "tcxEgress"
)

// TCProgram owns the attach/detach lifecycle of the TC egress classifier on an
// interface. It does NOT own the loaded eBPF objects: the program handle (and
// the shared maps) are loaded and closed by XDPProgram, which is the single
// owner of the collection. TCProgram only manages the bpf_link, so detaching
// egress while the XDP program stays attached is possible without tearing down
// either program.
type TCProgram struct {
	ifaceIndex int
	prog       *ebpf.Program
	link       link.Link
}

// NewTCProgram wraps a loaded TC egress classifier program for the given
// interface index. The program must remain alive for the lifetime of the
// TCProgram (the caller owns it).
func NewTCProgram(prog *ebpf.Program, ifaceIndex int) *TCProgram {
	return &TCProgram{
		ifaceIndex: ifaceIndex,
		prog:       prog,
	}
}

// Start attaches the classifier to the TC egress path via the TCX bpf_link API
// (kernel >= 6.6). It is safe to call only once; subsequent calls are a no-op.
// If the running kernel predates TCX, the attach fails with the feature error
// from the kernel, which the daemon surfaces so the operator can defer the
// feature rather than silently losing egress filtering.
func (t *TCProgram) Start() error {
	if t.link != nil {
		return nil
	}
	if t.prog == nil {
		return fmt.Errorf("tc egress: no classifier program loaded (regenerate bindings with `make generate`)")
	}

	l, err := link.AttachTCX(link.TCXOptions{
		Interface: t.ifaceIndex,
		Program:   t.prog,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		return fmt.Errorf("attaching TC egress classifier to ifindex %d: %w", t.ifaceIndex, err)
	}

	t.link = l
	log.Printf("tc egress (tcx) attached to ifindex %d", t.ifaceIndex)
	return nil
}

// Attached reports whether the egress classifier is currently attached.
func (t *TCProgram) Attached() bool {
	return t.link != nil
}

// Close detaches the egress classifier. The program object itself is owned by
// the collection and is closed by XDPProgram.
func (t *TCProgram) Close() error {
	var firstErr error
	if t.link != nil {
		if err := t.link.Close(); err != nil {
			firstErr = err
		}
		t.link = nil
	}
	return firstErr
}