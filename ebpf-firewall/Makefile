# Project variables
BINARY_NAME := firewall
BIN_DIR := bin
CMD_DIR := ./cmd/firewall
EBPF_DIR := ./control/ebpf
BPF_DIR := ./bpf
VMLINUX_H := $(BPF_DIR)/vmlinux.h
IFACE ?= lo

# Go & Build tools
GO ?= go
CLANG ?= clang
BPFTOOL ?= bpftool

# Debug build of the eBPF datapath. Set DEBUG=1 to compile in bpf_printk
# inspection (bpf/firewall.c) — useful while learning, but leaves the
# datapath under trace. Leave unset for performance-sensitive measurements.
DEBUG ?= 0

.PHONY: all deps vmlinux generate generate-debug build test integration-test clean run trace help

## all: Resolve deps, generate eBPF bindings, and build binaries
all: deps generate build

## help: Display this help message
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^## ' $(MAKEFILE_LIST) | sed -e 's/## //' | awk 'BEGIN {FS = ":"}; {printf "  %-20s %s\n", $$1, $$2}'

## deps: Download and tidy Go module dependencies
deps:
	@echo "==> Resolving Go module dependencies..."
	$(GO) mod tidy
	$(GO) mod download

## vmlinux: Generate bpf/vmlinux.h from the running kernel's BTF (distro-neutral)
vmlinux: $(VMLINUX_H)

$(VMLINUX_H):
	@echo "==> Generating $@ from kernel BTF..."
	sh ./scripts/gen-vmlinux.sh $@

## generate: Compile eBPF C code and generate Go bindings via bpf2go (DEBUG=1 for tracing)
generate: $(VMLINUX_H)
	@echo "==> Generating eBPF Go bindings..."
	cd $(EBPF_DIR) && $(GO) generate

## generate-debug: Same as generate but compiles in bpf_printk debugging
generate-debug: $(VMLINUX_H)
	@echo "==> Generating eBPF Go bindings (debug)..."
	cd $(EBPF_DIR) && $(GO) run github.com/cilium/ebpf/cmd/bpf2go -target bpf firewall ../../bpf/firewall.c -- -I../../bpf -D FIREWALL_DEBUG

## build: Build the firewall binary and firewallctl client
build:
	@echo "==> Building $(BINARY_NAME) binary..."
	mkdir -p $(BIN_DIR)
	$(GO) build -o $(BIN_DIR)/$(BINARY_NAME) $(CMD_DIR)
	@echo "==> Building firewallctl client..."
	$(GO) build -o $(BIN_DIR)/firewallctl ./cmd/firewallctl
	@echo "==> Binaries built in $(BIN_DIR)"

## test: Run unit tests (no kernel required; requires generated bindings)
test: generate
	@echo "==> Running unit tests..."
	$(GO) test ./control/rules/ ./control/server/ ./control/ebpf/ -count=1

## integration-test: Run integration tests (require Linux + eBPF/root privileges)
integration-test: generate
	@echo "==> Running integration tests (needs root + eBPF)..."
	sudo $(GO) test -tags integration ./control/ebpf/ ./control/server/ -count=1 -v

## clean: Remove build artifacts and generated eBPF files
clean:
	@echo "==> Cleaning build artifacts..."
	rm -rf $(BIN_DIR)
	rm -f $(EBPF_DIR)/*_bpfel.go $(EBPF_DIR)/*_bpfeb.go
	rm -f $(EBPF_DIR)/*_bpfel.o $(EBPF_DIR)/*_bpfeb.o
	rm -f $(VMLINUX_H)

## run: Run the firewall with root privileges (default: IFACE=lo, override: make run IFACE=eth0)
run: build
	@echo "==> Running firewall on interface $(IFACE)..."
	sudo ./$(BIN_DIR)/$(BINARY_NAME) -i $(IFACE)

## trace: Read the kernel BPF trace pipe to view bpf_printk output (use with DEBUG=1 generate)
trace:
	@echo "==> Streaming BPF trace pipe (Ctrl+C to stop)..."
	sudo cat /sys/kernel/debug/tracing/trace_pipe
