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

.PHONY: all deps vmlinux generate build clean run trace help

## all: Install dependencies, generate eBPF bindings, and build binary
all: deps generate build

## help: Display this help message
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^## ' $(MAKEFILE_LIST) | sed -e 's/## //' | awk 'BEGIN {FS = ":"}; {printf "  %-15s %s\n", $$1, $$2}'

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

## generate: Compile eBPF C code and generate Go bindings via bpf2go
generate: $(VMLINUX_H)
	@echo "==> Generating eBPF Go bindings..."
	cd $(EBPF_DIR) && $(GO) generate

## build: Build the firewall user-space binary
build:
	@echo "==> Building $(BINARY_NAME) binary..."
	mkdir -p $(BIN_DIR)
	$(GO) build -o $(BIN_DIR)/$(BINARY_NAME) $(CMD_DIR)
	@echo "==> Binary built at $(BIN_DIR)/$(BINARY_NAME)"

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

## trace: Read the kernel BPF trace pipe to view bpf_printk output
trace:
	@echo "==> Streaming BPF trace pipe (Ctrl+C to stop)..."
	sudo cat /sys/kernel/debug/tracing/trace_pipe
