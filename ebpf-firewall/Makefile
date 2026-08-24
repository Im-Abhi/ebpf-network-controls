# Project variables
BINARY_NAME := firewall
BIN_DIR := bin
CMD_DIR := cmd/firewall
LOADER_DIR := control/loader
IFACE ?= lo

# Go & Build tools
GO ?= go
CLANG ?= clang

.PHONY: all deps generate build clean run trace help

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

## generate: Compile eBPF C code and generate Go bindings via bpf2go
generate:
	@echo "==> Generating eBPF Go bindings..."
	cd $(LOADER_DIR) && $(GO) generate

## build: Build the firewall user-space binary
build:
	@echo "==> Building $(BINARY_NAME) binary..."
	mkdir -p $(BIN_DIR)
	$(GO) build -o $(BIN_DIR)/$(BINARY_NAME) $(CMD_DIR)/main.go
	@echo "==> Binary built at $(BIN_DIR)/$(BINARY_NAME)"

## clean: Remove build artifacts and generated eBPF files
clean:
	@echo "==> Cleaning build artifacts..."
	rm -rf $(BIN_DIR)
	rm -f $(LOADER_DIR)/*_bpfel.go $(LOADER_DIR)/*_bpfeb.go
	rm -f $(LOADER_DIR)/*_bpfel.o $(LOADER_DIR)/*_bpfeb.o

## run: Run the firewall with root privileges (default: IFACE=lo, override: make run IFACE=eth0)
run: build
	@echo "==> Running firewall on interface $(IFACE)..."
	sudo ./$(BIN_DIR)/$(BINARY_NAME) -i $(IFACE)

## trace: Read the kernel BPF trace pipe to view bpf_printk output
trace:
	@echo "==> Streaming BPF trace pipe (Ctrl+C to stop)..."
	sudo cat /sys/kernel/debug/tracing/trace_pipe
