```bash
sudo apt update
sudo apt install -y \
    clang \
    llvm \
    libbpf-dev \
    gcc-multilib \
    linux-headers-$(uname -r) \
    linux-tools-common \
    linux-tools-$(uname -r) \
    bpftool \
    make \
    golang
```