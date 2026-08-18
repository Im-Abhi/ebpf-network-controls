load the program into the kernel, pin it to the filesystem so that it can be referred to as
```shell
bpftool prog load hello.bpf.o /sys/fs/bpf/hello
```

command attaches it to the loopback network interface on this virtual machine.
```shell
bpftool net attach xdp name hello dev lo
```

You can see all the network-related eBPF programs by running the following command:
```shell
bpftool net list
```

You can also use the ip command to see that the program is attached to the loopback interface. Run the following command:
```shell
ip a show dev lo
```

```shell
bpftool prog tracelog
```
eBPF tracing output gets sent to a pseudofile at `/sys/kernel/debug/tracing/trace_pipe` - an alternative to using `bpftool` is simply to use cat on this file. (Notice that all tracing gets generated to this single location, which is why you would probably use a map to extract output to user space for production applications.)


Rather than bpftool, this time let's use ip to load the program and attach it to the network interface:
```shell
ip link set dev lo xdp obj hello.bpf.o sec xdp
```