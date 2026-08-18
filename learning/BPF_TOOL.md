```bash
bpftool prog list
```
This will show all the eBPF programs loaded into the kernel at present. 
```bash
72: kprobe  name hello  tag f1db4e564ad5219a  gpl
        loaded_at 2023-05-04T13:50:51+0000  uid 0
        xlated 104B  jited 68B  memlock 4096B
        btf_id 46
        pids hello.py(2787)
```
You can see that this is a program named hello attached to a kprobe. In this example, it has been given the ID `72` - yours might be different. It also has a tag, in this case `f1db4e564ad5219a`.

In the last line of this output you can see information about the user space process(es) that have references to this eBPF program. You can confirm that the process ID (`2787` in my example output) matches what you see if you run `ps -a`:
```excel
    PID TTY          TIME CMD
   2749 pts/2    00:00:00 bash
   2760 pts/3    00:00:00 bash
   2787 pts/2    00:00:00 hello.py
   8744 pts/3    00:00:00 ps
```
Get information about a specific eBPF program
You can refer to a program by ID, tag or name when using bpftool.

Check that you get the same output for all of the following commands (substituting whatever ID and tag your version of hello has been given):
```bash
bpftool prog show id 72
bpftool prog show name hello
bpftool prog show tag f1db4e564ad5219a
```

Inspect the eBPF program bytecode
bpftool can show you the bytecode instructions for eBPF programs. Run the following command to see the bytecode for "Hello World":
```shell
bpftool prog dump xlated name hello
```
The output should look something like this:
```C

int hello(void * ctx):
; int hello(void *ctx) {
   0: (b7) r1 = 560229490
; ({ char _fmt[] = "Hello World!"; bpf_trace_printk_(_fmt, sizeof(_fmt)); });
   1: (63) *(u32 *)(r10 -8) = r1
   2: (18) r1 = 0x6f57206f6c6c6548
   4: (7b) *(u64 *)(r10 -16) = r1
   5: (b7) r1 = 0
   6: (73) *(u8 *)(r10 -4) = r1
   7: (bf) r1 = r10
;
   8: (07) r1 += -16
; ({ char _fmt[] = "Hello World!"; bpf_trace_printk_(_fmt, sizeof(_fmt)); });
   9: (b7) r2 = 13
  10: (85) call bpf_trace_printk#-70240
; return 0;
  11: (b7) r0 = 0
  12: (95) exit
```
Don't feel that you need to understand everything about this output - and feel free to skip over this if you don't want to dive into the details. For those of you who are interested:

c
   0: (b7) r1 = 560229490
The 0 is simply an index showing the offset of this instruction in memory from the start of the program.

b7 is the opcode for the instruction. From the unofficial documentation of the eBPF instruction set, you can see that b7 means dst = src, or "set the value of dst to the value of src". In this case dst is Register 1 (r1) and src is a value (this will be the location in memory of the ctx variable passed to the eBPF program). So, after this instruction is run, Register 1 will hold the value 560229490.

By convention, the context to an eBPF program is passed in using Register 1, and the return value from a program is stored in Register 0. You can see Register 0 being set to the return value of 0 in the instruction at offset 11 in the bytecode listing.

When you're done, go ahead and click Next and see how you can use bpftool to examine and update eBPF maps.


---
### BPFTOOL
Assuming that in an earlier lab you modified the example so that it is attached to the sys_enter tracepoint, you'll see output like this:
```
88: raw_tracepoint  name hello  tag de24cf185ee252cd  gpl
        loaded_at 2023-05-05T16:52:22+0000  uid 0
        xlated 208B  jited 127B  memlock 4096B  map_ids 6
        btf_id 48
        pids hello-map.py(8987)
```
For this example, there is an additional field *`map_ids`* which in my example output shows that the hello program is using a map with ID 6. Let's store this in an environment variable (change 6 to whatever value you see for map_ids).
```shell
export MAP_ID=6
```

Get map information with bpftool
Let's see what bpftool can tell us about that map by running the following command (using whatever value you've just learned is being used for the map ID):

```shell
bpftool map show id $MAP_ID
```
You'll see output like this:
```
6: hash  name counter_table  flags 0x0
        key 8B  value 8B  max_entries 10240  memlock 163840B
        btf_id 48
        pids hello-map.py(8987)
```
As expected, the map is of type hash, it has the name counter_table, and you can see that it is referred to by the user space process that's running hello-map.py.

You can also see that this map contains up to `10,240` entries of key-value pairs, where both the key and value are `8 bytes` long. This matches the eBPF program code: if you look at the source code for hello-map.py again you'll see that both uid and counter local variables are 64-bit integers.

```shell
bpftool map dump id $MAP_ID
```
You should see an array of key-value pairs.

In a hash map you can also look up the value that corresponds to a particular key, like this:

```shell
bpftool map lookup id $MAP_ID key 100 0 0 0 0 0 0 0
```
Note that you have to specify each of the 8 bytes of the key individually, starting with the least significant. You can use hex notation if you prefer, so all of the following are equivalent:
```shell
bpftool map lookup id $MAP_ID key 100 0 0 0 0 0 0 0
bpftool map lookup id $MAP_ID key 0x64 0 0 0 0 0 0 0
bpftool map lookup id $MAP_ID key hex 64 0 0 0 0 0 0 0
```
If user ID 100 has generated some system calls you would see output something like this:

```json
{
    "key": 100,
    "value": 216
}
```
Updating maps with bpftool
You can also update values in eBPF maps using bpftool. Here's a command that will add an arbitrary key-value pair to the counter_table map.:

```shell
bpftool map update id $MAP_ID key 5 0 0 0 0 0 0 0 value 0 0 0 0 0 0 0 1
```
You have to specify the key and value byte by individual byte. Recalling that the bytes are specified starting with the least significant, the command above will store a large number corresponding to the key 5.