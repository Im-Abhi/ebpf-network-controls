from bcc import BPF
from time import sleep

program = r"""
BPF_HASH(counter_table, u64, u64);

int hello(void *ctx) {
    u64 uid;
    u64 counter = 0;
    u64 *p;

    // TO GET THE USER ID STORE IN THE LOWER 4 BYTES
    uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    // see if the userID is present in the map or not and get a reference to it
    p = counter_table.lookup(&uid);
    if (p != 0) {
        counter = *p;
    }
    // if not present this is the first time set counter to zero 
    counter++;
    // update the bpf map
    counter_table.update(&uid, &counter);
    return 0;
}
"""

b = BPF(text = program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")

# Attach to a tracepoint that gets hit for all syscalls 
# b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

# accessing the BPF_MAP in the user_space
while True:
    sleep(2)
    s = ""
    for k, v in b["counter_table"].items():
        s += f"ID {k.value}: {v.value}\t"
    print(s)

# id -nu <user ID>
# for checking what those userID's are