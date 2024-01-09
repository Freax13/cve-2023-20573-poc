### PoC Usage

This repo contains a VMM that boots an SEV-SNP guest with a custom kernel. The VMM and kernel are a stripped-down version of a project of mine. A modified Linux kernel is required to run on the host: https://github.com/Freax13/linux/tree/for-amd.

The Proof of Concept can be run like this:
```bash
cd host
cargo run -p vmm
```

### Explanation

This code jumps back and forth between two instructions:

```assembly
2:
    nop
    jmp 2b
```

When the TF flag is set in the FLAGS registers exceptions should be generated with the instruction pointer alternating between the two instructions.

The guest kernel defines an exception handler that simply logs the instruction pointer reported in the interrupt stack frame. In theory, the logs should look like this:
```
...
[INFO  kernel/src/exception.rs:50] nop
[INFO  kernel/src/exception.rs:56] jmp
[INFO  kernel/src/exception.rs:50] nop
[INFO  kernel/src/exception.rs:56] jmp
[INFO  kernel/src/exception.rs:50] nop
[INFO  kernel/src/exception.rs:56] jmp
[INFO  kernel/src/exception.rs:50] nop
[INFO  kernel/src/exception.rs:56] jmp
[INFO  kernel/src/exception.rs:50] nop
[INFO  kernel/src/exception.rs:56] jmp
[INFO  kernel/src/exception.rs:50] nop
[INFO  kernel/src/exception.rs:56] jmp
...
```

However, in practice, the modified host kernel suppresses reinjection that results in the following logs:
```
...
[INFO  kernel/src/exception.rs:56] jmp
[INFO  kernel/src/exception.rs:50] nop
[INFO  kernel/src/exception.rs:56] jmp
[INFO  kernel/src/exception.rs:50] nop
[INFO  kernel/src/exception.rs:50] nop
[INFO  kernel/src/exception.rs:53] last instruction was also nop
[INFO  kernel/src/exception.rs:56] jmp
[INFO  kernel/src/exception.rs:50] nop
[INFO  kernel/src/exception.rs:56] jmp
[INFO  kernel/src/exception.rs:50] nop
[INFO  kernel/src/exception.rs:56] jmp
[INFO  kernel/src/exception.rs:50] nop
[INFO  kernel/src/exception.rs:56] jmp
[INFO  kernel/src/exception.rs:56] jmp
[INFO  kernel/src/exception.rs:59] last instruction was also jmp
[INFO  kernel/src/exception.rs:50] nop
[INFO  kernel/src/exception.rs:56] jmp
[INFO  kernel/src/exception.rs:50] nop
...
```

The suppressed events will show up in the host kernel logs:
```
...
[798678.660473] kvm_amd: exit_int_info=80000301 exit_info_1=500000004 exit_info_2=180000000 exit_code=400
[798678.678645] kvm_amd: exit_int_info=80000301 exit_info_1=500000004 exit_info_2=180000000 exit_code=400
[798678.680906] kvm_amd: exit_int_info=80000301 exit_info_1=500000004 exit_info_2=180000000 exit_code=400
[798678.683491] kvm_amd: exit_int_info=80000301 exit_info_1=500000004 exit_info_2=180000000 exit_code=400
[798678.700844] kvm_amd: exit_int_info=80000301 exit_info_1=500000004 exit_info_2=180000000 exit_code=400
[798678.712970] kvm_amd: exit_int_info=80000301 exit_info_1=500000004 exit_info_2=180000000 exit_code=400
...
```

This demonstrates that delivery of the #DB exception was suppressed.
