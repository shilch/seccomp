**Summary**  
This is a proof-of-concept for the generation of eBPF-based Linux seccomp profiles for syscall filtering using Symbolic execution.
The generator receives a x86_64 Linux binary as an input and analyzes which syscalls as well as which syscall arguments it uses.
Then, at startup, the binary can load the previously generated seccomp profile into the kernel (eBPF code) which from then on intercepts any syscalls made by the process.
When it encounters a syscall/syscall argument combination that does not match with what was found during analysis, it kills the process.
The motivation for this generator is to have simple tooling for developers to harden their Linux binaries against remote code execution attacks.

**Usage**  
Generation of the seccomp profile consists of two steps:
1. The target x86_64 Linux binary is provided to the `analyse.py` script. This generates a JSON which describes valid syscall/syscall argument combinations.
2. The `builder.cpp` application (pre-compiled for convenience) takes the JSON as an input and generates a eBPF-based seccomp profile using libseccomp.

Several example sources and binaries are provided in the `examples/` directory.

**Caveats**  
Since this is a proof-of-concept, don't use it in production, obviously.
Symbolic execution suffers from the path explosion problem which I deal with by exploring the binary backwards, from the call sites of the syscalls down the call stack.
This process makes certain assumptions about the binary's layout, specifically in regards to control flow graph restoration.
Thus, anything with complex control flow such as dynamic code execution (e.g. JIT compiler) will certainly fail.
Also, I did not implement support for dynamic libraries.
