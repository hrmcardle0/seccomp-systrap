# seccomp-systrap

This is an example implementation of how [gVisor uses Systrap](https://gvisor.dev/blog/2023/04/28/systrap-release/) to intercept and perform syscalls on behalf of a child process. In this case of gVisor, this would be the sandbox environment.

## Details

The program uses CGO to do the following:

1. Start up a child process
2. Apply `seccomp` rules & filters to the child process that trap the `Getpid` syscall
3. Utilize the `SCMP_ACT_TRAP` action to trigger `SIGSYS` signals when the syscall is made
4. Register a `SIGSYS` signal handler that is called when the syscall is made
5. Populate allocated shared memory with the syscall identifier
6. The parent reads from the shared memory section to retreive the syscall identifier
7. The parent performs the syscall itself
6. The parent stores the results back in the shared memory section
7. The child then reads the result of the syscall

The example given is the `Getpid` syscall and therefore will really be the pid of the parent, not the child. However this shows a very basic example of how you can utilize `seccomp` to catch syscalls for further processing