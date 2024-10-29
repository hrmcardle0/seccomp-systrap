package main

/*
#cgo LDFLAGS: -lseccomp
#include <seccomp.h>
#include <signal.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

int *shared_mem;

// Function to set the shared memory pointer from Go
void set_shared_mem(void *mem) {
    shared_mem = (int *)mem;
}

void *create_shared_memory(size_t size) {
    return mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
}

// Signal handler for SIGSYS in the child
void sigsys_handler(int signum, siginfo_t *info, void *context) {
    if (signum == SIGSYS) {
        // Write the syscall number to shared memory (for example purposes)
        printf("Syscall found: %d\n", info->si_syscall);
        printf("Syscall Addr: %#018lx\n", (unsigned long)info->si_addr);
        printf("Syscall Value at addr: %d\n", *(int *)(info->si_addr));

        printf("sigsys_handler() shared_mem: %#018lx\n", (int *)context);

        printf("Shared Memory: %#018lx\n", (int *)shared_mem);
        printf("Value at addr: %d\n", *(shared_mem));
        *shared_mem = info->si_syscall; // Store the intercepted syscall number
        printf("Value at addr: %d\n", *(shared_mem));
        printf("Writing syscall %d to shared memory...\n", info->si_syscall);

    }
}

// Set up the seccomp filter
int setup_seccomp() {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (ctx == NULL) {
        return -1;
    }
    seccomp_rule_add(ctx, SCMP_ACT_TRAP, SCMP_SYS(getpid), 0);
    return seccomp_load(ctx);
}

// Set up the SIGSYS signal handler
void setup_sigsys_handler() {
	printf("setup_sigsys_handler() shared_mem Addr: %#018lx\n", (int *)shared_mem);
    struct sigaction act;
    memset(&act, 0, sizeof(act));
    act.sa_sigaction = sigsys_handler;
    act.sa_flags = SA_SIGINFO;
    sigaction(SIGSYS, &act, NULL);
}
*/
import "C"
import (
	"fmt"
	"os"
	//"os/signal"
	"syscall"
	"time"
	"unsafe"
)

const sharedMemSize = 4

var sharedMemPtr unsafe.Pointer

func main() {
	// Create shared memory
	sharedMemPtr = C.create_shared_memory(C.size_t(sharedMemSize))
	fmt.Printf("Shared memory pointer in Go: %p\n", sharedMemPtr)
	if sharedMemPtr == nil {
		fmt.Println("Failed to create shared memory")
		os.Exit(1)
	}

	// Set the shared memory pointer in C
	C.set_shared_mem(sharedMemPtr)

	// Fork a child process
	pid, _, errno := syscall.RawSyscall(syscall.SYS_FORK, 0, 0, 0)
	if errno != 0 {
		fmt.Printf("Fork failed: %v\n", errno)
		os.Exit(1)
	}

	if pid == 0 {
		// Child process
		childProcess()
	} else {
		// Parent process
		parentProcess(pid)
	}
}

func parentProcess(pid uintptr) {
	fmt.Println("Parent process started. Monitoring shared memory...")

	// Wait for child to complete
	//syscall.Wait4(int(pid), nil, 0, nil)

	for {
		syscallNum := *(*int)(sharedMemPtr)
		fmt.Printf("Intercepted syscall number from child: %d\n", syscallNum)

		if syscallNum == 39 {
			parentPid := syscall.Getpid()
			fmt.Printf("Parent performed Getpid(): %d\n", parentPid)
			*(*int)(sharedMemPtr) = parentPid
			fmt.Println(*(*int)(sharedMemPtr))
			break
		}
	}
}

func childProcess() {
	// Set up seccomp in the child process
	if C.setup_seccomp() != 0 {
		fmt.Println("Failed to set up seccomp")
		os.Exit(1)
	}

	// Set up the SIGSYS handler
	C.setup_sigsys_handler()

	// Trigger a syscall to be intercepted
	fmt.Println("Child process making a syscall to trigger SIGSYS...")
	pid := syscall.Getpid()
	fmt.Printf("Result of intercepted Getpid(): %d\n", pid)

	// Read the result from shared memory (provided by parent)
	for {
		result := *(*int)(sharedMemPtr)
		if result != 39 {
			fmt.Printf("Result of intercepted Getpid() from parent: %d\n", result)
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// The program continues or exits after handling
}
