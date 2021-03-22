#include <errno.h>
#include <linux/audit.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <time.h>
#include <unistd.h>

struct sock_filter filter[] = {
    BPF_STMT(BPF_LD + BPF_W + BPF_ABS,
        (offsetof(struct seccomp_data, arch))),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, AUDIT_ARCH_X86_64, 0, 3),
    BPF_STMT(BPF_LD + BPF_W + BPF_ABS,
        (offsetof(struct seccomp_data, nr))),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_time, 0, 1),
    BPF_STMT(BPF_RET + BPF_K,
        SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
    BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW)
};
struct sock_fprog fprog = {
    .len = sizeof(filter) / sizeof(struct sock_filter),
    .filter = filter,
};

void forbid_time() {
    prctl(PR_SET_NO_NEW_PRIVS, 1);
    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fprog);
}

void print_time() {
    time_t ts;
    char* ts_str;

    puts("Ermittle Zeit...");

    ts = (time_t)syscall(__NR_time, NULL);
    if(ts == ((time_t) -1)
        || (ts_str = ctime(&ts)) == NULL) {
        perror("Zeit konnte nicht ermittelt werden");
        exit(1);
    }

    printf("Aktuelle Zeit: %s\n", ts_str);
    fflush(stdout);
}

int main(int argc, char** argv) {
    /* Vor Konfiguration von seccomp */
    print_time();

    /* Konfiguriere seccomp */
    puts("Verbiete Zeitermittlung...");
    forbid_time();

    /* Nach Konfiguration von seccomp */
    print_time();

    return 0;
}