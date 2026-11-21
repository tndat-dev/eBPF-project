// Sentinel Pulse attack/control generator pulse-live-recalibrated: the frozen B1 scenarios plus a
// benign control that follows the identical launch path (kubectl exec ->
// execve -> run -> exit) but only calls getpid. Comparing detections on the
// benign control with detections on attacks separates "a new process ran"
// from attack behaviour. B1 (runtime_attack_blind_b1.c) stays unchanged.
//
// Each operation is process-local or guaranteed to fail before changing host,
// namespace, credential, filesystem, or network state. It must never be used
// for training, calibration, threshold selection, or post-hoc policy tuning.
/* =================================================================================================================
 * FIXTURE TẤN CÔNG + BINARY ĐỐI CHỨNG VÔ HẠI (tự viết; plan_matched_run.py biên dịch tĩnh thành runtime-attack-development).
 * Cách gọi: <binary> MODE [SECONDS] [RATE] [SEED] [PAD] — lặp thao tác của MODE `RATE` lần/giây trong SECONDS giây.
 * 5 kịch bản tấn công (đều chỉ ảnh hưởng process của chính nó hoặc CHẮC CHẮN thất bại trước khi đổi trạng thái host):
 *   anonymous_mprotect_churn  : đổi quyền một trang nhớ ẩn danh RW → R → RW (kiểu chuẩn bị shellcode);
 *   child_ptrace_handshake    : process con gọi ptrace(PTRACE_TRACEME) (kỹ thuật chống gỡ lỗi / leo thang);
 *   invalid_setns_burst       : setns với fd -1 (thử nhảy namespace — luôn EBADF);
 *   seccomp_api_probe         : seccomp với mã thao tác không hợp lệ (thử can thiệp seccomp — luôn EINVAL);
 *   execveat_resolution_probe : execveat với dirfd -1 tới file không tồn tại (exec bất thường — luôn thất bại).
 * benign_exec_control: chỉ gọi getpid — đi đúng đường khởi chạy như tấn công (kubectl exec → execve → chạy → thoát),
 * nên so phát hiện của nó với tấn công tách được "có process mới" khỏi "có hành vi tấn công".
 * PAD (lượt v6, kẻ tấn công thích nghi "pha loãng"): sau mỗi thao tác chèn PAD cặp getpid + sched_yield — syscall quen
 * thuộc — để tỉ lệ syscall của tấn công trong cửa sổ nhỏ đi (giả thuyết H3).
 * ================================================================================================================= */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t running = 1;
static uint64_t rng_state = 1;

static void stop_handler(int signo) {
    (void)signo;
    running = 0;
}

static uint32_t next_random(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return (uint32_t)rng_state;
}
//Cấp phát một trang nhớ ẩn danh RW, ghi ngẫu nhiên 1 byte, đổi quyền sang R, đổi lại RW
//rồi giải phóng (munmap) — mô phỏng kiểu thao tác quyền trang nhớ trước khi nạp/thực thi mã.
static void anonymous_mprotect_churn(void) {
    const size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    void *page = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) return;
    ((volatile unsigned char *)page)[0] = (unsigned char)next_random();
    (void)mprotect(page, page_size, PROT_READ);
    (void)mprotect(page, page_size, PROT_READ | PROT_WRITE);
    (void)munmap(page, page_size);
}

//Tạo tiến trình con (fork), cho con gọi ptrace(PTRACE_TRACEME, ...)
//rồi thoát ngay (_exit(0)), còn tiến trình cha chờ con kết thúc (waitpid)
static void child_ptrace_handshake(void) {
    pid_t child = fork();
    if (child == 0) {
        // PTRACE_TRACEME affects this short-lived child only; no other process
        // is inspected and no payload is read or persisted.
        (void)ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        _exit(0);
    }
    if (child > 0) (void)waitpid(child, NULL, 0);
}

//Gọi SYS_setns với file descriptor -1 (kèm cờ 0 và CLONE_NEWNET)
//uôn thất bại với EBADF nên không thể chuyển namespace.
static void invalid_setns_burst(void) {
    // EBADF is guaranteed: no namespace transition can succeed.
    (void)syscall(SYS_setns, -1, 0);
    (void)syscall(SYS_setns, -1, CLONE_NEWNET);
}

//Gọi SYS_seccomp với mã thao tác không hợp lệ (UINT32_MAX và UINT32_MAX-1)
static void seccomp_api_probe(void) {
    // An unsupported operation is rejected with EINVAL before state changes.
    (void)syscall(SYS_seccomp, UINT32_MAX, 0U, NULL);
    (void)syscall(SYS_seccomp, UINT32_MAX - 1U, 0U, NULL);
}

//Chỉ gọi SYS_getpid, đi cùng quy trình khởi chạy tiến trình mới như các kịch bản trên
//để giúp phân biệt "có tiến trình mới chạy" với "có hành vi tấn công"
static void benign_exec_control(void) {
    (void)syscall(SYS_getpid);
}

static void execveat_resolution_probe(void) {
    char *const argv[] = {(char *)"sentinel-absent", NULL};
    char *const envp[] = {NULL};
    // Invalid dirfd plus a relative absent path guarantees no image change.
    (void)syscall(SYS_execveat, -1, "sentinel-absent", argv, envp, 0);
}

/* Vòng chính: mỗi 1/RATE giây chạy một thao tác của MODE (+ PAD cặp syscall đệm), tới hết SECONDS hoặc bị SIGTERM. */
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s MODE [SECONDS] [RATE] [SEED] [PAD] [ON_OFF]\n", argv[0]);
        return 2;
    }
    const char *mode = argv[1];
    int seconds = argc > 2 ? atoi(argv[2]) : 45;
    // RATE may be fractional (improvement-round-v1 D12, slow attacker: 0.5, 0.2, 0.1 operations per second)
    double rate = argc > 3 ? strtod(argv[3], NULL) : 12.0;
    unsigned long seed = argc > 4 ? strtoul(argv[4], NULL, 10) : 1UL;
    // PAD (adaptive attacker, dilution): after each operation, PAD pairs of common calls (getpid, sched_yield), so the
    // attack's own calls are a smaller share of its windows. 0, the default, is the fixture of the earlier runs.
    int pad = argc > 5 ? atoi(argv[5]) : 0;
    // ON_OFF (D12, on-off attacker): operations only in the first second of every ON_OFF-second period; 0 = always on
    int on_off = argc > 6 ? atoi(argv[6]) : 0;
    if (seconds < 1 || seconds > 600 || rate < 0.05 || rate > 100 || pad < 0 || pad > 10000 || on_off < 0 || on_off > 60)
        return 2;
    rng_state = seed ? seed : 1UL;

    signal(SIGINT, stop_handler);
    signal(SIGTERM, stop_handler);
    const long interval_ns = (long)(1e9 / rate);
    const struct timespec pause = {
        .tv_sec = interval_ns / 1000000000L,
        .tv_nsec = interval_ns % 1000000000L,
    };
    const time_t deadline = time(NULL) + seconds;
    unsigned long iterations = 0;
    fprintf(stderr,
            "sentinel-runtime-attack start mode=%s seconds=%d rate=%g seed=%lu pad=%d on_off=%d\n",
            mode, seconds, rate, seed, pad, on_off);
    const time_t started = time(NULL);

    while (running && time(NULL) < deadline) {
        if (on_off > 0 && (time(NULL) - started) % on_off != 0) {     // off phase: wait for the next period
            struct timespec tick = {.tv_sec = 0, .tv_nsec = 100000000L};
            nanosleep(&tick, NULL);
            continue;
        }
        if (strcmp(mode, "anonymous_mprotect_churn") == 0)
            anonymous_mprotect_churn();
        else if (strcmp(mode, "child_ptrace_handshake") == 0)
            child_ptrace_handshake();
        else if (strcmp(mode, "invalid_setns_burst") == 0)
            invalid_setns_burst();
        else if (strcmp(mode, "seccomp_api_probe") == 0)
            seccomp_api_probe();
        else if (strcmp(mode, "execveat_resolution_probe") == 0)
            execveat_resolution_probe();
        else if (strcmp(mode, "benign_exec_control") == 0)
            benign_exec_control();
        else {
            fprintf(stderr, "unknown mode: %s\n", mode);
            return 2;
        }
        for (int i = 0; i < pad; i++) {
            (void)syscall(SYS_getpid);
            (void)syscall(SYS_sched_yield);
        }
        ++iterations;
        nanosleep(&pause, NULL);
    }
    fprintf(stderr, "sentinel-runtime-attack done mode=%s iterations=%lu\n",
            mode, iterations);
    return 0;
}
