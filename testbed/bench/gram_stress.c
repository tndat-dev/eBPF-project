// Gram-map load generator for the token probe's capacity test (protocol map-capacity-v1).
// THREADS threads each issue RATE syscalls per second for SECONDS seconds, picking each call at random from 32 calls
// that give 32 distinct select1f tokens (read and write of 16 sizes each from /dev/zero and to /dev/null), so the
// 4-grams of a thread are random over 32^4 (about one million) values: almost every event of a window is a new
// gram until the window holds about a million, which is what fills the probe's (cgroup, window, gram) map.
// Prints one JSON line: {"threads": T, "rate": R, "seconds": S, "events": N}.
// Bộ sinh tải tệ nhất cho map 4-gram: mỗi lời gọi là read/write ngẫu nhiên trong 32 token khác nhau nên gần như mọi
// sự kiện là một gram mới; scripts/map_capacity_test.py tăng dần syscall/s tới khi map đầy (map-capacity-v1).
#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

static int zero_fd, null_fd, rate_per_thread;
static double seconds;
static char buffer[1 << 16];

static double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void *worker(void *arg) {
    uint64_t state = 0x9E3779B97F4A7C15ULL ^ (uint64_t)(uintptr_t)arg;
    unsigned long long *events = arg;
    double start = now(), stop = start + seconds;
    double step = 1.0 / rate_per_thread, next = start;
    unsigned long long n = 0;
    while (now() < stop) {
        for (int i = 0; i < 64; i++) {
            state ^= state << 13; state ^= state >> 7; state ^= state << 17;
            unsigned pick = (unsigned)(state & 31);
            size_t size = (size_t)1 << (pick & 15);            // 1 .. 32768 bytes: log2 buckets 0 .. 15
            ssize_t r = (pick & 16) ? write(null_fd, buffer, size) : read(zero_fd, buffer, size);
            (void)r;
            n++;
        }
        next += 64 * step;
        double wait = next - now();
        if (wait > 0) {
            struct timespec ts = {(time_t)wait, (long)((wait - (time_t)wait) * 1e9)};
            nanosleep(&ts, NULL);
        }
    }
    *events = n;
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s THREADS RATE_PER_THREAD SECONDS\n", argv[0]);
        return 2;
    }
    int threads = atoi(argv[1]);
    rate_per_thread = atoi(argv[2]);
    seconds = atof(argv[3]);
    if (threads < 1 || threads > 256 || rate_per_thread < 64 || seconds <= 0 || seconds > 600) return 2;
    zero_fd = open("/dev/zero", O_RDONLY);
    null_fd = open("/dev/null", O_WRONLY);
    if (zero_fd < 0 || null_fd < 0) return 1;
    pthread_t ids[256];
    unsigned long long counts[256];
    for (int t = 0; t < threads; t++) {
        counts[t] = (unsigned long long)t + 1;               // seeds the thread's generator, overwritten with its count
        if (pthread_create(&ids[t], NULL, worker, &counts[t]) != 0) return 1;
    }
    unsigned long long total = 0;
    for (int t = 0; t < threads; t++) {
        pthread_join(ids[t], NULL);
        total += counts[t];
    }
    printf("{\"threads\": %d, \"rate\": %d, \"seconds\": %.3f, \"events\": %llu}\n", threads, rate_per_thread, seconds, total);
    return 0;
}
