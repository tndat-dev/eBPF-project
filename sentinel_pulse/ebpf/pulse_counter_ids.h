// SPDX-License-Identifier: GPL-2.0
/* [VI] pulse_counter_ids.h — 29 SYSCALL ĐƯỢC THEO DÕI RIÊNG trong ảnh chụp bộ đếm (mô hình đếm cũ, nay chạy shadow).
 *
 * Dạng "X-macro": PULSE_TRACKED_ROWS(X) gọi X(số_syscall, slot) cho từng dòng. Nơi dùng tự định nghĩa X để sinh ra thứ
 * nó cần (ví dụ mảng số syscall trong pulse_counter_projection.h). Nhờ vậy danh sách chỉ viết MỘT lần.
 *   X(id, slot): id = số syscall x86_64 (0 read, 1 write, 2 open, 3 close, 9 mmap, 10 mprotect, 41 socket, 42 connect,
 *   43 accept, 44 sendto, 45 recvfrom, 56 clone, 59 execve, 90 chmod, 101 ptrace, 105 setuid, 106 setgid, 126 capset,
 *   155 pivot_root, 165 mount, 257 openat, 272 unshare, 288 accept4, 299 recvmmsg, 307 sendmmsg, 308 setns,
 *   317 seccomp, 322 execveat, 435 clone3); slot = vị trí cột trong vector đặc trưng.
 * Thứ tự PHẢI trùng với danh sách syscall trong sentinel_pulse/collector/features.py (comment gốc bên dưới nói vậy).
 * Đây là các syscall nhạy cảm về an ninh (đổi quyền, namespace, exec, ptrace, mount...) mà mô hình đếm cũ xem riêng. */
#ifndef PULSE_COUNTER_IDS_H
#define PULSE_COUNTER_IDS_H

/* Keep explicit feature order identical to features.py's x86_64 syscall IDs. */
#define PULSE_TRACKED_ROWS(X) \
    X(0, 0) X(1, 1) X(2, 2) X(3, 3) X(9, 4) X(10, 5) \
    X(41, 6) X(42, 7) X(43, 8) X(44, 9) X(45, 10) X(56, 11) \
    X(59, 12) X(90, 13) X(101, 14) X(105, 15) X(106, 16) \
    X(126, 17) X(155, 18) X(165, 19) X(257, 20) X(272, 21) \
    X(288, 22) X(299, 23) X(307, 24) X(308, 25) X(317, 26) \
    X(322, 27) X(435, 28)

#endif
