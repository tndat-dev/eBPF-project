// SPDX-License-Identifier: GPL-2.0
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
