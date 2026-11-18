// SPDX-License-Identifier: GPL-2.0
/* ===================================================================================================================
 * pulse_counter_projection.h — GỘP BỘ ĐẾM SYSCALL TỪ NHIỀU CPU THÀNH MỘT ẢNH CHỤP (dùng ở USER SPACE)
 * -------------------------------------------------------------------------------------------------------------------
 * Vai trò trong hệ thống:
 *   - Trong kernel, chương trình eBPF (pulse_counter.bpf.c) đếm số lần mỗi container gọi từng syscall. Bộ đếm nằm trong
 *     map kiểu PERCPU_HASH: mỗi CPU có MỘT BẢN RIÊNG của `struct pulse_counters` cho mỗi cgroup (container), để các CPU
 *     không phải tranh nhau khoá khi tăng bộ đếm (nhanh hơn nhiều so với một bộ đếm chung).
 *   - Loader (pulse_counter_loader.c) đọc map định kỳ; mỗi lần đọc một cgroup nhận về N bản (N = số CPU). File này cung
 *     cấp hàm `pulse_project_cpu` để CỘNG từng bản vào một `struct pulse_snapshot` duy nhất, rồi loader in snapshot đó ra
 *     JSON cho worker Python.
 *   - Đây là phần "ML cũ" (đếm syscall theo cửa sổ, dùng cho cây ExtraTrees + support). Từ lidds-ml-v5, đường cảnh báo chỉ
 *     dùng mô hình token (pulse_tokens.bpf.h); bộ đếm này vẫn chạy để tính nhánh đếm ở chế độ shadow (chỉ ghi, không báo).
 *
 * Vì sao là file .h dùng chung: struct `pulse_counters` ở đây phải TRÙNG BỐ CỤC BYTE với struct cùng tên trong
 * pulse_counter.bpf.c (kernel). _Static_assert bên dưới bắt lỗi nếu ai đổi một bên mà quên bên kia.
 * =================================================================================================================== */
#ifndef PULSE_COUNTER_PROJECTION_H
#define PULSE_COUNTER_PROJECTION_H
#include <stdint.h>
#include "pulse_counter_ids.h"   /* danh sách 29 syscall "được theo dõi riêng" (PULSE_TRACKED_ROWS) */

/* Kernel ABI: exactly one primary counter is incremented per syscall entry.
 * There is no separately updated total/full histogram to race with that word.
 * Like the legacy per-CPU read this is NOT an atomic cross-CPU time cut. */
/* Giá trị của map trong kernel, cho MỘT cgroup trên MỘT CPU.
 *   - full_counts[id]: số lần syscall số `id` (số syscall x86_64, 0..1023) được gọi.
 *   - transition_bins: "phác thảo chuyển tiếp" — mỗi cặp (syscall trước, syscall sau) của cùng một thread được băm vào
 *     1 trong 64 ô; cho biết thứ tự gọi một cách thô (không phải 4-gram đầy đủ như probe token).
 *   - seccomp_skipped_or_emulated: số lời gọi bị seccomp chặn/giả lập (không bao giờ tới sys_enter bình thường).
 * Lưu ý (câu tiếng Anh ở trên): đọc N bản per-CPU KHÔNG phải một lát cắt thời gian nguyên tử — CPU này có thể đã đếm
 * thêm trong lúc loader đang đọc CPU khác. Sai số này nhỏ so với cửa sổ 1 s và được chấp nhận. */
struct pulse_counters {
    uint64_t full_counts[1024];
    uint64_t transition_bins[PULSE_TRANSITION_BINS];
    uint64_t seccomp_skipped_or_emulated;
};

/* Ảnh chụp đã gộp mọi CPU của một cgroup — thứ loader in ra JSON ("cgroup_snapshot_extended"):
 *   - full_counts: như trên, đã cộng mọi CPU;
 *   - syscall_bins: 64 ô, mỗi syscall băm vào một ô (đặc trưng gọn cho mô hình đếm cũ);
 *   - tracked: số đếm của đúng 29 syscall trong PULSE_TRACKED_ROWS (theo thứ tự cố định mà features.py mong đợi);
 *   - total: tổng số syscall của cgroup trong khoảng đọc. */
struct pulse_snapshot {
    uint64_t full_counts[1024];
    uint64_t syscall_bins[PULSE_SYSCALL_BINS];
    uint64_t transition_bins[PULSE_TRANSITION_BINS];
    uint64_t tracked[PULSE_TRACKED];
    uint64_t total;
    uint64_t seccomp_skipped_or_emulated;
};

/* Khoá bố cục: 1024 bộ đếm syscall + 64 ô chuyển tiếp + 1 bộ đếm seccomp, mỗi cái 8 byte. Nếu kernel và loader
 * lệch nhau, loader sẽ đọc rác; lỗi biên dịch ở đây chặn chuyện đó từ sớm. */
_Static_assert(sizeof(struct pulse_counters) == (1024 + 64 + 1) * 8,
               "full-ID extended counter map ABI changed");

/* Cộng có kiểm tra tràn số: trả -1 nếu destination + value vượt UINT64_MAX (thực tế không xảy ra với bộ đếm 64 bit,
 * nhưng nếu xảy ra thì cả ảnh chụp bị bỏ thay vì in một con số sai). */
static inline int pulse_add_u64(uint64_t *destination, uint64_t value)
{
    if (UINT64_MAX - *destination < value)
        return -1;
    *destination += value;
    return 0;
}

/* Input is one already copied per-CPU value, never a live map pointer.
 * A partially written destination on overflow must be discarded by caller. */
/* Cộng bản của MỘT CPU (`raw`, đã chép ra khỏi map) vào ảnh chụp `sum`. Loader gọi hàm này lần lượt cho từng CPU.
 * Trả 0 nếu ổn, -1 nếu tràn số (khi đó loader bỏ cả ảnh chụp của cgroup này và tăng bộ đếm projection_failures). */
static inline int pulse_project_cpu(
    const struct pulse_counters *raw, struct pulse_snapshot *sum)
{
    /* Bảng số syscall của 29 syscall được theo dõi, sinh từ macro X-list PULSE_TRACKED_ROWS:
     * mỗi dòng X(id, slot) trở thành phần tử `id,` — thứ tự mảng = thứ tự slot. */
    static const uint32_t ids[PULSE_TRACKED] = {
#define PULSE_ID(id, slot) id,
        PULSE_TRACKED_ROWS(PULSE_ID)
#undef PULSE_ID
    };
    for (int id = 0; id < 1024; id++) {
        uint64_t count = raw->full_counts[id];
        /* Băm Fibonacci: nhân với 2654435761 (≈ 2^32 / tỉ lệ vàng) rồi lấy 6 bit cao (>> 26) → ô 0..63.
         * Đây đúng là hàm syscall_bin() trong pulse_counter.bpf.c, nên user space và kernel chia ô giống nhau. */
        uint32_t bin = ((uint32_t)id * 2654435761U) >> 26;
        if (pulse_add_u64(&sum->full_counts[id], count) ||
            pulse_add_u64(&sum->syscall_bins[bin], count) ||
            pulse_add_u64(&sum->total, count)) return -1;
    }
    /* 29 cột "tracked" chỉ là bản sao của full_counts tại đúng các số syscall đó, theo thứ tự slot. */
    for (int slot = 0; slot < PULSE_TRACKED; slot++)
        if (pulse_add_u64(&sum->tracked[slot], raw->full_counts[ids[slot]])) return -1;
    for (int bin = 0; bin < PULSE_TRANSITION_BINS; bin++)
        if (pulse_add_u64(&sum->transition_bins[bin], raw->transition_bins[bin]))
            return -1;
    if (pulse_add_u64(&sum->seccomp_skipped_or_emulated, raw->seccomp_skipped_or_emulated))
        return -1;
    return 0;
}
#endif
