// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
// Sorted set of address ranges with lock-free readers.
//
// Readers (hooks on the hot path) take the current snapshot with one atomic load and
// binary-search it: no lock, no allocation (ТЗ §5). Writers are rare (a module load, an
// executable allocation) and copy the snapshot under an SRW lock. Old snapshots are kept
// alive on purpose — a reader may still be looking at one; with merged ranges the arrays
// stay small (tens of entries), so the cost is a few kilobytes per session.
#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "nt.hpp"

namespace mebet {

template <typename Payload>
class RangeSet {
public:
    struct Entry {
        std::uintptr_t begin;
        std::uintptr_t end;  // exclusive
        Payload payload;
    };

    RangeSet() : current_(make_snapshot(0)) { InitializeSRWLock(&lock_); }

    // Lock-free.
    bool find(std::uintptr_t addr, Entry* out = nullptr) const {
        const Snapshot* s = current_.load(std::memory_order_acquire);
        std::size_t lo = 0, hi = s->count;
        while (lo < hi) {
            const std::size_t mid = (lo + hi) / 2;
            const Entry& e = s->entries[mid];
            if (addr < e.begin) {
                hi = mid;
            } else if (addr >= e.end) {
                lo = mid + 1;
            } else {
                if (out) *out = e;
                return true;
            }
        }
        return false;
    }

    // Lock-free: is [begin, end) covered by the union of the entries?
    bool covers(std::uintptr_t begin, std::uintptr_t end) const {
        const Snapshot* s = current_.load(std::memory_order_acquire);
        std::uintptr_t pos = begin;
        for (std::size_t i = 0; i < s->count && pos < end; ++i) {
            const Entry& e = s->entries[i];
            if (e.end <= pos) continue;
            if (e.begin > pos) return false;
            pos = e.end;
        }
        return pos >= end;
    }

    // Lock-free: does [begin, end) touch any entry?
    bool overlaps(std::uintptr_t begin, std::uintptr_t end) const {
        const Snapshot* s = current_.load(std::memory_order_acquire);
        for (std::size_t i = 0; i < s->count; ++i) {
            const Entry& e = s->entries[i];
            if (e.begin >= end) break;
            if (e.end > begin) return true;
        }
        return false;
    }

    // Adds [begin, end); with merge, touching entries with an equal payload are joined.
    void add(std::uintptr_t begin, std::uintptr_t end, const Payload& payload, bool merge) {
        if (begin >= end) return;
        AcquireSRWLockExclusive(&lock_);
        const Snapshot* old = current_.load(std::memory_order_relaxed);
        std::vector<Entry> v;
        v.reserve(old->count + 1);
        for (std::size_t i = 0; i < old->count; ++i) {
            const Entry& e = old->entries[i];
            if (e.end <= begin || e.begin >= end) {
                v.push_back(e);  // untouched
                continue;
            }
            // Overlap: keep the parts outside the new range.
            if (e.begin < begin) v.push_back({e.begin, begin, e.payload});
            if (e.end > end) v.push_back({end, e.end, e.payload});
        }
        Entry fresh{begin, end, payload};
        std::size_t at = 0;
        while (at < v.size() && v[at].begin < begin) ++at;
        v.insert(v.begin() + static_cast<std::ptrdiff_t>(at), fresh);
        if (merge) {
            std::vector<Entry> m;
            m.reserve(v.size());
            for (const Entry& e : v) {
                if (!m.empty() && m.back().end == e.begin && m.back().payload == e.payload) {
                    m.back().end = e.end;
                } else {
                    m.push_back(e);
                }
            }
            v.swap(m);
        }
        publish(v);
        ReleaseSRWLockExclusive(&lock_);
    }

    // Removes [begin, end) from every entry it touches.
    void remove(std::uintptr_t begin, std::uintptr_t end) {
        if (begin >= end || !overlaps(begin, end)) return;
        AcquireSRWLockExclusive(&lock_);
        const Snapshot* old = current_.load(std::memory_order_relaxed);
        std::vector<Entry> v;
        v.reserve(old->count + 1);
        for (std::size_t i = 0; i < old->count; ++i) {
            const Entry& e = old->entries[i];
            if (e.end <= begin || e.begin >= end) {
                v.push_back(e);
                continue;
            }
            if (e.begin < begin) v.push_back({e.begin, begin, e.payload});
            if (e.end > end) v.push_back({end, e.end, e.payload});
        }
        publish(v);
        ReleaseSRWLockExclusive(&lock_);
    }

    std::vector<Entry> entries() const {
        const Snapshot* s = current_.load(std::memory_order_acquire);
        return std::vector<Entry>(s->entries, s->entries + s->count);
    }

private:
    struct Snapshot {
        std::size_t count;
        Entry entries[1];
    };

    static Snapshot* make_snapshot(std::size_t n) {
        const std::size_t bytes = sizeof(Snapshot) + (n ? n - 1 : 0) * sizeof(Entry);
        void* mem = ::operator new(bytes);
        Snapshot* s = static_cast<Snapshot*>(mem);
        s->count = n;
        return s;
    }

    void publish(const std::vector<Entry>& v) {
        Snapshot* s = make_snapshot(v.size());
        for (std::size_t i = 0; i < v.size(); ++i) s->entries[i] = v[i];
        current_.store(s, std::memory_order_release);  // the previous snapshot is intentionally kept
    }

    std::atomic<Snapshot*> current_;
    SRWLOCK lock_;
};

}  // namespace mebet
