// Every C++ allocation of the agent goes to its own heap.
//
// The hooks on NtAllocateVirtualMemory / NtFreeVirtualMemory run while the caller may hold
// the process heap lock (the heap itself grows and shrinks through these calls). If the
// slow path of a hook allocated from the process heap it could re-enter a heap that is
// half-way through an update. A private heap has its own lock, so the guard never touches
// a lock its caller might hold (ТЗ §5: no locks on the hot path, no reentrancy into the caller).

#include <cstddef>
#include <new>

#include "nt.hpp"

namespace {

HANDLE g_heap = nullptr;

HANDLE heap() {
    HANDLE h = g_heap;
    if (h) return h;
    HANDLE created = HeapCreate(0, 0, 0);
    if (!created) return GetProcessHeap();
    if (InterlockedCompareExchangePointer(&g_heap, created, nullptr) != nullptr) {
        HeapDestroy(created);
    }
    return g_heap;
}

void* allocate(std::size_t n) {
    void* p = HeapAlloc(heap(), 0, n ? n : 1);
    if (!p) throw std::bad_alloc();
    return p;
}

void* allocate_nothrow(std::size_t n) noexcept { return HeapAlloc(heap(), 0, n ? n : 1); }

void release(void* p) noexcept {
    if (p) HeapFree(heap(), 0, p);
}

// Aligned variants keep the original pointer just before the aligned block.
void* allocate_aligned(std::size_t n, std::size_t align) {
    if (align < sizeof(void*)) align = sizeof(void*);
    char* raw = static_cast<char*>(allocate(n + align + sizeof(void*)));
    std::size_t addr = reinterpret_cast<std::size_t>(raw + sizeof(void*));
    addr = (addr + align - 1) & ~(align - 1);
    reinterpret_cast<void**>(addr)[-1] = raw;
    return reinterpret_cast<void*>(addr);
}

void release_aligned(void* p) noexcept {
    if (p) release(static_cast<void**>(p)[-1]);
}

}  // namespace

void* operator new(std::size_t n) { return allocate(n); }
void* operator new[](std::size_t n) { return allocate(n); }
void* operator new(std::size_t n, const std::nothrow_t&) noexcept { return allocate_nothrow(n); }
void* operator new[](std::size_t n, const std::nothrow_t&) noexcept { return allocate_nothrow(n); }
void operator delete(void* p) noexcept { release(p); }
void operator delete[](void* p) noexcept { release(p); }
void operator delete(void* p, std::size_t) noexcept { release(p); }
void operator delete[](void* p, std::size_t) noexcept { release(p); }
void operator delete(void* p, const std::nothrow_t&) noexcept { release(p); }
void operator delete[](void* p, const std::nothrow_t&) noexcept { release(p); }

void* operator new(std::size_t n, std::align_val_t a) { return allocate_aligned(n, static_cast<std::size_t>(a)); }
void* operator new[](std::size_t n, std::align_val_t a) { return allocate_aligned(n, static_cast<std::size_t>(a)); }
void operator delete(void* p, std::align_val_t) noexcept { release_aligned(p); }
void operator delete[](void* p, std::align_val_t) noexcept { release_aligned(p); }
void operator delete(void* p, std::size_t, std::align_val_t) noexcept { release_aligned(p); }
void operator delete[](void* p, std::size_t, std::align_val_t) noexcept { release_aligned(p); }
