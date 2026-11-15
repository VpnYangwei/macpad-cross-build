// substrate_compat.c — macOS-compatible CydiaSubstrate entry points for chroot use.
// Exports MSHookFunction / MSGetImageByName / MSFindSymbol / MSHookMessageEx,
// linked against macOS Foundation so it loads inside the Ventura chroot
// (the iOS libellekit build depends on iOS Foundation 5026 and cannot dlopen there).
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <libkern/OSCacheControl.h>
#include <objc/runtime.h>

typedef void *MSImageRef;

static int my_streq(const char *a, const char *b) {
    if (!a || !b) return 0;
    while (*a && *a == *b) { a++; b++; }
    return *a == *b;
}

MSImageRef MSGetImageByName(const char *file) {
    if (!file) return NULL;
    // Headless preferences clients must not dlopen GUI frameworks (SkyLight,
    // Metal, QuartzCore): their init faults (Bus error) on this chroot path.
    // libmachook sets MACWS_CFPREFERENCES_CLIENT=1 for the defaults probe.
    const char *pc = getenv("MACWS_CFPREFERENCES_CLIENT");
    if (pc && my_streq(pc, "1")) return NULL;
    return dlopen(file, RTLD_NOW | RTLD_LOCAL);
}

void *MSFindSymbol(MSImageRef image, const char *name) {
    if (!image || !name) return NULL;
    return dlsym(image, name);
}

static uint64_t strip_pac(uint64_t v) {
#if defined(__arm64e__)
    __asm__ volatile("xpaci %0" : "+r"(v));
#endif
    return v;
}

static void make_writable(uint64_t addr, size_t len) {
    uint64_t page = addr & ~0x3FFFULL;
    size_t size = ((addr + len - page + 0x3FFF) & ~0x3FFFULL);
    vm_protect(mach_task_self(), (vm_address_t)page, size, false,
               VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
}

static void write_branch(uint64_t from, uint64_t to) {
    int64_t offset = (int64_t)(to - from);
    if (offset < -0x08000000LL || offset >= 0x08000000LL) {
        // Far branch: adrp x16, page(to); add x16, x16, off; br x16
        uint64_t from_page = from & ~0xFFFULL;
        uint64_t to_page = to & ~0xFFFULL;
        int64_t page_off = (int64_t)(to_page - from_page);
        uint32_t adrp = 0x90000010U | (((uint32_t)((page_off >> 12) & 0x3FFFF)) << 5) |
                        (((uint32_t)((page_off >> 14) & 0x7FFFF)) << 5);
        // encode adrp properly: immhi:19 = bits 20:2 of page_off, immlo:2 = bits 1:0
        int64_t imm = page_off >> 12;
        uint32_t immhi = (uint32_t)((imm >> 2) & 0x7FFFF);
        uint32_t immlo = (uint32_t)(imm & 0x3);
        adrp = 0x90000010U | (immlo << 29) | (immhi << 5);
        uint32_t add = 0x91000210U | ((uint32_t)(to & 0xFFF) << 10);
        uint32_t br = 0xD61F0200U;
        uint32_t *p = (uint32_t *)from;
        p[0] = adrp;
        p[1] = add;
        p[2] = br;
    } else {
        uint32_t b = 0x14000000U | ((uint32_t)((offset >> 2) & 0x03FFFFFFU));
        *(uint32_t *)from = b;
    }
    sys_icache_invalidate((void *)from, 16);
}

void MSHookFunction(void *symbol, void *replace, void **result) {
    if (!symbol || !replace) {
        if (result) *result = NULL;
        return;
    }
    uint64_t target = strip_pac((uint64_t)symbol);
    uint64_t repl = strip_pac((uint64_t)replace);

    if (result) {
        // trampoline: original 16 bytes + branch back to target+16.
        // arm64e: the returned trampoline pointer must carry the same PAC
        // signature the caller expects for a function pointer, otherwise the
        // indirect call faults (Bus error). Sign it with the ASIA key using
        // the stripped target address as discriminator.
        uint8_t *tramp = mmap(NULL, 0x4000, PROT_READ | PROT_WRITE,
                              MAP_ANON | MAP_PRIVATE, -1, 0);
        if (tramp == MAP_FAILED) { *result = NULL; return; }
        memcpy(tramp, (void *)target, 16);
        uint64_t after = target + 16;
        int64_t off = (int64_t)(after - ((uint64_t)tramp + 16));
        if (off >= -0x08000000LL && off < 0x08000000LL) {
            uint32_t b = 0x14000000U | ((uint32_t)((off >> 2) & 0x03FFFFFFU));
            *(uint32_t *)(tramp + 16) = b;
        }
        mprotect(tramp, 0x4000, PROT_READ | PROT_EXEC);
        sys_icache_invalidate(tramp, 32);
#if defined(__arm64e__)
        // Hand-written PACIA instead of the ptrauth_sign_unauthenticated
        // builtin: the builtin emits __ptrauth fixups that dyld rejects on
        // this chroot path, while a plain pacia instruction does not.
        uint64_t signed_tramp = (uint64_t)tramp;
        __asm__ volatile("pacia %0, %1" : "+r"(signed_tramp) : "r"(target));
        *result = (void *)signed_tramp;
#else
        *result = tramp;
#endif
    }

    make_writable(target, 16);
    write_branch(target, repl);
}

void MSHookMessageEx(Class cls, SEL sel, IMP imp, IMP *result) {
    if (!cls || !sel || !imp) return;
    Method m = class_getInstanceMethod(cls, sel);
    if (result) *result = m ? method_getImplementation(m) : NULL;
    if (m) method_setImplementation(m, imp);
}
