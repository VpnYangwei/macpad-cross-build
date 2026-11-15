// substrate_compat.c — macOS-compatible CydiaSubstrate entry points for chroot use.
// Exports MSHookFunction / MSGetImageByName / MSFindSymbol / MSHookMessageEx,
// linked against macOS Foundation so it loads inside the Ventura chroot
// (the iOS libellekit build depends on iOS Foundation 5026 and cannot dlopen there).
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <libkern/OSCacheControl.h>
#include <objc/runtime.h>

typedef void *MSImageRef;

static void log_hook(uint64_t target, uint64_t repl) {
    char buf[96];
    int n = 0;
    buf[n++] = 'h'; buf[n++] = ' ';
    const char hex[] = "0123456789abcdef";
    for (int s = 60; s >= 0; s -= 4) buf[n++] = hex[(target >> s) & 0xf];
    buf[n++] = ' ';
    for (int s = 60; s >= 0; s -= 4) buf[n++] = hex[(repl >> s) & 0xf];
    buf[n++] = '\n';
    int fd = open("/tmp/mshook.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) { write(fd, buf, n); close(fd); }
}

MSImageRef MSGetImageByName(const char *file) {
    if (!file) return NULL;
    // RTLD_LAZY: defer symbol binding/init so dlopen of an unloaded GUI
    // framework returns without running its constructors on this chroot path.
    return dlopen(file, RTLD_LAZY | RTLD_LOCAL);
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
    // Headless preferences clients (defaults probe) must not patch anything:
    // the hooked flow faults later in main. Skip hooks entirely for them.
    const char *pc = getenv("MACWS_CFPREFERENCES_CLIENT");
    if (pc && pc[0] == '1' && pc[1] == '\0') {
        if (result) *result = NULL;
        return;
    }
    uint64_t target = strip_pac((uint64_t)symbol);
    uint64_t repl = strip_pac((uint64_t)replace);
    log_hook(target, repl);

    // Bisect: hardcoded skip list of target low-32 addresses.
    if ((target & 0xffffffffULL) == 0x9dec49d0ULL ||
        (target & 0xffffffffULL) == 0xa8c531ccULL) {
        if (result) *result = NULL;
        return;
    }

    if (result) {
        // trampoline: copy 32 bytes (8 insns, enough for arm64e PAC prologue
        // + first real insns) then branch back to target+32.
        uint8_t *tramp = mmap(NULL, 0x4000, PROT_READ | PROT_WRITE,
                              MAP_ANON | MAP_PRIVATE, -1, 0);
        if (tramp == MAP_FAILED) { *result = NULL; return; }
        memcpy(tramp, (void *)target, 32);
        uint64_t after = target + 32;
        int64_t off = (int64_t)(after - ((uint64_t)tramp + 32));
        if (off >= -0x08000000LL && off < 0x08000000LL) {
            uint32_t b = 0x14000000U | ((uint32_t)((off >> 2) & 0x03FFFFFFU));
            *(uint32_t *)(tramp + 32) = b;
        }
        mprotect(tramp, 0x4000, PROT_READ | PROT_EXEC);
        sys_icache_invalidate(tramp, 64);
#if defined(__arm64e__)
        // Function-pointer calls authenticate with a zero discriminator
        // (pacizb). Signing with the target as discriminator faults later.
        uint64_t signed_tramp = (uint64_t)tramp;
        __asm__ volatile("pacizb %0" : "+r"(signed_tramp));
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
