// substrate_compat.c — macOS-compatible CydiaSubstrate entry points for chroot use.
// Exports MSHookFunction / MSGetImageByName / MSFindSymbol / MSHookMessageEx,
// linked against macOS Foundation so it loads inside the Ventura chroot
// (the iOS libellekit build depends on iOS Foundation 5026 and cannot dlopen there).
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <libkern/OSCacheControl.h>
#include <objc/runtime.h>

static void crash_log(const char *tag, uintptr_t v) {
    char buf[80];
    int n = 0;
    const char *t = tag;
    while (*t && n < 40) buf[n++] = *t++;
    buf[n++] = ' ';
    const char hex[] = "0123456789abcdef";
    for (int s = 60; s >= 0; s -= 4) buf[n++] = hex[(v >> s) & 0xf];
    buf[n++] = '\n';
    int fd = open("/tmp/sub_crash.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) { write(fd, buf, n); close(fd); }
}

static void sigbus_handler(int sig, siginfo_t *si, void *ctx) {
    crash_log("SIGBUS", (uintptr_t)si->si_addr);
    uintptr_t pc = (uintptr_t)si->si_addr;
    int fd = open("/tmp/sub_crash.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        char b[256];
        int n = 0;
        const char *h = "0123456789abcdef";
        // dump 8 insns before PC and 8 after
        const uint32_t *base = (const uint32_t *)(pc - 32);
        b[n++] = 'C'; b[n++] = ' ';
        for (int i = 0; i < 16; i++) {
            uint32_t v = base[i];
            for (int s = 28; s >= 0; s -= 4) b[n++] = h[(v >> s) & 0xf];
        }
        b[n++] = '\n';
        write(fd, b, n);
        close(fd);
    }
    _exit(128 + sig);
}

typedef void *MSImageRef;

static void log_hook(uint64_t target, uint64_t repl) {
    char buf[160];
    int n = 0;
    buf[n++] = 'h'; buf[n++] = ' ';
    const char hex[] = "0123456789abcdef";
    for (int s = 60; s >= 0; s -= 4) buf[n++] = hex[(target >> s) & 0xf];
    buf[n++] = ' ';
    for (int s = 60; s >= 0; s -= 4) buf[n++] = hex[(repl >> s) & 0xf];
    buf[n++] = ' ';
    const uint32_t *code = (const uint32_t *)target;
    for (int i = 0; i < 8; i++) {
        for (int s = 28; s >= 0; s -= 4) buf[n++] = hex[(code[i] >> s) & 0xf];
    }
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
    if (!name) return NULL;
    // libxpc.dylib and other Ventura libs live only in the dyld shared
    // cache here, so dlopen may return NULL; RTLD_DEFAULT still resolves
    // the symbol from the process image list.
    void *sym = dlsym(image ? image : RTLD_DEFAULT, name);
#if defined(__arm64e__)
    // dlsym returns a bare address on this chroot path; libmachook's
    // BRAAZ/BLRAAZ call sites authenticate function pointers with the
    // zero-discriminator, so sign it (pacizb) before returning.
    if (sym) {
        uint64_t s = (uint64_t)sym;
        __asm__ volatile("pacizb %0" : "+r"(s));
        sym = (void *)s;
    }
#endif
    return sym;
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

// Fix up PC-relative adr/adrp instructions copied into the trampoline.
// Original targets are computed from the source address, then re-encoded
// relative to the trampoline address.
static void fixup_pcrel(uint32_t *code, size_t insns, uint64_t src, uint64_t dst) {
    for (size_t i = 0; i < insns; i++) {
        uint32_t insn = code[i];
        uint64_t src_pc = src + i * 4;
        uint64_t dst_pc = dst + i * 4;
        if ((insn & 0x9F000000) == 0x10000000) {  // adr
            int64_t imm = ((int64_t)((insn >> 5) & 0x7FFFF) << 2) |
                          ((insn >> 29) & 0x3);
            if (imm & (1 << 20)) imm -= (1 << 21);  // sign extend 21-bit
            uint64_t target = src_pc + imm;
            int64_t nimm = (int64_t)(target - dst_pc);
            if (nimm >= -(1 << 20) && nimm < (1 << 20)) {
                insn &= ~(0x7FFFF << 5) & ~(0x3 << 29);
                insn |= ((uint32_t)((nimm >> 2) & 0x7FFFF) << 5);
                insn |= ((uint32_t)(nimm & 0x3) << 29);
                code[i] = insn;
            }
        } else if ((insn & 0x9F000000) == 0x90000000) {  // adrp
            int64_t imm = ((int64_t)((insn >> 5) & 0x7FFFF) << 2) |
                          ((insn >> 29) & 0x3);
            imm <<= 12;
            if (imm & (1 << 32)) imm -= (1LL << 33);  // sign extend 33-bit
            uint64_t target = (src_pc & ~0xFFFULL) + imm;
            int64_t nimm = (int64_t)((target & ~0xFFFULL) - (dst_pc & ~0xFFFULL));
            nimm >>= 12;
            insn &= ~(0x7FFFF << 5) & ~(0x3 << 29);
            insn |= ((uint32_t)((nimm >> 2) & 0x7FFFF) << 5);
            insn |= ((uint32_t)(nimm & 0x3) << 29);
            code[i] = insn;
        }
    }
}

static void write_branch(uint64_t from, uint64_t to) {
    int64_t offset = (int64_t)(to - from);
    uint64_t page = from & ~0x3FFFULL;
    size_t page_len = 0x4000;
    if (offset < -0x08000000LL || offset >= 0x08000000LL) {
        // Absolute far branch: ldr x16, #8; br x16; .quad to
        uint32_t *p = (uint32_t *)from;
        p[0] = 0x58000050U;  // ldr x16, #8
        p[1] = 0xD61F0200U;  // br x16
        *(uint64_t *)(p + 2) = to;
    } else {
        uint32_t b = 0x14000000U | ((uint32_t)((offset >> 2) & 0x03FFFFFFU));
        *(uint32_t *)from = b;
    }
    sys_icache_invalidate((void *)from, 16);
    vm_protect(mach_task_self(), (vm_address_t)page, page_len,
               true, VM_PROT_READ | VM_PROT_EXECUTE);
    {
        char buf[64];
        uint32_t insn = *(uint32_t *)from;
        int n = 0;
        buf[n++] = 'p'; buf[n++] = ' ';
        const char hex[] = "0123456789abcdef";
        for (int s = 28; s >= 0; s -= 4) buf[n++] = hex[(insn >> s) & 0xf];
        buf[n++] = '\n';
        int fd = open("/tmp/mshook.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd >= 0) { write(fd, buf, n); close(fd); }
    }
}

void MSHookFunction(void *symbol, void *replace, void **result) {
    static int sig_installed = 0;
    if (!sig_installed) {
        sig_installed = 1;
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_sigaction = sigbus_handler;
        sa.sa_flags = SA_SIGINFO;
        sigaction(SIGBUS, &sa, NULL);
        sigaction(SIGSEGV, &sa, NULL);
    }
    if (!symbol || !replace) {
        if (result) *result = NULL;
        return;
    }
    // cfprefsd is the XPC server; its own startup must not be hooked.
    const char *pn = getprogname();
    int is_cfprefsd = pn && pn[0] == 'm' && pn[1] == 'a' && pn[2] == 'c' &&
        pn[3] == 'w' && pn[4] == 's' && pn[5] == '-' && pn[6] == 'c' && pn[7] == 'f';
    if (is_cfprefsd) {
        if (result) *result = NULL;
        return;
    }
    uint64_t target = strip_pac((uint64_t)symbol);
    uint64_t repl = strip_pac((uint64_t)replace);
    log_hook(target, repl);

    if (result) {
        uint8_t *tramp = mmap(NULL, 0x4000, PROT_READ | PROT_WRITE,
                              MAP_ANON | MAP_PRIVATE, -1, 0);
        if (tramp == MAP_FAILED) { *result = NULL; return; }
        memcpy(tramp, (void *)target, 32);
        // Keeping this loop is load-critical: without it the dylib fails to
        // dlopen on the chroot path. It replaces any leading PAC SP prologue
        // instruction with NOP in the trampoline.
        for (int i = 0; i < 8; i++) {
            uint32_t insn = ((uint32_t *)tramp)[i];
            if (insn == 0xD503237F ||  // pacibsp
                insn == 0xD503233F) {  // paciasp
                ((uint32_t *)tramp)[i] = 0xD503201F;  // nop
            }
        }
        fixup_pcrel((uint32_t *)tramp, 8, target, (uint64_t)tramp);
        uint64_t after = target + 32;
        int64_t off = (int64_t)(after - ((uint64_t)tramp + 32));
        if (off >= -0x08000000LL && off < 0x08000000LL) {
            uint32_t b = 0x14000000U | ((uint32_t)((off >> 2) & 0x03FFFFFFU));
            *(uint32_t *)(tramp + 32) = b;
        }
        mprotect(tramp, 0x4000, PROT_READ | PROT_EXEC);
        sys_icache_invalidate(tramp, 64);
#if defined(__arm64e__)
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
