// Forwarding shim for the CydiaSubstrate entry points that libmachook calls.
//
// The macOS cross-build links with -undefined dynamic_lookup, so ld64 never
// records a dependency on CydiaSubstrate.framework and dyld then aborts at
// injection with "symbol not found in flat namespace '_MSFindSymbol'".
// Defining the four entry points here removes the undefined symbols entirely:
// each one lazily dlopen()s the real framework (ElleKit in this chroot) and
// forwards, so hook behaviour is unchanged.

#include <dlfcn.h>
#include <stdio.h>
#include <pthread.h>
#include <objc/runtime.h>

typedef void *MSImageRef;

typedef MSImageRef (*PFN_GetImageByName)(const char *);
typedef void *(*PFN_FindSymbol)(MSImageRef, const char *);
typedef void (*PFN_HookFunction)(void *, void *, void **);
typedef void (*PFN_HookMessageEx)(Class, SEL, IMP, IMP *);

static void *gSubstrateHandle;
static PFN_GetImageByName gGetImageByName;
static PFN_FindSymbol gFindSymbol;
static PFN_HookFunction gHookFunction;
static PFN_HookMessageEx gHookMessageEx;
static int gLoadAttempted;
static pthread_mutex_t gLoadLock = PTHREAD_MUTEX_INITIALIZER;

static void MacWSSubstrateLoad(void) {
    static const char *candidates[] = {
        "/System/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate",
        "/var/jb/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate",
        "/usr/local/lib/CydiaSubstrate.framework/CydiaSubstrate",
        "/usr/lib/libsubstrate.dylib",
        "/var/jb/usr/lib/libsubstrate.dylib",
        NULL,
    };
    if (gLoadAttempted) return;
    pthread_mutex_lock(&gLoadLock);
    if (!gLoadAttempted) {
        for (int i = 0; candidates[i] != NULL; i++) {
            void *handle = dlopen(candidates[i], RTLD_NOW | RTLD_LOCAL);
            if (!handle) continue;
            gSubstrateHandle = handle;
            gGetImageByName = (PFN_GetImageByName)dlsym(handle, "MSGetImageByName");
            gFindSymbol = (PFN_FindSymbol)dlsym(handle, "MSFindSymbol");
            gHookFunction = (PFN_HookFunction)dlsym(handle, "MSHookFunction");
            gHookMessageEx = (PFN_HookMessageEx)dlsym(handle, "MSHookMessageEx");
            break;
        }
        gLoadAttempted = 1;
    }
    pthread_mutex_unlock(&gLoadLock);
}

// Fallbacks keep image/symbol lookups working even if the framework is absent;
// only MSHookFunction genuinely needs the real implementation.
MSImageRef MSGetImageByName(const char *file) {
    MacWSSubstrateLoad();
    if (gGetImageByName) return gGetImageByName(file);
    if (!file) return NULL;
    void *handle = dlopen(file, RTLD_NOW | RTLD_LOCAL);
    if (!handle && file[0] != '/') {
        char frameworkPath[1024];
        snprintf(frameworkPath, sizeof(frameworkPath),
                 "/System/Library/Frameworks/%s.framework/%s", file, file);
        handle = dlopen(frameworkPath, RTLD_NOW | RTLD_LOCAL);
    }
    return (MSImageRef)handle;
}

void *MSFindSymbol(MSImageRef image, const char *name) {
    MacWSSubstrateLoad();
    if (gFindSymbol) return gFindSymbol(image, name);
    if (!image || !name) return NULL;
    return dlsym((void *)image, name);
}

void MSHookFunction(void *symbol, void *replace, void **result) {
    MacWSSubstrateLoad();
    if (gHookFunction) {
        gHookFunction(symbol, replace, result);
        return;
    }
    if (result) *result = NULL;
    fprintf(stderr,
            "#### MACWS_SUBSTRATE_SHIM MSHookFunction unavailable symbol=%p\n",
            symbol);
}

void MSHookMessageEx(Class _class, SEL sel, IMP imp, IMP *result) {
    MacWSSubstrateLoad();
    if (gHookMessageEx) {
        gHookMessageEx(_class, sel, imp, result);
        return;
    }
    if (result) *result = class_getMethodImplementation(_class, sel);
    if (_class && sel && imp) {
        Method m = class_getInstanceMethod(_class, sel);
        if (m) method_setImplementation(m, imp);
    }
}
