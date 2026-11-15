// Minimal CydiaSubstrate surface for the macOS cross-build.
//
// The macOS SDK has no Substrate headers; the device runtime supplies these
// symbols through CydiaSubstrate.framework (ElleKit in this chroot).
#ifndef MACWS_CYDIASUBSTRATE_H
#define MACWS_CYDIASUBSTRATE_H

#include <stddef.h>
#include <objc/objc.h>
#include <objc/runtime.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void *MSImageRef;

MSImageRef MSGetImageByName(const char *file);
void *MSFindSymbol(MSImageRef image, const char *name);

void MSHookFunction(void *symbol, void *replace, void **result);
void MSHookMessageEx(Class _class, SEL sel, IMP imp, IMP *result);

#ifdef __cplusplus
}
#endif

#endif /* MACWS_CYDIASUBSTRATE_H */
