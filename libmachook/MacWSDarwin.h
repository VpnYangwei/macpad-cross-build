// The macOS SDK ships Darwin as a clang module only (there is no
// <Darwin/Darwin.h> header), so a -fno-modules cross-build cannot import it by
// path.  Pull in the same libc surface explicitly.
#pragma once
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/fat.h>
#include <mach-o/arch.h>
#include <mach-o/getsect.h>
#include <malloc/malloc.h>

// libroot's JBROOT_PATH is unavailable outside an on-device rootless build.
#ifndef JBROOT_PATH
#define JBROOT_PATH(path) ("/var/jb" path)
#endif
