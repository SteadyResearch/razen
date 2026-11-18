/* Trusted macOS-only fixture, loaded solely into an owned recovery child.
 * Never configured globally. The arming file is created only AFTER Ledger::open.
 * Both device and inode must match the one controlled SQLite database.
 */
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

static int selected(int fd) {
    const char *dev = getenv("RAZEN_SYNC_DEVICE");
    const char *ino = getenv("RAZEN_SYNC_INODE");
    const char *arm = getenv("RAZEN_SYNC_ARM");
    struct stat target, armed;
    if (!dev || !ino || !arm || lstat(arm, &armed) != 0 || !S_ISREG(armed.st_mode)
        || armed.st_uid != geteuid() || (armed.st_mode & 0777) != 0600 || armed.st_nlink != 1
        || fstat(fd, &target) != 0 || !S_ISREG(target.st_mode)) return 0;
    return (uint64_t)target.st_dev == strtoull(dev, NULL, 10)
        && (uint64_t)target.st_ino == strtoull(ino, NULL, 10);
}

static int injected(int fd, const char *operation) {
    if (!selected(fd)) return 0;
    const char *path = getenv("RAZEN_SYNC_TELEMETRY");
    if (!path) return 0;
    int out = open(path, O_WRONLY | O_APPEND | O_NOFOLLOW | O_CLOEXEC);
    struct stat telemetry;
    if (out < 0) return 0;
    const size_t length = strlen(operation);
    if (fstat(out, &telemetry) != 0 || !S_ISREG(telemetry.st_mode)
        || telemetry.st_uid != geteuid() || (telemetry.st_mode & 0777) != 0600
        || telemetry.st_nlink != 1 || telemetry.st_size < 0
        || (uint64_t)telemetry.st_size + length > 4096) { close(out); return 0; }
    ssize_t wrote = write(out, operation, length);
    close(out);
    if (wrote != (ssize_t)length) return 0;
    errno = EIO;
    return 1;
}

static int fault_fsync(int fd) {
    if (injected(fd, "fsync:EIO\n")) return -1;
    return fsync(fd);
}

/* fcntl is variadic: preserve the documented argument type for commands used by
 * libc/Rust/SQLite in this closed worker. Commands without an argument must NOT
 * read a nonexistent va_arg. This is not a general-purpose preload library. */
static int fault_fcntl(int fd, int cmd, ...) {
    if (cmd == F_FULLFSYNC) {
        if (injected(fd, "F_FULLFSYNC:EIO\n")) return -1;
        return fcntl(fd, cmd);
    }
    switch (cmd) {
        case F_GETFD: case F_GETFL: case F_GETOWN:
#ifdef F_BARRIERFSYNC
        case F_BARRIERFSYNC:
#endif
            return fcntl(fd, cmd);
        default: break;
    }
    va_list args;
    va_start(args, cmd);
    int result;
    switch (cmd) {
        case F_DUPFD: case F_SETFD: case F_SETFL: case F_SETOWN:
#ifdef F_DUPFD_CLOEXEC
        case F_DUPFD_CLOEXEC:
#endif
#ifdef F_NOCACHE
        case F_NOCACHE:
#endif
            result = fcntl(fd, cmd, va_arg(args, int)); break;
        case F_GETLK: case F_SETLK: case F_SETLKW:
            result = fcntl(fd, cmd, va_arg(args, struct flock *)); break;
#ifdef F_PREALLOCATE
        case F_PREALLOCATE:
            result = fcntl(fd, cmd, va_arg(args, fstore_t *)); break;
#endif
#ifdef F_GETPATH
        case F_GETPATH:
            result = fcntl(fd, cmd, va_arg(args, char *)); break;
#endif
        default:
            /* Never read an unknown variadic argument with a guessed type. */
            errno = EINVAL; result = -1; break;
    }
    va_end(args);
    return result;
}

#define INTERPOSE(replacement, original) \
    __attribute__((used)) static struct { const void *new_function; const void *old_function; } \
    interpose_##original __attribute__((section("__DATA,__interpose"))) = { \
        (const void *)(uintptr_t)&replacement, (const void *)(uintptr_t)&original \
    }
INTERPOSE(fault_fsync, fsync);
INTERPOSE(fault_fcntl, fcntl);
