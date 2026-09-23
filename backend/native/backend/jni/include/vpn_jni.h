#pragma once
#include <jni.h>
#include <stdint.h>

// n must match the width of cgo's GoInt, which cgo sizes off the pointer width of the target
// , not a fixed 64 bits. intptr_t tracks that same rule on every platform:
// 64-bit on LP64 (Linux/macOS amd64/arm64) and LLP64 (64-bit Windows, where `long` is 32-bit -
// the original reason this wasn't just `long`), and 32-bit on ILP32 targets such as
// armeabi-v7a (32-bit Android). A fixed int64_t here silently corrupts every go_string argument
// on 32-bit ARM, since cgo's real GoString.n field is only 4 bytes there.
struct go_string {
    const char *str;
    intptr_t n;
};

/* Helpers */
struct go_string jstring_to_go(JNIEnv *env, jstring s, const char **pinned);
void release_jstring(JNIEnv *env, jstring s, const char *pinned);

extern void setUnderlayNetworkHandle(int64_t handle);
extern void setVpnNetworkHandle(int64_t handle);

char *JniLookupOnUnderlayNetwork(struct go_string host,
                                 struct go_string networkFamily);
int bypass_socket(int fd);
void notifyStatus(int32_t handle, int32_t code);

JavaVM *vpn_jni_java_vm(void);
jclass vpn_jni_dns_resolver_class(void);
int vpn_jni_shared_onload(JNIEnv *env);
void vpn_jni_android_onload(JNIEnv *env);
void vpn_jni_desktop_onload(JNIEnv *env);
void network_monitor_jni_onload(JNIEnv *env);