#pragma once
#include <jni.h>
#include <stdint.h>

struct go_string {
    const char *str;
    long n;
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