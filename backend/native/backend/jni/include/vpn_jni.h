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
struct go_string cstr_to_go(const char *s);

/* Go exports */
extern void StartResolveBootstrap(int64_t id, struct go_string host,
                                  struct go_string protocol,
                                  struct go_string resolved_upstream,
                                  struct go_string original_upstream, int bypass);
extern void setUnderlayNetworkHandle(int64_t handle);

void NotifyDnsResult(int64_t id, struct go_string result);
char *JniLookupOnUnderlayNetwork(struct go_string host,
                                 struct go_string networkFamily);
int bypass_socket(int fd);
void notifyStatus(int32_t handle, int32_t code);

JavaVM *vpn_jni_java_vm(void);
jclass vpn_jni_dns_resolver_class(void);
int vpn_jni_shared_onload(JNIEnv *env);
void vpn_jni_android_onload(JNIEnv *env);
void vpn_jni_android_onunload(JNIEnv *env);
void vpn_jni_desktop_onload(JNIEnv *env);
void vpn_jni_dns_onload(JNIEnv *env);