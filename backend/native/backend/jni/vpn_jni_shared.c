#include <jni.h>
#include <stdlib.h>
#include <string.h>

#include "include/vpn_jni.h"

extern void stopVpn(int handle);
extern char *getVpnConfig(int handle);
extern char *version(void);
extern int startVpn(struct go_string ifname, int tun_fd, struct go_string config,
                  struct go_string dnsconfig, struct go_string uapipath);
extern int updateVpnTunnelPeers(int handle, struct go_string config);

static JavaVM *g_vm;
static jobject g_status_cb;
static jmethodID g_status_mid;

static JavaVM *g_vm;
static jclass g_dnsResolverClass;   // needed for underlay lookup

static JNIEnv *get_env(int *attached);
static void release_env(int attached);

struct go_string
jstring_to_go(JNIEnv *env, jstring s, const char **pinned)
{
    if (s == NULL) {
        *pinned = NULL;
        return (struct go_string){ .str = "", .n = 0 };
    }
    *pinned = (*env)->GetStringUTFChars(env, s, NULL);
    if (*pinned == NULL) {
        return (struct go_string){ .str = "", .n = 0 };
    }
    return (struct go_string){
            .str = *pinned,
            .n = (long)(*env)->GetStringUTFLength(env, s),
    };
}

void
release_jstring(JNIEnv *env, jstring s, const char *pinned)
{
    if (s != NULL && pinned != NULL) {
        (*env)->ReleaseStringUTFChars(env, s, pinned);
    }
}

struct go_string
cstr_to_go(const char *s)
{
    if (s == NULL) {
        return (struct go_string){ .str = "", .n = 0 };
    }
    return (struct go_string){ .str = s, .n = (long)strlen(s) };
}

JavaVM *
vpn_jni_java_vm(void)
{
    return g_vm;
}

static JNIEnv *
get_env(int *attached)
{
    JNIEnv *env = NULL;
    jint rc;

    *attached = 0;
    if (g_vm == NULL) {
        return NULL;
    }

    rc = (*g_vm)->GetEnv(g_vm, (void **)&env, JNI_VERSION_1_6);
    if (rc == JNI_EDETACHED) {
        if ((*g_vm)->AttachCurrentThread(g_vm, (void **) &env, NULL) != 0) {
            return NULL;
        }
        *attached = 1;
    } else if (rc != JNI_OK) {
        return NULL;
    }
    return env;
}

jclass
vpn_jni_dns_resolver_class(void)
{
    return g_dnsResolverClass;
}

static void
setup_dns_resolver_class(JNIEnv *env)
{
    jclass local = (*env)->FindClass(env, "com/wgtunnel/backend/dns/NativeDnsResolver");
    if (local == NULL) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        return;
    }
    if (g_dnsResolverClass != NULL) {
        (*env)->DeleteGlobalRef(env, g_dnsResolverClass);
    }
    g_dnsResolverClass = (*env)->NewGlobalRef(env, local);
    (*env)->DeleteLocalRef(env, local);
}

int
vpn_jni_shared_onload(JNIEnv *env)
{
    if ((*env)->GetJavaVM(env, &g_vm) != 0) {
        return -1;
    }
    setup_dns_resolver_class(env);   // needed for JniLookupOnUnderlayNetwork
    return 0;
}

static void
release_env(int attached)
{
    if (attached && g_vm != NULL) {
        (*g_vm)->DetachCurrentThread(g_vm);
    }
}

void
notifyStatus(int32_t handle, int32_t code)
{
    int attached = 0;
    JNIEnv *env;

    if (g_status_cb == NULL || g_status_mid == NULL) {
        return;
    }
    env = get_env(&attached);
    if (env == NULL) {
        return;
    }
    (*env)->CallVoidMethod(env, g_status_cb, g_status_mid, (jint)handle, (jint)code);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
    }
    release_env(attached);
}

JNIEXPORT void JNICALL
Java_com_wgtunnel_backend_TunnelBackend_setStatusCallback(
        JNIEnv *env, jclass c, jobject cb)
{
    jclass cls;
    (void)c;

    if (g_status_cb != NULL) {
        (*env)->DeleteGlobalRef(env, g_status_cb);
        g_status_cb = NULL;
        g_status_mid = NULL;
    }
    if (cb == NULL) {
        return;
    }
    g_status_cb = (*env)->NewGlobalRef(env, cb);
    if (g_status_cb == NULL) {
        return;
    }
    cls = (*env)->GetObjectClass(env, cb);
    g_status_mid = (*env)->GetMethodID(env, cls, "onStatus", "(II)V");
    (*env)->DeleteLocalRef(env, cls);
    if (g_status_mid == NULL) {
        (*env)->DeleteGlobalRef(env, g_status_cb);
        g_status_cb = NULL;
    }
}

JNIEXPORT jint JNICALL
Java_com_wgtunnel_backend_VpnBackend_turnOn(
        JNIEnv *env, jclass c,
        jstring ifname, jint tun_fd, jstring settings,
        jstring dnsConfigJson, jstring uapiPath)
{
    const char *if_p = NULL, *set_p = NULL, *dns_p = NULL, *uapi_p = NULL;
    struct go_string if_g, set_g, dns_g, uapi_g;
    int ret;
    (void)c;

    if_g = jstring_to_go(env, ifname, &if_p);
    set_g = jstring_to_go(env, settings, &set_p);
    dns_g = jstring_to_go(env, dnsConfigJson, &dns_p);
    uapi_g = jstring_to_go(env, uapiPath, &uapi_p);

    ret = startVpn(if_g, (int)tun_fd, set_g, dns_g, uapi_g);

    release_jstring(env, ifname, if_p);
    release_jstring(env, settings, set_p);
    release_jstring(env, dnsConfigJson, dns_p);
    release_jstring(env, uapiPath, uapi_p);
    return (jint)ret;
}

JNIEXPORT void JNICALL
Java_com_wgtunnel_backend_VpnBackend_turnOff(JNIEnv *env, jclass c, jint handle)
{
    (void)env;
    (void)c;
    stopVpn((int)handle);
}

JNIEXPORT jstring JNICALL
Java_com_wgtunnel_backend_VpnBackend_getConfig(JNIEnv *env, jclass c, jint handle)
{
    char *config;
    jstring ret;
    (void)c;

    config = getVpnConfig((int)handle);
    if (config == NULL) {
        return NULL;
    }
    ret = (*env)->NewStringUTF(env, config);
    free(config);
    return ret;
}

JNIEXPORT jstring JNICALL
Java_com_wgtunnel_backend_VpnBackend_version(JNIEnv *env, jclass c)
{
    char *v;
    jstring ret;
    (void)c;

    v = version();
    if (v == NULL) {
        return NULL;
    }
    ret = (*env)->NewStringUTF(env, v);
    free(v);
    return ret;
}

JNIEXPORT jint JNICALL
Java_com_wgtunnel_backend_VpnBackend_updateTunnelPeers(
        JNIEnv *env, jclass c, jint handle, jstring settings)
{
    const char *set_p = NULL;
    struct go_string set_g;
    int ret;
    (void)c;

    set_g = jstring_to_go(env, settings, &set_p);
    ret = updateVpnTunnelPeers((int)handle, set_g);
    release_jstring(env, settings, set_p);
    return (jint)ret;
}

JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void *reserved)
{
    JNIEnv *env = NULL;
    (void)reserved;

    g_vm = vm;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    if (vpn_jni_shared_onload(env) != 0) {
        return JNI_ERR;
    }
#if defined(__ANDROID__)
    vpn_jni_android_onload(env);
#else
    vpn_jni_desktop_onload(env);
#endif
    return JNI_VERSION_1_6;
}