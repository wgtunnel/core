#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include "include/vpn_jni.h"

extern int32_t startProxy(int32_t handle, struct go_string ifName,
                          struct go_string config, struct go_string uapiPath,
                          int32_t bypass, struct go_string dnsConfig);
extern int32_t updateProxyTunnelPeers(int32_t handle, struct go_string config);
extern void turnProxyTunnelOff(int32_t handle);
extern char *getProxyConfig(int32_t handle);

JNIEXPORT jint JNICALL
Java_com_wgtunnel_backend_ProxyBackend_startProxy(
        JNIEnv *env, jclass c,
        jint handle, jstring ifName, jstring config, jstring uapiPath,
        jint bypass, jstring dnsConfigJson)
{
    const char *if_p = NULL, *cfg_p = NULL, *uapi_p = NULL, *dns_p = NULL;
    struct go_string if_g, cfg_g, uapi_g, dns_g;
    int32_t ret;
    (void)c;

    if_g = jstring_to_go(env, ifName, &if_p);
    cfg_g = jstring_to_go(env, config, &cfg_p);
    uapi_g = jstring_to_go(env, uapiPath, &uapi_p);
    dns_g = jstring_to_go(env, dnsConfigJson, &dns_p);

    ret = startProxy((int32_t)handle, if_g, cfg_g, uapi_g, (int32_t)bypass, dns_g);

    release_jstring(env, ifName, if_p);
    release_jstring(env, config, cfg_p);
    release_jstring(env, uapiPath, uapi_p);
    release_jstring(env, dnsConfigJson, dns_p);
    return (jint)ret;
}

JNIEXPORT jint JNICALL
Java_com_wgtunnel_backend_ProxyBackend_updateProxyTunnelPeers(
        JNIEnv *env, jclass c, jint handle, jstring settings)
{
    const char *s = NULL;
    struct go_string sg;
    int32_t ret;
    (void)c;

    sg = jstring_to_go(env, settings, &s);
    ret = updateProxyTunnelPeers((int32_t)handle, sg);
    release_jstring(env, settings, s);
    return (jint)ret;
}

JNIEXPORT void JNICALL
Java_com_wgtunnel_backend_ProxyBackend_turnProxyTunnelOff(
        JNIEnv *env, jclass c, jint handle)
{
    (void)env;
    (void)c;
    turnProxyTunnelOff((int32_t)handle);
}

JNIEXPORT jstring JNICALL
Java_com_wgtunnel_backend_ProxyBackend_getProxyConfig(
        JNIEnv *env, jclass c, jint handle)
{
    char *cfg;
    jstring ret;
    (void)c;

    cfg = getProxyConfig((int32_t)handle);
    if (cfg == NULL) {
        return NULL;
    }
    ret = (*env)->NewStringUTF(env, cfg);
    free(cfg);
    return ret;
}