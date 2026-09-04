//go:build !android
#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include "include/vpn_jni.h"

extern int createInterface(struct go_string ifname, struct go_string config);
extern void destroyInterface(struct go_string ifname);

void
vpn_jni_desktop_onload(JNIEnv *env)
{
    network_monitor_jni_onload(env);
}

JNIEXPORT jint JNICALL
Java_com_wgtunnel_backend_DesktopVpnBackend_createInterface(
        JNIEnv *env, jclass c, jstring ifname, jstring settings)
{
    const char *if_p = NULL, *set_p = NULL;
    struct go_string if_g, set_g;
    int ret;
    (void)c;

    if_g = jstring_to_go(env, ifname, &if_p);
    set_g = jstring_to_go(env, settings, &set_p);
    ret = createInterface(if_g, set_g);
    release_jstring(env, ifname, if_p);
    release_jstring(env, settings, set_p);
    return (jint)ret;
}

JNIEXPORT void JNICALL
Java_com_wgtunnel_backend_DesktopVpnBackend_destroyInterface(
        JNIEnv *env, jclass c, jstring ifname)
{
    const char *if_p = NULL;
    struct go_string if_g;
    (void)c;

    if_g = jstring_to_go(env, ifname, &if_p);
    destroyInterface(if_g);
    release_jstring(env, ifname, if_p);
}