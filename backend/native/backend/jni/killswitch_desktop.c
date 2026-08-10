//go:build !android
#include <jni.h>
#include <stdlib.h>

#include "include/vpn_jni.h"

extern int setKillSwitch(int enabled);
extern int getKillSwitchStatus(void);
extern int setKillSwitchAllowedNetworks(struct go_string cidrs_csv);
extern int getKillSwitchAllowedNetworksEnabled(void);

JNIEXPORT jint JNICALL
Java_com_wgtunnel_backend_service_DesktopKillSwitchNative_setKillSwitch(
        JNIEnv *env, jclass clazz, jint enabled)
{
    (void)env;
    (void)clazz;
    return (jint)setKillSwitch((int)enabled);
}

JNIEXPORT jint JNICALL
Java_com_wgtunnel_backend_service_DesktopKillSwitchNative_getKillSwitchStatus(
        JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    return (jint)getKillSwitchStatus();
}

JNIEXPORT jint JNICALL
Java_com_wgtunnel_backend_service_DesktopKillSwitchNative_setKillSwitchAllowedNetworks(
        JNIEnv *env, jclass clazz, jstring cidrsCsv)
{
    const char *utf = NULL;
    struct go_string g;
    int ret;
    (void)clazz;

    g = jstring_to_go(env, cidrsCsv, &utf);
    ret = setKillSwitchAllowedNetworks(g);
    release_jstring(env, cidrsCsv, utf);
    return (jint)ret;
}

JNIEXPORT jint JNICALL
Java_com_wgtunnel_backend_service_DesktopKillSwitchNative_getKillSwitchAllowedNetworksEnabled(
        JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    return (jint)getKillSwitchAllowedNetworksEnabled();
}