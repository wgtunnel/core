//go:build !android
#include <jni.h>
#include <stdlib.h>

#include "include/vpn_jni.h"

extern char *FileOwnerSid(struct go_string path);
extern char *ProtectSecret(struct go_string b64);
extern char *UnprotectSecret(struct go_string b64);
extern int RunAsAdminWait(struct go_string path, struct go_string args);

static jstring transform(JNIEnv *env, jstring in, char *(*fn)(struct go_string))
{
    const char *utf = NULL;
    struct go_string g;
    char *res;
    jstring out;

    g = jstring_to_go(env, in, &utf);
    res = fn(g);
    release_jstring(env, in, utf);
    if (res == NULL) {
        return NULL;
    }
    out = (*env)->NewStringUTF(env, res);
    free(res);
    return out;
}

JNIEXPORT jstring JNICALL
Java_com_wgtunnel_backend_system_SystemSecretNative_protect(
        JNIEnv *env, jclass clazz, jstring b64)
{
    (void)clazz;
    return transform(env, b64, ProtectSecret);
}

JNIEXPORT jstring JNICALL
Java_com_wgtunnel_backend_system_SystemSecretNative_unprotect(
        JNIEnv *env, jclass clazz, jstring b64)
{
    (void)clazz;
    return transform(env, b64, UnprotectSecret);
}

JNIEXPORT jstring JNICALL
Java_com_wgtunnel_backend_system_FileOwnerNative_ownerSid(
        JNIEnv *env, jclass clazz, jstring path)
{
    const char *utf = NULL;
    struct go_string g;
    char *sid;
    jstring out;
    (void)clazz;

    g = jstring_to_go(env, path, &utf);
    sid = FileOwnerSid(g);
    release_jstring(env, path, utf);
    if (sid == NULL) {
        return NULL;
    }
    out = (*env)->NewStringUTF(env, sid);
    free(sid);
    return out;
}

JNIEXPORT jint JNICALL
Java_com_wgtunnel_backend_system_ElevationNative_runAsAdmin(
        JNIEnv *env, jclass clazz, jstring path, jstring args)
{
    const char *path_utf = NULL;
    const char *args_utf = NULL;
    struct go_string gp, ga;
    int ret;
    (void)clazz;

    gp = jstring_to_go(env, path, &path_utf);
    ga = jstring_to_go(env, args, &args_utf);
    ret = RunAsAdminWait(gp, ga);
    release_jstring(env, path, path_utf);
    release_jstring(env, args, args_utf);
    return (jint)ret;
}
