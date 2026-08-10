//go:build android
#include <jni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "include/vpn_jni.h"

static jobject g_protector;
static jmethodID g_bypass_mid;
static jmethodID g_lookupOnUnderlayNetworkMethod;

static JNIEnv *
android_get_env(int *attached)
{
    JavaVM *vm = vpn_jni_java_vm();
    JNIEnv *env = NULL;
    jint rc;

    *attached = 0;
    if (vm == NULL) {
        return NULL;
    }
    rc = (*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6);
    if (rc == JNI_EDETACHED) {
        if ((*vm)->AttachCurrentThread(vm, &env, NULL) != 0) {
            return NULL;
        }
        *attached = 1;
    } else if (rc != JNI_OK) {
        return NULL;
    }
    return env;
}

static void
android_release_env(int attached)
{
    JavaVM *vm = vpn_jni_java_vm();
    if (attached && vm != NULL) {
        (*vm)->DetachCurrentThread(vm);
    }
}

void
vpn_jni_android_onload(JNIEnv *env)
{
    jclass cls = vpn_jni_dns_resolver_class();

    g_lookupOnUnderlayNetworkMethod = NULL;
    if (cls == NULL) {
        return;
    }
    g_lookupOnUnderlayNetworkMethod = (*env)->GetStaticMethodID(
            env, cls, "lookupOnUnderlayNetwork",
            "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
    if (g_lookupOnUnderlayNetworkMethod == NULL && (*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
    }
}

void
vpn_jni_android_onunload(JNIEnv *env)
{
    if (g_protector != NULL) {
        (*env)->DeleteGlobalRef(env, g_protector);
        g_protector = NULL;
        g_bypass_mid = NULL;
    }
    g_lookupOnUnderlayNetworkMethod = NULL;
}

char *
JniLookupOnUnderlayNetwork(struct go_string host, struct go_string networkFamily)
{
    int attached = 0;
    JNIEnv *env;
    jclass cls;
    jstring jhost, jfam, jresult;
    char *out = NULL;
    char *host_tmp = NULL;
    char *fam_tmp = NULL;
    const char *host_s = "";
    const char *fam_s = "";

    cls = vpn_jni_dns_resolver_class();
    env = android_get_env(&attached);
    if (env == NULL || cls == NULL || g_lookupOnUnderlayNetworkMethod == NULL) {
        return NULL;
    }

    if (host.str != NULL && host.n > 0) {
        host_tmp = malloc((size_t)host.n + 1);
        if (host_tmp) {
            memcpy(host_tmp, host.str, (size_t)host.n);
            host_tmp[host.n] = '\0';
            host_s = host_tmp;
        }
    }
    if (networkFamily.str != NULL && networkFamily.n > 0) {
        fam_tmp = malloc((size_t)networkFamily.n + 1);
        if (fam_tmp) {
            memcpy(fam_tmp, networkFamily.str, (size_t)networkFamily.n);
            fam_tmp[networkFamily.n] = '\0';
            fam_s = fam_tmp;
        }
    }

    jhost = (*env)->NewStringUTF(env, host_s);
    jfam = (*env)->NewStringUTF(env, fam_s);
    jresult = (jstring)(*env)->CallStaticObjectMethod(
            env, cls, g_lookupOnUnderlayNetworkMethod, jhost, jfam);

    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        jresult = NULL;
    }
    if (jresult != NULL) {
        const char *utf = (*env)->GetStringUTFChars(env, jresult, NULL);
        if (utf != NULL) {
            out = strdup(utf);
            (*env)->ReleaseStringUTFChars(env, jresult, utf);
        }
        (*env)->DeleteLocalRef(env, jresult);
    }
    if (jhost != NULL) {
        (*env)->DeleteLocalRef(env, jhost);
    }
    if (jfam != NULL) {
        (*env)->DeleteLocalRef(env, jfam);
    }

    free(host_tmp);
    free(fam_tmp);
    android_release_env(attached);
    return out;
}

int
bypass_socket(int fd)
{
    int attached = 0;
    JNIEnv *env;
    jint ok;

    if (g_protector == NULL || g_bypass_mid == NULL) {
        return 0;
    }
    env = android_get_env(&attached);
    if (env == NULL) {
        return 0;
    }
    ok = (*env)->CallIntMethod(env, g_protector, g_bypass_mid, (jint)fd);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        ok = 0;
    }
    android_release_env(attached);
    return ok ? 1 : 0;
}

JNIEXPORT void JNICALL
Java_com_wgtunnel_backend_BypassSocket_setSocketProtector(
        JNIEnv *env, jclass c, jobject protector)
{
    jclass cls;
    (void)c;

    if (g_protector != NULL) {
        (*env)->DeleteGlobalRef(env, g_protector);
        g_protector = NULL;
        g_bypass_mid = NULL;
    }
    if (protector == NULL) {
        return;
    }
    g_protector = (*env)->NewGlobalRef(env, protector);
    if (g_protector == NULL) {
        return;
    }
    cls = (*env)->GetObjectClass(env, protector);
    g_bypass_mid = (*env)->GetMethodID(env, cls, "bypass", "(I)I");
    (*env)->DeleteLocalRef(env, cls);
    if (g_bypass_mid == NULL) {
        (*env)->DeleteGlobalRef(env, g_protector);
        g_protector = NULL;
    }
}

JNIEXPORT void JNICALL
Java_com_wgtunnel_backend_dns_UnderlayDnsBridge_setUnderlayNetworkHandleNative(
        JNIEnv *env, jclass c, jlong handle)
{
    (void)env;
    (void)c;
    setUnderlayNetworkHandle((int64_t)handle);
}