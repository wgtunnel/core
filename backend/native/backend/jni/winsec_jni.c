//go:build !android
#include <jni.h>
#include <stdlib.h>

#include "include/vpn_jni.h"

extern char *FileOwnerSid(struct go_string path);

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
