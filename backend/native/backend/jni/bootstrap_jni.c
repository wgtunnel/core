#include <jni.h>
#include <stdlib.h>
#include <string.h>

#include "include/vpn_jni.h"

extern char *ResolveBootstrapSync(
        struct go_string host,
        struct go_string protocol,
        struct go_string resolvedUpstream,
        struct go_string originalUpstream,
        int bypass);

JNIEXPORT jstring JNICALL
Java_com_wgtunnel_backend_dns_NativeDnsResolver_resolveBootstrapSync(
        JNIEnv *env, jclass c,
        jstring host, jstring protocol,
        jstring resolvedUpstream, jstring originalUpstream, jint bypass)
{
    const char *h = NULL, *p = NULL, *ru = NULL, *ou = NULL;
    struct go_string gh, gp, gru, gou;
    char *cresult = NULL;
    jstring jresult = NULL;

    (void)c;

    gh  = jstring_to_go(env, host, &h);
    gp  = jstring_to_go(env, protocol, &p);
    gru = jstring_to_go(env, resolvedUpstream, &ru);
    gou = jstring_to_go(env, originalUpstream, &ou);

    cresult = ResolveBootstrapSync(gh, gp, gru, gou, (int)bypass);

    release_jstring(env, host, h);
    release_jstring(env, protocol, p);
    release_jstring(env, resolvedUpstream, ru);
    release_jstring(env, originalUpstream, ou);

    if (cresult == NULL) {
        return NULL;
    }

    jresult = (*env)->NewStringUTF(env, cresult);
    free(cresult);          /* Go allocated with C.CString */
    return jresult;
}