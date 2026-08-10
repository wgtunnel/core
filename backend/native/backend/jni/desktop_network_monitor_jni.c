//go:build !android
#include <jni.h>
#include <stdlib.h>
#include <string.h>

#include "include/vpn_jni.h"

static jclass g_nm_class;
static jmethodID g_on_network_info;

extern int startNetworkMonitor(void);
extern void stopNetworkMonitor(void);
extern char *getNetworkInfoJson(void);

void
network_monitor_jni_onload(JNIEnv *env)
{
	jclass local = (*env)->FindClass(
		env, "com/wgtunnel/backend/network/NetworkMonitorNative");
	if (local == NULL) {
		if ((*env)->ExceptionCheck(env))
			(*env)->ExceptionClear(env);
		return;
	}
	g_nm_class = (*env)->NewGlobalRef(env, local);
	(*env)->DeleteLocalRef(env, local);
	g_on_network_info = (*env)->GetStaticMethodID(
		env, g_nm_class, "onNetworkInfo", "(Ljava/lang/String;)V");
	if (g_on_network_info == NULL && (*env)->ExceptionCheck(env))
		(*env)->ExceptionClear(env);
}

void
NotifyNetworkInfo(const char *json)
{
	JavaVM *vm = vpn_jni_java_vm();
	JNIEnv *env = NULL;
	int attached = 0;
	jstring jjson;

	if (vm == NULL || g_nm_class == NULL || g_on_network_info == NULL)
		return;

	if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) == JNI_EDETACHED) {
		if ((*vm)->AttachCurrentThread(vm, (void **)&env, NULL) != 0)
			return;
		attached = 1;
	}

	jjson = (*env)->NewStringUTF(env, json != NULL ? json : "{}");
	(*env)->CallStaticVoidMethod(env, g_nm_class, g_on_network_info, jjson);
	if ((*env)->ExceptionCheck(env))
		(*env)->ExceptionClear(env);
	if (jjson != NULL)
		(*env)->DeleteLocalRef(env, jjson);

	if (attached)
		(*vm)->DetachCurrentThread(vm);
}

JNIEXPORT jint JNICALL
Java_com_wgtunnel_backend_network_NetworkMonitorNative_start(
	JNIEnv *env, jclass c)
{
	(void)env;
	(void)c;
	return (jint)startNetworkMonitor();
}

JNIEXPORT void JNICALL
Java_com_wgtunnel_backend_network_NetworkMonitorNative_stop(
	JNIEnv *env, jclass c)
{
	(void)env;
	(void)c;
	stopNetworkMonitor();
}

JNIEXPORT jstring JNICALL
Java_com_wgtunnel_backend_network_NetworkMonitorNative_getInfoJson(
	JNIEnv *env, jclass c)
{
	char *json;
	jstring ret;
	(void)c;

	json = getNetworkInfoJson();
	if (json == NULL)
		return (*env)->NewStringUTF(env, "{\"type\":\"disconnected\"}");
	ret = (*env)->NewStringUTF(env, json);
	free(json);
	return ret;
}