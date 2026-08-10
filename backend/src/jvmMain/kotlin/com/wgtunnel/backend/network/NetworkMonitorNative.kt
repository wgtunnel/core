package com.wgtunnel.backend.network

internal object NetworkMonitorNative {
    @JvmStatic
    external fun start(): Int

    @JvmStatic
    external fun stop()

    @JvmStatic
    external fun getInfoJson(): String

    /** Called from JNI */
    @JvmStatic
    fun onNetworkInfo(json: String) {
        NetworkMonitorBridge.onNativeInfo(json)
    }
}