package com.wgtunnel.backend

actual fun loadBackendNativeLibrary(): Boolean =
    try {
        System.loadLibrary("am-go")
        true
    } catch (_: UnsatisfiedLinkError) {
        false
    }
