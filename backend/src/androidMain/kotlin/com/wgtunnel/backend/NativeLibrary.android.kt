package com.wgtunnel.backend

actual fun loadBackendNativeLibrary() {
    System.loadLibrary("am-go")
}
