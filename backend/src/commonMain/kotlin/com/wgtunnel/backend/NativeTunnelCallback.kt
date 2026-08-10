package com.wgtunnel.backend

interface NativeTunnelCallback {
    fun handleNativeStatusChange(handle: Int, code: Int)
}