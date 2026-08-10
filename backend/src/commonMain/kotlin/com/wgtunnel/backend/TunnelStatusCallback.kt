package com.wgtunnel.backend

interface TunnelStatusCallback {
    fun onStatus(handle: Int, code: Int)
}
