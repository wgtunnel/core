package com.wgtunnel.backend

internal interface SocketProtector {
    fun bypass(fd: Int): Int
}