package com.wgtunnel.backend.util

import com.wgtunnel.backend.exception.BackendException
import kotlinx.coroutines.delay
import java.io.IOException
import java.net.DatagramSocket
import java.net.ServerSocket
import java.net.SocketException
import kotlin.time.Duration.Companion.milliseconds

object PortUtils {

    fun isTcpPortAvailable(port: Int): Boolean {
        if (port !in 1..65_535) return false
        return try {
            ServerSocket(port).use { true }
        } catch (_: IOException) {
            false
        }
    }

    @Throws(IOException::class)
    fun getAvailableTcpPort(tag: Int = 0): Int =
        withSocketTag(tag) {
            ServerSocket(0).use { it.localPort }
        }

    @Throws(BackendException::class)
    suspend fun waitForUdpPortAvailable(port: Int, timeoutMs: Long = 3000L) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (isUdpPortAvailable(port)) return
            delay(50.milliseconds)
        }
        throw BackendException.ListenPortUnavailable(
            "UDP ListenPort $port is still in use after waiting $timeoutMs ms",
            port,
        )
    }

    private fun isUdpPortAvailable(port: Int): Boolean {
        if (port !in 1..65_535) return false
        return try {
            DatagramSocket(port).use { true }
        } catch (_: SocketException) {
            false
        }
    }
}
