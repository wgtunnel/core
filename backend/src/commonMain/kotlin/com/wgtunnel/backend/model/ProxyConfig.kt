package com.wgtunnel.backend.model

import com.wgtunnel.backend.model.dns.TunnelDnsConfig
import com.wgtunnel.backend.util.DnsHostUtils

data class ProxyConfig(val socks5: Socks5? = null, val http: Http? = null) {

    fun toQuickString(): String = buildString {
        socks5?.let {
            appendLine("[Socks5]")
            appendLine("BindAddress = ${it.host.asBindAddress(it.port)}")
            it.username?.let { u -> appendLine("Username = $u") }
            it.password?.let { p -> appendLine("Password = $p") }
            if (it.allowSocks4) appendLine("AllowSocks4 = true")
        }

        if (socks5 != null && http != null) {
            appendLine()
        }

        http?.let {
            appendLine("[http]")
            appendLine("BindAddress = ${it.host.asBindAddress(it.port)}")
            it.username?.let { u -> appendLine("Username = $u") }
            it.password?.let { p -> appendLine("Password = $p") }
        }
    }

    data class Socks5(
        val host: String = "127.0.0.1",
        val port: Int,
        val username: String? = null,
        val password: String? = null,
        val allowSocks4: Boolean = false,
    )

    data class Http(
        val host: String = "127.0.0.1",
        val port: Int,
        val username: String? = null,
        val password: String? = null,
    )
}

// Brackets a bare IPv6
private fun String.asBindAddress(port: Int): String =
    if (contains(":") && !startsWith("[")) "[$this]:$port" else "$this:$port"

/** Parses a proxy bind address into (host, port) with IPv6 hosts bracketed */
fun String.parseProxyBindAddress(): Pair<String, Int>? {
    val (host, port) = TunnelDnsConfig.splitHostPort(this) ?: return null
    return host to (port ?: return null)
}

// only allow valid proxy bind addresses optionally with a %<zone> scope id for link-local addresses
// Port 1024-65535 since lower ports are privileged.
fun String.isValidProxyBindAddress(minPort: Int = 1024): Boolean {
    val (host, port) = parseProxyBindAddress() ?: return false
    if (port !in minPort..65535) return false
    return DnsHostUtils.isIpAddress(host)
}
