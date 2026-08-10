package com.wgtunnel.backend.model.dns

import com.wgtunnel.backend.exception.BackendException
import com.wgtunnel.backend.util.UrlParse
import kotlinx.serialization.Serializable

@Serializable
data class TunnelDnsConfig(
    val defaultTransport: String,
    val localSuffixes: List<String> = emptyList(),
    val upstream: List<String> = emptyList(),
    val serverName: String? = null,
    val fakeDns: String = FAKE_DNS_V4,
    val fakeDnsV6: String = FAKE_DNS_V6,
    val foreignDnsPolicy: ForeignDnsPolicy = ForeignDnsPolicy.REDIRECT,
) {
    fun needsResolve(): Boolean {
        if (defaultTransport == "local") return false
        if (upstream.isEmpty()) return true
        return upstream.any { !isPreResolvedEntry(it) }
    }

    fun resolveHost(): String? {
        return upstream.firstOrNull()?.let { hostFromEntry(it) }
    }

    fun withResolvedAddresses(ips: DnsBootstrapResult): TunnelDnsConfig {
        val host =
            resolveHost() ?: throw BackendException.ConfigMissingDNS("Host missing from upstream")
        val port = portFromUpstreamOrDefault()
        val path = dohPathFromUpstream()
        val out = ArrayList<String>()

        for (ip in ips.ipv4) {
            out +=
                when (defaultTransport) {
                    "doh" -> "https://$ip$path"
                    else -> "$ip:$port"
                }
        }
        for (raw in ips.ipv6) {
            val ip = raw.removePrefix("[").removeSuffix("]")
            out +=
                when (defaultTransport) {
                    "doh" -> "https://[$ip]$path"
                    else -> "[$ip]:$port"
                }
        }

        return copy(upstream = out, serverName = serverName?.takeIf { it.isNotBlank() } ?: host)
    }

    private fun isPreResolvedEntry(entry: String): Boolean {
        val e = entry.trim()
        if (e.isEmpty()) return false
        return when (defaultTransport) {
            "doh" -> {
                if (!e.startsWith("https://")) return false
                val h = UrlParse.host(e) ?: return false
                isLiteralIp(h)
            }
            "dot",
            "plain" -> {
                val host = splitHostPort(e)?.first ?: return false
                isLiteralIp(host)
            }
            else -> true
        }
    }

    private fun hostFromEntry(entry: String): String? {
        val e = entry.trim()
        if (e.isEmpty()) return null
        if (e.startsWith("http://") || e.startsWith("https://")) {
            return UrlParse.host(e)
        }
        return splitHostPort(e)?.first ?: e
    }

    private fun portFromUpstreamOrDefault(): Int {
        val first = upstream.firstOrNull()?.trim().orEmpty()
        when (defaultTransport) {
            "doh" -> {
                val p = UrlParse.port(first)
                return if (p > 0) p else 443
            }
            "dot",
            "plain" -> {
                val p = splitHostPort(first)?.second
                if (p != null && p > 0) return p
                return if (defaultTransport == "dot") 853 else 53
            }
            else -> return 53
        }
    }

    private fun dohPathFromUpstream(): String {
        if (defaultTransport != "doh") return "/dns-query"
        val first = upstream.firstOrNull()?.trim().orEmpty()
        if (first.isEmpty()) return "/dns-query"
        return UrlParse.pathAndQuery(first, "/dns-query")
    }

    companion object {
        const val FAKE_DNS_V4 = "198.18.0.2"
        const val FAKE_DNS_V6 = "2001:db8::53"

        private fun isLiteralIp(host: String): Boolean {
            val h = host.removePrefix("[").removeSuffix("]")
            return isIpv4(h) || h.contains(':')
        }

        private fun isIpv4(s: String): Boolean {
            val p = s.split('.')
            if (p.size != 4) return false
            return p.all { it.toIntOrNull()?.let { n -> n in 0..255 } == true }
        }

        fun splitHostPort(value: String): Pair<String, Int?>? {
            val v = value.trim()
            if (v.startsWith("[")) {
                val end = v.indexOf(']')
                if (end <= 1) return null
                val host = v.substring(1, end)
                val rest = v.substring(end + 1)
                val port = if (rest.startsWith(":")) rest.drop(1).toIntOrNull() else null
                return host to port
            }
            val idx = v.lastIndexOf(':')
            if (idx > 0 && v.indexOf(':') == idx) {
                return v.substring(0, idx) to v.substring(idx + 1).toIntOrNull()
            }
            return v to null
        }
    }
}