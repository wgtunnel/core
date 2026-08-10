package com.wgtunnel.backend.util

import inet.ipaddr.IPAddressString
import inet.ipaddr.ipv6.IPv6Address
import java.net.URI

object DnsHostUtils {

    /** Extracts the host portion from a DoH/DoT/Plain upstream string. */
    fun extractHost(upstream: String): String {
        val trimmed = upstream.trim()

        // DoH full url
        if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
            return try {
                URI(trimmed).host ?: trimmed
            } catch (_: Exception) {
                trimmed
            }
        }

        val hostPart = trimmed.substringBeforeLast(":")
        return hostPart.removeSurrounding("[", "]")
    }

    /** Replaces the hostname in the upstream string with the given IP address. */
    fun replaceHostWithIP(upstream: String, newIp: String): String {
        val trimmed = upstream.trim()

        val cleanedIp = newIp.trim().removeSurrounding("[", "]")
        val isIpv6 = isIpAddress(cleanedIp) && cleanedIp.contains(":")

        val replacementIp = if (isIpv6) "[$cleanedIp]" else cleanedIp

        // handle full url for DoH
        if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
            return try {
                val uri = URI(trimmed)
                val newAuthority =
                    if (uri.port != -1) {
                        "$replacementIp:${uri.port}"
                    } else {
                        replacementIp
                    }

                URI(uri.scheme, newAuthority, uri.path, uri.query, uri.fragment).toString()
            } catch (_: Exception) {
                // just return the IP if URL parsing fails
                replacementIp
            }
        }

        // host:port format DoT and plain
        if (trimmed.contains(":")) {
            val port = trimmed.substringAfterLast(":")
            // Only treat as port if it's numeric
            if (port.toIntOrNull() != null) {
                return "$replacementIp:$port"
            }
        }

        // bare hostname/ip
        return replacementIp
    }

    fun isIpAddress(host: String): Boolean {
        val cleaned = host.trim().removeSurrounding("[", "]")
        return try {
            val addr = IPAddressString(cleaned).address
            addr != null && (addr.isIPv4 || addr.isIPv6)
        } catch (_: Exception) {
            false
        }
    }

    fun needsResolution(upstream: String): Boolean {
        val host = extractHost(upstream)
        return host.isNotBlank() && !isIpAddress(host)
    }

    /**
     * Decodes an IP4P address from natmap format into a real IPv4 and port. Returns null if the
     * address is not IP4P.
     */
    fun decodeIp4p(raw: String): Pair<String, Int>? {
        val clean = raw.removePrefix("[").removeSuffix("]")
        val ipv6 = IPAddressString(clean).address as? IPv6Address ?: return null

        val bytes = ipv6.bytes
        if (bytes.size != 16) return null

        // Must start with 2001:
        if (bytes[0] != 0x20.toByte() || bytes[1] != 0x01.toByte()) return null

        // IP4P has zeros in bytes 2 to 9
        for (i in 2..9) {
            if (bytes[i] != 0.toByte()) return null
        }

        // bytes 10 to 11 for port
        val port = ((bytes[10].toInt() and 0xFF) shl 8) or (bytes[11].toInt() and 0xFF)
        if (port !in 1..65535) return null

        // bytes 12 to 15 for IPv4
        val ipv4 = buildString {
            append(bytes[12].toInt() and 0xFF).append('.')
            append(bytes[13].toInt() and 0xFF).append('.')
            append(bytes[14].toInt() and 0xFF).append('.')
            append(bytes[15].toInt() and 0xFF)
        }

        return ipv4 to port
    }

    fun ensurePort53(ip: String): String = ensureDnsPort(ip, 53)

    fun ensureDnsPort(ip: String, defaultPort: Int): String {
        val ip = ip.trim()
        if (ip.isEmpty()) return ip

        // [IPv6] or [IPv6]:port
        if (ip.startsWith("[")) {
            val end = ip.indexOf(']')
            if (end <= 1) return ip
            val rest = ip.substring(end + 1)
            if (rest.startsWith(":") && rest.drop(1).toIntOrNull() != null) return ip
            return "$ip:$defaultPort"
        }

        // IPv4 or hostname with port (single colon)
        val colon = ip.lastIndexOf(':')
        if (colon > 0 && ip.indexOf(':') == colon) {
            val port = ip.substring(colon + 1).toIntOrNull()
            if (port != null && port in 1..65535) return ip
        }

        if (ip.contains(':')) return ip

        return "$ip:$defaultPort"
    }
}
