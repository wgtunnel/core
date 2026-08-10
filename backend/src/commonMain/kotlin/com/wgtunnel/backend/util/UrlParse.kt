package com.wgtunnel.backend.util

internal object UrlParse {
    /** host from http(s) URL or null */
    fun host(url: String): String? {
        val s = url.trim()
        val schemeEnd = s.indexOf("://")
        if (schemeEnd < 0) return null
        var rest = s.substring(schemeEnd + 3)
        // strip userinfo
        val at = rest.lastIndexOf('@')
        if (at >= 0) rest = rest.substring(at + 1)
        // authority ends at / ? #
        val end = rest.indexOfAny(charArrayOf('/', '?', '#')).let { if (it < 0) rest.length else it }
        val authority = rest.substring(0, end)
        return authorityHost(authority)
    }

    fun port(url: String): Int {
        val s = url.trim()
        val schemeEnd = s.indexOf("://")
        if (schemeEnd < 0) return -1
        var rest = s.substring(schemeEnd + 3)
        val at = rest.lastIndexOf('@')
        if (at >= 0) rest = rest.substring(at + 1)
        val end = rest.indexOfAny(charArrayOf('/', '?', '#')).let { if (it < 0) rest.length else it }
        val authority = rest.substring(0, end)
        return authorityPort(authority)
    }

    /** path + optional ?query, default /dns-query */
    fun pathAndQuery(url: String, defaultPath: String = "/dns-query"): String {
        val s = url.trim()
        val withScheme = if (s.contains("://")) s else "https://$s"
        val schemeEnd = withScheme.indexOf("://")
        var rest = withScheme.substring(schemeEnd + 3)
        val at = rest.lastIndexOf('@')
        if (at >= 0) rest = rest.substring(at + 1)
        val pathStart = rest.indexOf('/').let { if (it < 0) rest.length else it }
        val afterAuth = rest.substring(pathStart) // "", "/dns-query", "/x?y"
        if (afterAuth.isEmpty() || afterAuth == "/") return defaultPath
        val frag = afterAuth.indexOf('#')
        val noFrag = if (frag >= 0) afterAuth.substring(0, frag) else afterAuth
        return noFrag.ifEmpty { defaultPath }
    }

    private fun authorityHost(authority: String): String? {
        if (authority.isEmpty()) return null
        if (authority.startsWith("[")) {
            val end = authority.indexOf(']')
            if (end <= 1) return null
            return authority.substring(1, end)
        }
        val colon = authority.lastIndexOf(':')
        // IPv4 or hostname:port — single colon
        if (colon > 0 && authority.indexOf(':') == colon) {
            return authority.substring(0, colon)
        }
        return authority
    }

    private fun authorityPort(authority: String): Int {
        if (authority.startsWith("[")) {
            val end = authority.indexOf(']')
            if (end <= 1) return -1
            val rest = authority.substring(end + 1)
            return if (rest.startsWith(":")) rest.drop(1).toIntOrNull() ?: -1 else -1
        }
        val colon = authority.lastIndexOf(':')
        if (colon > 0 && authority.indexOf(':') == colon) {
            return authority.substring(colon + 1).toIntOrNull() ?: -1
        }
        return -1
    }
}