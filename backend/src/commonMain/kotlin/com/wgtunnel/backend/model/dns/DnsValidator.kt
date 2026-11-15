package com.wgtunnel.backend.model.dns

import com.wgtunnel.backend.util.DnsHostUtils
import com.wgtunnel.backend.util.UrlParse

enum class DnsEndpointProtocol {
    SYSTEM,
    DOH,
    DOT,
    UDP,
}

sealed class DnsValidationError {
    data object Empty : DnsValidationError()

    data object InvalidUrl : DnsValidationError()

    data object InvalidScheme : DnsValidationError()

    data object InvalidHost : DnsValidationError()

    data object InvalidPort : DnsValidationError()

    data object InvalidIpOrHost : DnsValidationError()
}

// Validates and normalizes user-entered DNS endpoints/suffixes, shared by every app's DNS
// settings screen.
object DnsValidator {

    private const val DEFAULT_DOT_PORT = 853
    private const val DEFAULT_DNS_PORT = 53

    sealed class Result {
        data object Valid : Result()

        data class Invalid(val error: DnsValidationError) : Result()
    }

    fun normalizeEndpoint(protocol: DnsEndpointProtocol, input: String?): String {
        val value = input?.trim().orEmpty()
        if (value.isEmpty()) return value

        return when (protocol) {
            DnsEndpointProtocol.SYSTEM -> value
            DnsEndpointProtocol.DOH -> normalizeDoH(value)
            DnsEndpointProtocol.DOT -> normalizeHostPort(value, DEFAULT_DOT_PORT)
            DnsEndpointProtocol.UDP -> normalizeHostPort(value, DEFAULT_DNS_PORT)
        }
    }

    fun validateEndpoint(protocol: DnsEndpointProtocol, endpoint: String?): Result {
        if (protocol == DnsEndpointProtocol.SYSTEM) return Result.Valid

        val value = endpoint?.trim().orEmpty()
        if (value.isEmpty()) return Result.Invalid(DnsValidationError.Empty)

        return when (protocol) {
            DnsEndpointProtocol.SYSTEM -> Result.Valid
            DnsEndpointProtocol.DOH -> validateDoH(value)
            DnsEndpointProtocol.DOT -> validateHostPort(value, DEFAULT_DOT_PORT)
            DnsEndpointProtocol.UDP -> validateHostPort(value, DEFAULT_DNS_PORT)
        }
    }

    fun normalizeLocalSuffixes(input: String?): String {
        if (input.isNullOrBlank()) return ""
        return input
            .split(',', '\n', ' ')
            .asSequence()
            .map { it.trim().lowercase().trim('.') }
            .filter { it.isNotEmpty() }
            .map { ".$it" }
            .distinct()
            .joinToString(",")
    }

    fun validateLocalSuffixes(requiresSuffixes: Boolean, input: String?): Result {
        if (!requiresSuffixes) return Result.Valid

        val normalized = normalizeLocalSuffixes(input)
        if (normalized.isEmpty()) {
            return Result.Invalid(DnsValidationError.Empty)
        }

        for (suffix in normalized.split(",")) {
            val label = suffix.removePrefix(".")
            if (label.isEmpty() || label.contains("..") || label.contains(" ")) {
                return Result.Invalid(DnsValidationError.InvalidHost)
            }
            // single-label special-use (.local) and normal multi-label suffixes
            if (!isValidSuffix(label)) {
                return Result.Invalid(DnsValidationError.InvalidHost)
            }
        }
        return Result.Valid
    }

    private fun validateDoH(value: String): Result {
        if (!value.startsWith("https://")) {
            return Result.Invalid(DnsValidationError.InvalidScheme)
        }
        val host = UrlParse.host(value)
        if (host.isNullOrBlank()) {
            return Result.Invalid(DnsValidationError.InvalidUrl)
        }
        if (!isValidHostOrIp(host)) {
            return Result.Invalid(DnsValidationError.InvalidIpOrHost)
        }
        if (UrlParse.hasPort(value) && UrlParse.port(value) !in 1..65535) {
            return Result.Invalid(DnsValidationError.InvalidPort)
        }
        return Result.Valid
    }

    private fun validateHostPort(value: String, defaultPort: Int): Result {
        val (rawHost, rawPort) =
            if (value.contains("://")) {
                schemeStrippedHostPort(value)
                    ?: return Result.Invalid(DnsValidationError.InvalidUrl)
            } else {
                TunnelDnsConfig.splitHostPort(value) ?: (value to null)
            }
        val host = rawHost.trim()
        val port = rawPort ?: defaultPort

        if (host.isBlank()) {
            return Result.Invalid(DnsValidationError.InvalidHost)
        }
        if (!isValidHostOrIp(host)) {
            return Result.Invalid(DnsValidationError.InvalidIpOrHost)
        }
        if (port !in 1..65535) {
            return Result.Invalid(DnsValidationError.InvalidPort)
        }
        return Result.Valid
    }

    private fun normalizeDoH(value: String): String {
        return if (value.startsWith("http://") || value.startsWith("https://")) {
            value
        } else {
            "https://$value"
        }
    }

    private fun normalizeHostPort(value: String, defaultPort: Int): String {
        if (value.contains("://")) {
            // Looks like a DoH URL pasted into a DoT/plain field. Recover the intended
            // host[:port] instead of mistaking the scheme's colon for a port separator
            val (host, port) = schemeStrippedHostPort(value) ?: return value
            val effectivePort = port ?: defaultPort
            return if (host.contains(":") && !host.startsWith("[")) {
                "[$host]:$effectivePort"
            } else {
                "$host:$effectivePort"
            }
        }
        val (host, port) = TunnelDnsConfig.splitHostPort(value) ?: (value to null)
        if (port != null) return value
        val trimmedHost = host.trim()
        // Re-bracket an IPv6 host
        return if (trimmedHost.contains(":") && !trimmedHost.startsWith("[")) {
            "[$trimmedHost]:$defaultPort"
        } else {
            "$trimmedHost:$defaultPort"
        }
    }

    // Recovers host[:port] from a value that still has a URL scheme. Returns null when it has a
    // real path beyond "/", since that's a sign the endpoint is actually meant for DoH,
    private fun schemeStrippedHostPort(value: String): Pair<String, Int?>? {
        val path = UrlParse.pathAndQuery(value, "")
        if (path.isNotEmpty() && path != "/") return null
        val host = UrlParse.host(value) ?: return null
        val port = UrlParse.port(value).takeIf { it > 0 }
        return host to port
    }

    private fun isValidHostOrIp(value: String): Boolean {
        return DnsHostUtils.isIpAddress(value) || isValidHostname(value)
    }

    private fun isValidHostname(value: String): Boolean {
        // A single trailing dot marks a fully qualified name and is valid
        val name = value.removeSuffix(".")
        if (name.length > 253) return false
        val labels = name.split(".")
        return labels.all { label ->
            label.matches(Regex("^[a-zA-Z0-9_-]{1,63}$")) &&
                !label.startsWith("-") &&
                !label.endsWith("-")
        }
    }

    // Allows "local" and dotted domain suffixes
    private fun isValidSuffix(label: String): Boolean {
        if (label.equals("local", ignoreCase = true)) return true
        return isValidHostname(label)
    }
}
