package com.wgtunnel.backend.model.dns

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
        return Result.Valid
    }

    private fun validateHostPort(value: String, defaultPort: Int): Result {
        val (rawHost, rawPort) = TunnelDnsConfig.splitHostPort(value) ?: (value to null)
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
        val (host, port) = TunnelDnsConfig.splitHostPort(value) ?: (value to null)
        return if (port == null) "${host.trim()}:$defaultPort" else value
    }

    private fun isValidHostOrIp(value: String): Boolean {
        return isValidIpv4(value) || isValidHostname(value)
    }

    private fun isValidIpv4(value: String): Boolean {
        val parts = value.split(".")
        if (parts.size != 4) return false
        return parts.all { it.toIntOrNull()?.let { num -> num in 0..255 } == true }
    }

    private fun isValidHostname(value: String): Boolean {
        if (value.length > 253) return false
        val labels = value.split(".")
        return labels.all { label ->
            label.matches(Regex("^[a-zA-Z0-9-]{1,63}$")) &&
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
