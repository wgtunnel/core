package com.wgtunnel.parser.util

import com.wgtunnel.parser.ConfigParseException
import com.wgtunnel.parser.ErrorType
import java.net.Inet4Address
import java.net.InetAddress
import kotlin.io.encoding.Base64
import org.apache.commons.validator.routines.InetAddressValidator

object NetworkUtils {

    private val validator = InetAddressValidator.getInstance()

    fun isValidIp(ip: String): Boolean {
        return validator.isValid(ip.removeSurrounding("[", "]"))
    }

    fun isValidCidr(cidr: String): Boolean {
        val parts = cidr.split("/", limit = 2)
        val ip = parts[0]

        if (parts.size == 1) {
            return isValidIp(ip)
        }

        val prefix = parts[1].toIntOrNull() ?: return false
        if (!isValidIp(ip)) return false

        return try {
            val addr = InetAddress.getByName(ip.removeSurrounding("[", "]"))
            val maxPrefix = if (addr is Inet4Address) 32 else 128
            prefix in 0..maxPrefix
        } catch (_ : Exception) {
            false
        }
    }

    fun isValidDnsEntry(entry: String): Boolean {
        if (entry.isBlank()) return false
        return isValidIp(entry) || isValidHostname(entry)
    }

    fun isValidHostname(host: String): Boolean {
        val cleaned = host.removeSurrounding("[", "]").trim()
        if (cleaned.isBlank() || cleaned.length > 253) return false
        if (cleaned.startsWith(".") || cleaned.endsWith(".") || cleaned.contains("..")) return false

        return cleaned.split('.').all { label ->
            label.length in 1..63 &&
                !label.startsWith('-') &&
                !label.endsWith('-') &&
                label.matches(Regex("^[a-zA-Z0-9-]+$"))
        }
    }

    fun isValidBase64(str: String): Boolean {
        return try {
            val decoded = Base64.decode(str)
            decoded.size == 32
        } catch (_: Exception) {
            false
        }
    }

    fun isValidAmneziaHeader(header: String): Boolean {
        val maxUInt32 = 4294967295L
        return try {
            if (header.contains("-")) {
                val parts = header.split("-")
                if (parts.size != 2) return false
                val start = parts[0].trim().toLong()
                val end = parts[1].trim().toLong()
                start in 0..maxUInt32 && end in 0..maxUInt32 && start <= end
            } else {
                header.trim().toLong() in 0..maxUInt32
            }
        } catch (_: Exception) {
            false
        }
    }

    /**
     * AmneziaWG 3.0 range-or-scalar or "(off)" values Used for timings, content padding, and range
     * PersistentKeepalive.
     */
    fun isValidUintRangeOrScalar(value: String): Boolean {
        val v = value.trim()
        if (v.isEmpty()) return false
        if (v.equals("(off)", ignoreCase = true)) return true
        return try {
            if (v.contains("-")) {
                val parts = v.split("-", limit = 2)
                if (parts.size != 2) return false
                val start = parts[0].trim().toULong()
                val end = parts[1].trim().toULong()
                start <= end
            } else {
                v.toULong()
                true
            }
        } catch (_: Exception) {
            false
        }
    }

    @Throws(ConfigParseException::class)
    fun validateAmneziaSignaturePacket(value: String, fieldName: String) {
        var remaining = value
        var tagCount = 0

        while (true) {
            val start = remaining.indexOf('<')
            if (start == -1) break
            val end = remaining.indexOf('>', start + 1)
            if (end == -1) {
                throw ConfigParseException(ErrorType.INVALID_SIGNATURE_FORMAT, fieldName, value)
            }

            val parts =
                remaining.substring(start + 1, end).trim().split(WHITESPACE).filter {
                    it.isNotEmpty()
                }
            if (parts.isEmpty()) {
                throw ConfigParseException(ErrorType.INVALID_SIGNATURE_FORMAT, fieldName, value)
            }

            val tagType = parts[0].lowercase()
            val arg = parts.getOrNull(1).orEmpty()
            when (tagType) {
                "b" -> validateSignatureBytesArg(arg, fieldName, value)
                "r",
                "rc",
                "rd",
                "dz" -> validateSignatureLengthArg(arg, fieldName, value)
                "t",
                "d",
                "ds" -> Unit
                else ->
                    throw ConfigParseException(ErrorType.INVALID_SIGNATURE_FORMAT, fieldName, value)
            }

            tagCount++
            remaining = remaining.substring(end + 1)
        }

        if (tagCount == 0) {
            throw ConfigParseException(ErrorType.INVALID_SIGNATURE_FORMAT, fieldName, value)
        }
    }

    private fun validateSignatureBytesArg(arg: String, fieldName: String, value: String) {
        val hex = arg.removePrefix("0x").removePrefix("0X")
        if (hex.isEmpty() || hex.length % 2 != 0 || hex.any { !it.isHexDigit() }) {
            throw ConfigParseException(ErrorType.INVALID_SIGNATURE_FORMAT, fieldName, value)
        }
    }

    private fun validateSignatureLengthArg(arg: String, fieldName: String, value: String) {
        val size = arg.toIntOrNull()
        if (size == null || size < 0) {
            throw ConfigParseException(ErrorType.INVALID_SIGNATURE_FORMAT, fieldName, value)
        }
    }

    private fun Char.isHexDigit(): Boolean =
        this in '0'..'9' || this in 'a'..'f' || this in 'A'..'F'

    private val WHITESPACE = Regex("\\s+")
}
