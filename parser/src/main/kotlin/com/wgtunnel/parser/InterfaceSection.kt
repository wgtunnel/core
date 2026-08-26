package com.wgtunnel.parser

import com.wgtunnel.parser.util.NetworkUtils
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class InterfaceSection(
    @SerialName("PrivateKey") val privateKey: String,
    @SerialName("Address") val address: String? = null,
    @SerialName("ListenPort") val listenPort: Int? = null,
    @SerialName("DNS") val dns: String? = null,
    @SerialName("MTU") val mtu: Int? = null,
    // Linux
    @SerialName("FwMark") val fwMark: Int? = null,
    @SerialName("Table") val table: String? = null,
    @SerialName("SaveConfig") val saveConfig: Boolean? = null,
    // Desktop or Rooted Android
    @SerialName("PreUp") val preUp: List<String>? = null,
    @SerialName("PostUp") val postUp: List<String>? = null,
    @SerialName("PreDown") val preDown: List<String>? = null,
    @SerialName("PostDown") val postDown: List<String>? = null,
    // Android
    @SerialName("IncludedApplications") val includedApplications: List<String>? = null,
    @SerialName("ExcludedApplications") val excludedApplications: List<String>? = null,
    // AmneziaWG 1.x / 2.x
    @SerialName("Jc") val jC: Int? = null,
    @SerialName("Jmin") val jMin: Int? = null,
    @SerialName("Jmax") val jMax: Int? = null,
    @SerialName("S1") val s1: Int? = null,
    @SerialName("S2") val s2: Int? = null,
    @SerialName("S3") val s3: Int? = null,
    @SerialName("S4") val s4: Int? = null,
    @SerialName("H1") val h1: String? = null,
    @SerialName("H2") val h2: String? = null,
    @SerialName("H3") val h3: String? = null,
    @SerialName("H4") val h4: String? = null,
    @SerialName("I1") val i1: String? = null,
    @SerialName("I2") val i2: String? = null,
    @SerialName("I3") val i3: String? = null,
    @SerialName("I4") val i4: String? = null,
    @SerialName("I5") val i5: String? = null,
    // AmneziaWG 3.0+
    // Base64 Curve25519-style key for packet header protection.
    @SerialName("HeaderProtectionKey") val headerProtectionKey: String? = null,
    // Scalar or range of extra content padding bytes
    @SerialName("ContentPaddingAddition") val contentPaddingAddition: String? = null,
    @SerialName("RekeyAfterTime") val rekeyAfterTime: String? = null,
    @SerialName("RekeyTimeout") val rekeyTimeout: String? = null,
    @SerialName("RejectAfterTime") val rejectAfterTime: String? = null,
    @SerialName("KeepaliveTimeout") val keepaliveTimeout: String? = null,
    @SerialName("MaxHandshakeAttempts") val maxHandshakeAttempts: String? = null,
    @SerialName("RandomTrailers") val randomTrailers: String? = null,
    @SerialName("DisableCookies") val disableCookies: String? = null,
    val comments: List<String> = emptyList(),
) {

    private val validAmneziaBooleans = listOf("on", "off", "true", "false", "1", "0")

    val allIncludedApps: List<String>
        get() = includedApplications.orEmpty()

    val allExcludedApps: List<String>
        get() = excludedApplications.orEmpty()

    val allPreUp: List<String>
        get() = preUp.orEmpty()

    val allPostUp: List<String>
        get() = postUp.orEmpty()

    val allPreDown: List<String>
        get() = preDown.orEmpty()

    val allPostDown: List<String>
        get() = postDown.orEmpty()

    val hasScripts: Boolean
        get() =
            allPreUp.isNotEmpty() ||
                allPostUp.isNotEmpty() ||
                allPreDown.isNotEmpty() ||
                allPostDown.isNotEmpty()

    @Throws(ConfigParseException::class)
    fun validate() {
        if (privateKey.isBlank())
            throw ConfigParseException(ErrorType.MISSING_REQUIRED_FIELD, "Interface.PrivateKey")
        if (!NetworkUtils.isValidBase64(privateKey))
            throw ConfigParseException(
                ErrorType.INVALID_BASE64_KEY,
                "Interface.PrivateKey",
                privateKey,
            )

        listenPort?.let {
            if (it !in 0..65535)
                throw ConfigParseException(ErrorType.INVALID_PORT_RANGE, "Interface.ListenPort", it)
        }
        mtu?.let {
            if (it !in 576..9000)
                throw ConfigParseException(ErrorType.INVALID_MTU_RANGE, "Interface.MTU", it)
        }
        fwMark?.let {
            if (it < 0) throw ConfigParseException(ErrorType.INVALID_FWMARK, "Interface.FwMark", it)
        }

        jC?.let {
            if (it < 0) throw ConfigParseException(ErrorType.INVALID_JC_VALUE, "Interface.Jc", it)
        }
        if (jMin != null && jMax != null) {
            if (jMin > jMax)
                throw ConfigParseException(ErrorType.INVALID_JMIN_JMAX_ORDER, "Interface.Jmin/Jmax")
        }

        listOf(s1, s2, s3, s4).forEachIndexed { i, s ->
            if (s != null && s < 0)
                throw ConfigParseException(
                    ErrorType.INVALID_PADDING_NEGATIVE,
                    "Interface.S${i + 1}",
                    s,
                )
        }

        // Message type sizes must remain distinguishable after S1–S3 padding per Amnezia
        val initJunk = s1 ?: 0
        val responseJunk = s2 ?: 0
        val cookieJunk = s3 ?: 0
        if (148 + initJunk == 92 + responseJunk) {
            throw ConfigParseException(
                ErrorType.INVALID_PADDING_COLLISION,
                "Interface.S1/S2",
                "S1 + 148 must not equal S2 + 92",
            )
        }
        if (148 + initJunk == 64 + cookieJunk) {
            throw ConfigParseException(
                ErrorType.INVALID_PADDING_COLLISION,
                "Interface.S1/S3",
                "S1 + 148 must not equal S3 + 64",
            )
        }
        if (92 + responseJunk == 64 + cookieJunk) {
            throw ConfigParseException(
                ErrorType.INVALID_PADDING_COLLISION,
                "Interface.S2/S3",
                "S2 + 92 must not equal S3 + 64",
            )
        }

        listOf(h1, h2, h3, h4).forEachIndexed { i, h ->
            h?.takeIf { it.isNotBlank() }
                ?.let {
                    if (!NetworkUtils.isValidAmneziaHeader(it)) {
                        throw ConfigParseException(
                            ErrorType.INVALID_HEADER_FORMAT,
                            "Interface.H${i + 1}",
                            it,
                        )
                    }
                }
        }

        listOf(i1 to "I1", i2 to "I2", i3 to "I3", i4 to "I4", i5 to "I5").forEach {
            (sig, shortName) ->
            sig?.takeIf { it.isNotBlank() }
                ?.let { NetworkUtils.validateAmneziaSignaturePacket(it, "Interface.$shortName") }
        }

        headerProtectionKey
            ?.takeIf { it.isNotBlank() }
            ?.let { key ->
                if (!NetworkUtils.isValidBase64(key)) {
                    throw ConfigParseException(
                        ErrorType.INVALID_BASE64_KEY,
                        "Interface.HeaderProtectionKey",
                        key,
                    )
                }
                listOf(
                        s1 to "S1",
                        s2 to "S2",
                        s3 to "S3",
                        s4 to "S4",
                    )
                    .forEach { (value, name) ->
                        val junk = value ?: 0
                        if (junk < 12) {
                            throw ConfigParseException(
                                ErrorType.INVALID_HEADER_PROTECTION_PADDING,
                                "Interface.$name",
                                junk,
                            )
                        }
                    }
            }

        contentPaddingAddition
            ?.takeIf { it.isNotBlank() }
            ?.let {
                if (!NetworkUtils.isValidUintRangeOrScalar(it)) {
                    throw ConfigParseException(
                        ErrorType.INVALID_RANGE_FORMAT,
                        "Interface.ContentPaddingAddition",
                        it,
                    )
                }
            }

        listOf(
                rekeyAfterTime to "RekeyAfterTime",
                rekeyTimeout to "RekeyTimeout",
                rejectAfterTime to "RejectAfterTime",
                keepaliveTimeout to "KeepaliveTimeout",
                maxHandshakeAttempts to "MaxHandshakeAttempts",
            )
            .forEach { (value, name) ->
                value
                    ?.takeIf { it.isNotBlank() }
                    ?.let {
                        if (!NetworkUtils.isValidUintRangeOrScalar(it)) {
                            throw ConfigParseException(
                                ErrorType.INVALID_RANGE_FORMAT,
                                "Interface.$name",
                                it,
                            )
                        }
                    }
            }

        address
            ?.split(",")
            ?.map { it.trim() }
            ?.filter { it.isNotBlank() }
            ?.forEach {
                if (!NetworkUtils.isValidCidr(it))
                    throw ConfigParseException(ErrorType.INVALID_CIDR, "Interface.Address", it)
            }

        dns?.split(",")
            ?.map { it.trim() }
            ?.filter { it.isNotBlank() }
            ?.forEach {
                if (!NetworkUtils.isValidDnsEntry(it))
                    throw ConfigParseException(ErrorType.INVALID_DNS_ENTRY, "Interface.DNS", it)
            }

        randomTrailers
            ?.takeIf { it.isNotBlank() }
            ?.let {
                if (it !in validAmneziaBooleans) {
                    throw ConfigParseException(
                        ErrorType.INVALID_RANDOM_TRAILER_VALUE,
                        "Interface.RandomTrailers",
                        it,
                    )
                }
            }

        disableCookies
            ?.takeIf { it.isNotBlank() }
            ?.let {
                if (it !in validAmneziaBooleans) {
                    throw ConfigParseException(
                        ErrorType.INVALID_DISABLE_COOKIES_VALUE,
                        "Interface.DisableCookies",
                        it,
                    )
                }
            }
    }
}
