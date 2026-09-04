package com.wgtunnel.parser

import com.wgtunnel.parser.crypto.Key
import com.wgtunnel.parser.util.ConfigFormatter
import com.wgtunnel.parser.util.getBool
import com.wgtunnel.parser.util.getInt
import com.wgtunnel.parser.util.getList
import com.wgtunnel.parser.util.getLong
import com.wgtunnel.parser.util.getTrimmed
import kotlin.io.encoding.Base64
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class Config(
    @SerialName("Interface") val `interface`: InterfaceSection,
    @SerialName("Peer") val peers: List<PeerSection> = emptyList(),
    val name: String? = null,
    val headerComments: List<String> = emptyList(),
) {

    fun withName(newName: String?): Config =
        copy(name = newName?.trim()?.takeIf { it.isNotBlank() })

    @Throws(ConfigParseException::class)
    fun validate() {
        `interface`.validate()
        peers.forEachIndexed { index, peer -> peer.validate(index) }
    }

    fun asQuickString(include: ConfigQuickInclude = ConfigQuickInclude.All): String = buildString {
        if (include.core) {
            name?.let { appendLine("# Name = $it") }
            headerComments.forEach { appendLine(it) }
        }
        if (include.core || include.dns || include.amnezia) {
            ConfigFormatter.appendInterfaceSection(this, `interface`, include = include)
        }
        if (include.peers) {
            peers.forEach { ConfigFormatter.appendPeerSection(this, it) }
        }
    }
        .trim()

    fun rotateInterfaceKey(): Config {
        val privateKey = Key.generatePrivateKey()
        val newInterface = `interface`.copy(privateKey = privateKey.toBase64())
        return copy(`interface` = newInterface)
    }

    companion object {
        fun parseInterfaceQuickString(configString: String): Config {
            val trimmed = configString.replace("\r\n", "\n").replace("\r", "\n").trim()
            if (trimmed.isEmpty()) return parseQuickString("[Interface]")
            val hasInterface =
                trimmed.lineSequence().any { it.trim().equals("[Interface]", ignoreCase = true) }
            return parseQuickString(if (hasInterface) trimmed else "[Interface]\n$trimmed")
        }

        fun parseQuickString(configString: String): Config {
            val scripts = InterfaceScriptsBuilder()
            val interfaceMap = mutableMapOf<String, String>()
            val peerMaps = mutableListOf<Pair<MutableMap<String, String>, List<String>>>()

            val headerComments = mutableListOf<String>()
            val currentCommentBuffer = mutableListOf<String>()
            var interfaceComments = listOf<String>()

            var currentSectionMap: MutableMap<String, String>? = null
            var isFirstSectionFound = false

            // normalize and trim
            val normalizedConfig = configString.replace("\r\n", "\n").replace("\r", "\n").trim()

            normalizedConfig.lines().forEach { line ->
                val raw = line.trim()
                if (raw.isEmpty()) return@forEach

                // handle comments
                if (raw.startsWith("#") || raw.startsWith(";")) {
                    if (!isFirstSectionFound) {
                        headerComments.add(raw)
                    } else {
                        currentCommentBuffer.add(raw)
                    }
                    return@forEach
                }

                // Handle Section Headers
                if (raw.startsWith("[") && raw.endsWith("]")) {
                    isFirstSectionFound = true
                    val sectionName = raw.substring(1, raw.length - 1).lowercase()

                    when (sectionName) {
                        "interface" -> {
                            currentSectionMap = interfaceMap
                            interfaceComments = currentCommentBuffer.toList()
                            currentCommentBuffer.clear()
                        }
                        "peer" -> {
                            val newPeerMap = mutableMapOf<String, String>()
                            peerMaps.add(newPeerMap to currentCommentBuffer.toList())
                            currentSectionMap = newPeerMap
                            currentCommentBuffer.clear()
                        }
                        else -> currentSectionMap = null
                    }
                    return@forEach
                }

                val parts = raw.split("=", limit = 2)

                if (parts.size == 2) {
                    val rawKey = parts[0].trim()
                    val lowerKey = rawKey.lowercase()

                    // Normalize wireguard keys
                    val key =
                        when (lowerKey) {
                            "allowedips" -> "AllowedIPs"
                            "address" -> "Address"
                            "dns" -> "DNS"
                            "presharedkey" -> "PresharedKey"
                            "privatekey" -> "PrivateKey"
                            "publickey" -> "PublicKey"
                            "listenport" -> "ListenPort"
                            "persistentkeepalive" -> "PersistentKeepalive"
                            "mtu" -> "MTU"
                            "table" -> "Table"
                            "saveconfig" -> "SaveConfig"
                            else -> rawKey
                        }

                    // Strip inline comments before trimming
                    var value = parts[1].substringBefore("#").substringBefore(";").trim()

                    if (currentSectionMap === interfaceMap) {
                        when (key) {
                            "PreUp",
                            "PostUp",
                            "PreDown",
                            "PostDown" -> {
                                scripts.add(key, value)
                                return@forEach
                            }
                        }
                    }

                    // Remove whitespaces
                    if (
                        key in
                            listOf(
                                "PrivateKey",
                                "PublicKey",
                                "PresharedKey",
                                "HeaderProtectionKey",
                                "H1",
                                "H2",
                                "H3",
                                "H4",
                            )
                    ) {
                        value = value.replace(Regex("\\s+"), "")
                    }

                    when (key) {
                        "AllowedIPs",
                        "Address",
                        "DNS" -> {
                            val existing = currentSectionMap?.get(key)
                            currentSectionMap?.put(
                                key,
                                if (existing.isNullOrEmpty()) value else "$existing, $value",
                            )
                        }
                        "PresharedKey" -> {
                            currentSectionMap?.put("PresharedKey", value)
                            currentSectionMap?.put("PreSharedKey", value)
                        }
                        else -> {
                            currentSectionMap?.put(key, value)
                        }
                    }
                }
            }

            val extractedName =
                headerComments.firstOrNull()?.let { firstComment ->
                    val content = firstComment.trimStart('#', ' ', '\t').trim()

                    when {
                        content.startsWith("Name", ignoreCase = true) -> {
                            content
                                .substringAfter("Name", "")
                                .trimStart('=', ' ', '\t')
                                .trim()
                                .takeIf { it.isNotBlank() }
                        }
                        else -> null
                    }
                }

            // prevent name duplicates
            val cleanedHeaderComments =
                if (extractedName != null) {
                    headerComments.drop(1)
                } else {
                    headerComments
                }

            return Config(
                headerComments = cleanedHeaderComments,
                name = extractedName,
                `interface` = buildInterface(interfaceMap, scripts.build(), interfaceComments),
                peers = peerMaps.map { (map, comments) -> buildPeer(map, comments) },
            )
        }

        internal fun buildInterface(
            m: Map<String, String>,
            scripts: InterfaceScriptsBuilder.InterfaceScripts,
            comments: List<String>,
        ) =
            InterfaceSection(
                comments = comments,
                privateKey = m.getTrimmed("PrivateKey") ?: "",
                address = m.getTrimmed("Address"),
                dns = m.getTrimmed("DNS"),
                listenPort = m.getInt("ListenPort", "Interface"),
                mtu = m.getInt("MTU", "Interface"),
                fwMark = m.getInt("FwMark", "Interface"),
                table = m.getTrimmed("Table"),
                saveConfig = m.getBool("SaveConfig", "Interface"),
                preUp = scripts.preUp,
                postUp = scripts.postUp,
                preDown = scripts.preDown,
                postDown = scripts.postDown,
                jC = m.getInt("Jc", "Interface"),
                jMin = m.getInt("Jmin", "Interface"),
                jMax = m.getInt("Jmax", "Interface"),
                s1 = m.getInt("S1", "Interface"),
                s2 = m.getInt("S2", "Interface"),
                s3 = m.getInt("S3", "Interface"),
                s4 = m.getInt("S4", "Interface"),
                h1 = m.getTrimmed("H1"),
                h2 = m.getTrimmed("H2"),
                h3 = m.getTrimmed("H3"),
                h4 = m.getTrimmed("H4"),
                i1 = m.getTrimmed("I1"),
                i2 = m.getTrimmed("I2"),
                i3 = m.getTrimmed("I3"),
                i4 = m.getTrimmed("I4"),
                i5 = m.getTrimmed("I5"),
                headerProtectionKey = m.getTrimmed("HeaderProtectionKey"),
                contentPaddingAddition = m.getTrimmed("ContentPaddingAddition"),
                rekeyAfterTime = m.getTrimmed("RekeyAfterTime"),
                rekeyTimeout = m.getTrimmed("RekeyTimeout"),
                rejectAfterTime = m.getTrimmed("RejectAfterTime"),
                keepaliveTimeout = m.getTrimmed("KeepaliveTimeout"),
                maxHandshakeAttempts = m.getTrimmed("MaxHandshakeAttempts"),
                randomTrailers = m.getTrimmed("RandomTrailers"),
                disableCookies = m.getTrimmed("DisableCookies"),
                includedApplications = m.getList("IncludedApplications"),
                excludedApplications = m.getList("ExcludedApplications"),
            )

        private fun buildPeer(m: Map<String, String>, comments: List<String>) =
            PeerSection(
                publicKey = m["PublicKey"] ?: "",
                allowedIPs = m["AllowedIPs"],
                endpoint = m["Endpoint"],
                presharedKey = m["PresharedKey"] ?: m["PreSharedKey"],
                persistentKeepalive = m["PersistentKeepalive"]?.trim()?.takeIf { it.isNotEmpty() },
                comments = comments,
            )

        fun parseEndpoint(endpoint: String): Pair<String?, String?> {
            var host: String
            var portStr: String?
            if (endpoint.startsWith("[")) {
                val endBracket = endpoint.lastIndexOf("]")
                if (endBracket == -1 || !endpoint.substring(endBracket + 1).startsWith(":"))
                    return null to null
                host = endpoint.take(endBracket + 1)
                portStr = endpoint.substring(endBracket + 2)
            } else {
                val parts = endpoint.split(":", limit = 2)
                if (parts.size != 2) return null to null
                host = parts[0]
                portStr = parts[1]
            }
            return host to portStr
        }

        internal fun hexToBase64(hex: String): String {
            if (hex.length != 64 || !hex.matches(Regex("[0-9a-fA-F]{64}"))) {
                throw ConfigParseException(ErrorType.INVALID_HEX_KEY, "key", hex)
            }
            val bytes = ByteArray(32)
            for (i in 0 until 32) {
                val chunk = hex.substring(i * 2, i * 2 + 2)
                bytes[i] = chunk.toInt(16).toByte()
            }
            return Base64.encode(bytes)
        }

        internal fun buildActivePeer(m: Map<String, String>) =
            ActivePeer(
                publicKey = m["PublicKey"] ?: "",
                allowedIPs = m["AllowedIPs"],
                endpoint = m["Endpoint"],
                presharedKey = m["PresharedKey"] ?: m["PreSharedKey"],
                persistentKeepalive = m["PersistentKeepalive"]?.trim()?.takeIf { it.isNotEmpty() },
                lastHandshakeSeconds = m.getLong("LastHandshakeSeconds", "Peer"),
                lastHandshakeNanos = m.getLong("LastHandshakeNanos", "Peer"),
                txBytes = m.getLong("TxBytes", "Peer"),
                rxBytes = m.getLong("RxBytes", "Peer"),
            )

        fun generatePublicKeyFromPrivateKey(privateKeyBase64: String): String {
            val privateKey = Key.fromBase64(privateKeyBase64)
            val publicKey = Key.generatePublicKey(privateKey)
            return publicKey.toBase64()
        }
    }
}
