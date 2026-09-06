package com.wgtunnel.parser.crypto

import com.google.crypto.tink.subtle.X25519
import java.security.SecureRandom
import java.util.Base64
import kotlin.experimental.and

class Key private constructor(private val key: ByteArray) {

    fun getBytes(): ByteArray = key.copyOf()

    fun toBase64(): String = Base64.getEncoder().encodeToString(key)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Key) return false
        return key.contentEquals(other.key)
    }

    override fun hashCode(): Int = key.contentHashCode()

    companion object {
        fun fromBase64(str: String): Key {
            val bytes = Base64.getDecoder().decode(str)
            if (bytes.size != 32) throw KeyFormatException(Format.BINARY, Type.LENGTH)
            return Key(bytes)
        }

        fun fromBytes(bytes: ByteArray): Key {
            if (bytes.size != 32) throw KeyFormatException(Format.BINARY, Type.LENGTH)
            return Key(bytes.copyOf())
        }

        fun generatePrivateKey(): Key {
            val priv = ByteArray(32)
            SecureRandom().nextBytes(priv)

            priv[0] = priv[0] and 248.toByte()
            priv[31] = (priv[31].toInt() and 127 or 64).toByte()
            return Key(priv)
        }

        fun generatePublicKey(privateKey: Key): Key {
            val pub = X25519.publicFromPrivate(privateKey.getBytes())
            return Key(pub)
        }
    }

    enum class Format(val length: Int) {
        BASE64(44),
        BINARY(32),
        HEX(64),
    }

    enum class Type {
        LENGTH,
        CONTENTS,
    }
}

class KeyFormatException : Exception {
    constructor(
        format: Key.Format,
        type: Key.Type,
    ) : super("Invalid key format: $format, type: $type")
}
