package com.wgtunnel.backend.model.dns

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * How tunnel DNS hijacking treats packets not destined for FakeDNS (foreign, plaintext DNS).
 */
@Serializable
enum class ForeignDnsPolicy {
    @SerialName("redirect") REDIRECT,
    @SerialName("block") BLOCK,
    @SerialName("allow") ALLOW,
}

/** Wire name expected by native (lowercase). */
fun ForeignDnsPolicy.toNativeValue(): String =
    when (this) {
        ForeignDnsPolicy.REDIRECT -> "redirect"
        ForeignDnsPolicy.BLOCK -> "drop"
        ForeignDnsPolicy.ALLOW -> "allow"
    }

fun foreignDnsPolicyFromStorage(value: Int): ForeignDnsPolicy =
    when (value) {
        1 -> ForeignDnsPolicy.BLOCK
        2 -> ForeignDnsPolicy.ALLOW
        else -> ForeignDnsPolicy.REDIRECT
    }

fun ForeignDnsPolicy.toStorageValue(): Int =
    when (this) {
        ForeignDnsPolicy.REDIRECT -> 0
        ForeignDnsPolicy.BLOCK -> 1
        ForeignDnsPolicy.ALLOW -> 2
    }
