package com.wgtunnel.backend.system

expect class NetworkSnapshot {
    val key: String
    val hasIpv6: Boolean
    val isUsable: Boolean

    fun hasNetwork() : Boolean
}