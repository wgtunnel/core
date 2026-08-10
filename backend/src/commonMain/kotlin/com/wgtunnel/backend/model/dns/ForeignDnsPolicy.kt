package com.wgtunnel.backend.model.dns

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
enum class ForeignDnsPolicy {
    @SerialName("redirect") REDIRECT,
    @SerialName("drop") DROP,
    @SerialName("allow") ALLOW,
}
