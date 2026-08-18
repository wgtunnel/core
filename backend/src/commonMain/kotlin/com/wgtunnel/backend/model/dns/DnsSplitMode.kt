package com.wgtunnel.backend.model.dns

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/** Mode for how prefixes should be split. */
@Serializable
enum class DnsSplitMode {
    @SerialName("system") SYSTEM,
    @SerialName("tunnel") TUNNEL,
}
