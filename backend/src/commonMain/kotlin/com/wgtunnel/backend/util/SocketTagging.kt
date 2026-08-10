package com.wgtunnel.backend.util

internal expect fun <T> withSocketTag(tag: Int, block: () -> T): T