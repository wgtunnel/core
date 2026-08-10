package com.wgtunnel.backend.util

internal actual fun <T> withSocketTag(tag: Int, block: () -> T): T = block()
