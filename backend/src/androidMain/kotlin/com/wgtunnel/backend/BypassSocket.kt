package com.wgtunnel.backend

import androidx.annotation.Keep

@Keep
internal object BypassSocket {
    @JvmStatic external fun setSocketProtector(sp: SocketProtector?)
}
