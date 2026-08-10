package com.wgtunnel.backend

import androidx.annotation.Keep
import com.wgtunnel.backend.SocketProtector

@Keep
internal object BypassSocket {
    @JvmStatic
    external fun setSocketProtector(sp: SocketProtector?)
}