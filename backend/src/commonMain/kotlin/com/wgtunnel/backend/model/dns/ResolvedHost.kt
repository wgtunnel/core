package com.wgtunnel.backend.model.dns

import com.wgtunnel.backend.util.Host

data class ResolvedHost(val host: Host, val forcedPort: Int? = null)
