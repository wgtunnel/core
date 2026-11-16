package com.wgtunnel.backend

/**
 * Installs or clears the Android strict split-tunnel filter.
 *
 * [enabled] with an empty include and exclude list clears the filter. The lists are the
 * tunnel's normal IncludedApplications and ExcludedApplications. Desktop is a no-op. Below
 * Android 10 the filter stays unset.
 */
internal expect fun applyStrictSplit(
    enabled: Boolean,
    included: List<String>,
    excluded: List<String>,
)
