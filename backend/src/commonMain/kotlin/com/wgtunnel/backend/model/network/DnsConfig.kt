package com.wgtunnel.backend.model.network

data class DnsConfig(
    val dnsServers: List<String> = emptyList(),
    val searchDomains: List<String> = emptyList(),
)
