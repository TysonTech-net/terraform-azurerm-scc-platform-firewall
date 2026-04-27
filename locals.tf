###############################################################################
# Naming & Environment
###############################################################################

locals {
  environment_short = lower(replace(var.environment, " ", ""))
  workload_short    = lower(replace(var.workload, " ", ""))
  location_short    = lower(replace(var.location, " ", ""))

  # IP group naming prefix
  ip_group_prefix = "ipg-${local.workload_short}-${local.environment_short}-${local.location_short}"
}

###############################################################################
# Rule Settings (with defaults)
###############################################################################

locals {
  settings = {
    # Azure management rules
    enable_az_mgmt_rules     = coalesce(try(var.rule_settings.enable_az_mgmt_rules, null), true)
    enable_az_mgmt_app_rules = coalesce(try(var.rule_settings.enable_az_mgmt_app_rules, null), true)
    enable_ntp               = coalesce(try(var.rule_settings.enable_ntp, null), true)

    # LogicMonitor monitoring (auto-enabled when ip_groups.logicmonitor defined)
    enable_monitoring_windows = coalesce(try(var.rule_settings.enable_monitoring_windows, null), true)
    enable_monitoring_linux   = coalesce(try(var.rule_settings.enable_monitoring_linux, null), true)

    # Security monitoring (Sentinel, syslog, CEF, WEF)
    enable_security_monitoring = coalesce(try(var.rule_settings.enable_security_monitoring, null), true)

    # Internet outbound
    enable_internet_outbound = coalesce(try(var.rule_settings.enable_internet_outbound, null), false)

    # Troubleshooting
    enable_troubleshooting          = coalesce(try(var.rule_settings.enable_troubleshooting, null), false)
    enable_troubleshooting_internet = coalesce(try(var.rule_settings.enable_troubleshooting_internet, null), false)

    # Spoke/On-prem traffic
    enable_spoke_to_spoke      = coalesce(try(var.rule_settings.enable_spoke_to_spoke, null), true)
    enable_cross_region_spokes = coalesce(try(var.rule_settings.enable_cross_region_spokes, null), true)
    enable_jumpbox_access      = coalesce(try(var.rule_settings.enable_jumpbox_access, null), true)
    enable_spokes_to_on_prem   = coalesce(try(var.rule_settings.enable_spokes_to_on_prem, null), true)
    enable_icmp                = coalesce(try(var.rule_settings.enable_icmp, null), true)

    # Identity/ADDS rules
    enable_on_prem_adds     = coalesce(try(var.rule_settings.enable_on_prem_adds, null), false)
    enable_on_prem_kerberos = coalesce(try(var.rule_settings.enable_on_prem_kerberos, null), false)

    # OS updates and security tooling
    enable_edge_updates  = coalesce(try(var.rule_settings.enable_edge_updates, null), true)
    enable_linux_updates = coalesce(try(var.rule_settings.enable_linux_updates, null), true)
    enable_tenable       = coalesce(try(var.rule_settings.enable_tenable, null), false)

    # Rule collection group priorities
    # Order: DNAT(100) → Troubleshoot(200) → Identity(300) → Internet Net(400) / App(410) → Platform Net(500) / App(510) → Monitoring(600) → Custom(700-800)
    rcg_troubleshooting_priority      = coalesce(try(var.rule_settings.rcg_troubleshooting_priority, null), 200)
    rcg_identity_priority             = coalesce(try(var.rule_settings.rcg_identity_priority, null), 300)
    rcg_internet_network_priority     = coalesce(try(var.rule_settings.rcg_internet_network_priority, null), 400)
    rcg_internet_application_priority = coalesce(try(var.rule_settings.rcg_internet_application_priority, null), 410)
    rcg_platform_network_priority     = coalesce(try(var.rule_settings.rcg_platform_network_priority, null), 500)
    rcg_platform_application_priority = coalesce(try(var.rule_settings.rcg_platform_application_priority, null), 510)
    rcg_monitoring_priority           = coalesce(try(var.rule_settings.rcg_monitoring_priority, null), 600)
    rcg_custom_network_priority       = coalesce(try(var.rule_settings.rcg_custom_network_priority, null), 700)
    rcg_custom_application_priority   = coalesce(try(var.rule_settings.rcg_custom_application_priority, null), 800)
  }
}

###############################################################################
# Rule Collection Priorities
###############################################################################

locals {
  # Identity rule priorities
  p_dns              = local.settings.rcg_identity_priority + 1
  p_spokes_dns       = local.settings.rcg_identity_priority + 2 # DNS Spokes→DCs
  p_aad              = local.settings.rcg_identity_priority + 3
  p_bastion          = local.settings.rcg_identity_priority + 4
  p_spokes_adds      = local.settings.rcg_identity_priority + 5
  p_on_prem_adds     = local.settings.rcg_identity_priority + 6
  p_on_prem_kerberos = local.settings.rcg_identity_priority + 7 # Kerberos-only from on-prem
  p_replication      = local.settings.rcg_identity_priority + 8

  # Internet Network rule priorities (RCG priority 400)
  p_az_infra = local.settings.rcg_internet_network_priority + 1 # Azure Infrastructure (Wire Server, IMDS, KMS)
  p_ntp      = local.settings.rcg_internet_network_priority + 2 # NTP for all VMs
  p_lm       = local.settings.rcg_internet_network_priority + 3 # LogicMonitor Outbound IPs

  # Internet Application rule priorities (RCG priority 410)
  p_az_net            = local.settings.rcg_internet_application_priority + 1 # AzureCoreServices
  p_az_workload       = local.settings.rcg_internet_application_priority + 2 # AzureWorkloadServices
  p_az_app            = local.settings.rcg_internet_application_priority + 3 # AzureMgmtApplications
  p_lm_app            = local.settings.rcg_internet_application_priority + 4 # LogicMonitor Outbound FQDNs
  p_internet_outbound = local.settings.rcg_internet_application_priority + 5 # HTTP/HTTPS to internet
  p_edge_updates      = local.settings.rcg_internet_application_priority + 6 # Edge browser updates + SmartScreen
  p_linux_updates     = local.settings.rcg_internet_application_priority + 7 # Linux package repository access
  p_tenable_updates   = local.settings.rcg_internet_application_priority + 8 # Tenable cloud updates

  # Platform Network rule priorities (RCG priority 500)
  p_spoke_to_spoke      = local.settings.rcg_platform_network_priority + 1 # Spoke ↔ Spoke traffic
  p_security_monitoring = local.settings.rcg_platform_network_priority + 2 # Security monitoring (Sentinel, syslog, WEF)
  p_spokes_to_on_prem   = local.settings.rcg_platform_network_priority + 3
  p_on_prem_to_spokes   = local.settings.rcg_platform_network_priority + 4
  p_icmp                = local.settings.rcg_platform_network_priority + 5  # ICMP between segments
  p_cross_region_spoke  = local.settings.rcg_platform_network_priority + 6  # Cross-region spoke ↔ remote spoke
  p_cross_region_secmon = local.settings.rcg_platform_network_priority + 7  # Cross-region security monitoring
  p_tenable_scanning    = local.settings.rcg_platform_network_priority + 8  # Tenable vulnerability scanning
  p_jumpbox_access      = local.settings.rcg_platform_network_priority + 9  # Jumpbox SSH/RDP to spokes
  p_spokes_to_arm       = local.settings.rcg_platform_network_priority + 10 # Spokes → AzureResourceManager (control plane)

  # Platform Application rule priorities (RCG priority 510)
  p_spokes_to_fqdns = local.settings.rcg_platform_application_priority + 1

  # Monitoring rule priorities
  p_monitoring_general = local.settings.rcg_monitoring_priority + 0
  p_monitoring_windows = local.settings.rcg_monitoring_priority + 10
  p_monitoring_linux   = local.settings.rcg_monitoring_priority + 20

  # Troubleshooting
  p_troubleshoot_allow = local.settings.rcg_troubleshooting_priority
}

###############################################################################
# ADDS Ports (Active Directory Domain Services)
###############################################################################

locals {
  adds_ports = {
    tcp = ["53", "88", "135", "389", "445", "464", "636", "3268", "3269", "9389", "49152-65535"]
    udp = ["53", "88", "123", "389", "464"]
  }

  # Kerberos-only ports (lighter than full ADDS for on-prem auth)
  kerberos_ports = {
    tcp = ["88", "464"] # Kerberos, Kerberos password change
    udp = ["88", "464"]
  }
}

###############################################################################
# Traffic Rule Defaults
###############################################################################

locals {
  traffic_defaults = {
    spoke_to_spoke    = { ports = ["22", "80", "443", "445", "3389", "5985-5986"], protocols = ["TCP"] }
    spokes_to_on_prem = { ports = ["22", "53", "80", "443", "445", "1433", "3389", "5985-5986"], protocols = ["TCP", "UDP"] }
    on_prem_to_spokes = { ports = ["22", "53", "80", "443", "445", "1433", "3389", "5985-5986"], protocols = ["TCP", "UDP"] }
  }

  # Security monitoring ports (Sentinel, Tenable, CEF, syslog, WEF)
  security_monitoring_ports = {
    tcp_udp = ["443", "514", "1514", "5044", "5985-5986"]
    # 443  - HTTPS/Log Analytics API
    # 514  - Syslog (Tenable, CEF)
    # 1514 - Syslog TLS
    # 5044 - Beats/Logstash
    # 5985-5986 - WinRM (Windows Event Forwarding)
  }

  # Merge user overrides with defaults
  traffic = {
    spoke_to_spoke    = coalesce(try(var.traffic_rules.spoke_to_spoke, null), local.traffic_defaults.spoke_to_spoke)
    spokes_to_on_prem = coalesce(try(var.traffic_rules.spokes_to_on_prem, null), local.traffic_defaults.spokes_to_on_prem)
    on_prem_to_spokes = coalesce(try(var.traffic_rules.on_prem_to_spokes, null), local.traffic_defaults.on_prem_to_spokes)
  }
}

###############################################################################
# FQDN Tags & FQDNs
###############################################################################

locals {
  # Platform FQDN tags for application rules
  # NOTE: These must be valid Azure Firewall FQDN tags (not service tags).
  # Service tags (IP-based) go in network rule destination_addresses.
  # FQDN tags (URL-based) go in application rule destination_fqdn_tags.
  # Validated against: az network firewall list-fqdn-tags
  caf_platform_fqdn_tags = distinct(sort([
    "AppServiceEnvironment",
    "AzureBackup",
    "HDInsight",
    "MicrosoftActiveProtectionService",
    "MicrosoftIntune",
    "Windows365",
    "WindowsDiagnostics",
    "WindowsUpdate",
    "WindowsVirtualDesktop",
  ]))

  # Workload FQDN tags for application rules
  caf_workload_fqdn_tags = distinct(sort([
    "AzureKubernetesService",
    "WindowsVirtualDesktop",
  ]))

  # Office365 FQDN tags (subcategory tags required, "Office365" alone is not valid)
  caf_office365_fqdn_tags = distinct(sort([
    "Office365.Common.Allow.Required",
    "Office365.Common.Default.NotRequired",
    "Office365.Common.Default.Required",
    "Office365.Exchange.Allow.Required",
    "Office365.Exchange.Default.Required",
    "Office365.Exchange.Optimize",
    "Office365.SharePoint.Default.NotRequired",
    "Office365.SharePoint.Default.Required",
    "Office365.SharePoint.Optimize",
    "Office365.Skype.Allow.Required",
    "Office365.Skype.Default.NotRequired",
    "Office365.Skype.Default.Required",
  ]))

  # Categorized FQDNs for separate firewall rules
  fqdns_private_endpoints = sort(distinct([
    "*.privatelink.azurecr.io",
    "*.privatelink.azurewebsites.net",
    "*.privatelink.blob.core.windows.net",
    "*.privatelink.database.windows.net",
    "*.privatelink.dfs.core.windows.net",
    "*.privatelink.eventgrid.azure.net",
    "*.privatelink.file.core.windows.net",
    "*.privatelink.monitor.azure.com",
    "*.privatelink.ods.opinsights.azure.com",
    "*.privatelink.oms.opinsights.azure.com",
    "*.privatelink.queue.core.windows.net",
    "*.privatelink.servicebus.windows.net",
    "*.privatelink.table.core.windows.net",
    "*.privatelink.vaultcore.azure.net",
  ]))

  fqdns_authentication = sort(distinct([
    "*.aadcdn.msauth.net",
    "*.login.microsoft.com",
    "*.microsoftonline.com",
    "aadcdn.msauth.net",
    "login.microsoft.com",
    "login.microsoftonline.com",
  ]))

  fqdns_configuration = sort(distinct([
    "*.agentsvc.azure-automation.net",
    "*.azure-api.net",
    "*.azconfig.io",
    "*.dm.microsoft.com",
    "*.dp.kubernetesconfiguration.azure.com",
    "*.guestconfiguration.azure.com",
    "*.his.arc.azure.com",
    "*.manage.microsoft.com",
    "enterpriseregistration.windows.net",
    "graph.microsoft.com",
  ]))

  fqdns_updates_and_security = sort(distinct([
    "*.azureedge.net",
    "*.delivery.mp.microsoft.com",
    "*.download.windowsupdate.com",
    "*.endpoint.security.microsoft.com",
    "*.prod.do.dsp.mp.microsoft.com",
    "*.security.microsoft.com",
    "*.securitycenter.windows.com",
    "*.uk.endpoint.security.microsoft.com",
    "*.update.microsoft.com",
    "*.wd.microsoft.com",
    "*.wdcp.microsoft.com",
    "*.wdcpalt.microsoft.com",
    "*.windowsupdate.com",
    "crl.comodoca.com",
    "crl.microsoft.com",
    "crl.usertrust.com",
    "crl3.digicert.com",
    "crl4.digicert.com",
    "download.microsoft.com",
    "download.visualstudio.microsoft.com",
    "go.microsoft.com",
    "ipv6.msftconnecttest.com",
    "mscrl.microsoft.com",
    "ocsp.comodoca.com",
    "ocsp.digicert.com",
    "ocsp.msocsp.com",
    "ocsp.usertrust.com",
    "packages.microsoft.com",
    "time.windows.com",
    "www.msftconnecttest.com",
    "x1.c.lencr.org",
  ]))

  fqdns_storage = sort(distinct([
    "*.blob.core.windows.net",
    "*.blob.storage.azure.net", # Managed disk metadata (md-*.z*.blob.storage.azure.net)
    "*.dfs.core.windows.net",
    "*.documents.azure.com",
    "*.file.core.windows.net",
    "*.queue.core.windows.net",
    "*.table.core.windows.net",
  ]))

  fqdns_monitoring = sort(distinct([
    "*.azure-automation.net",
    "*.azurefd.net", # Microsoft Edge CDN (e.g. edgecdn-* hosts)
    "*.data.microsoft.com",
    "*.events.data.microsoft.com",
    "*.handler.control.monitor.azure.com",
    "*.monitoring.azure.com",
    "*.ods.opinsights.azure.com",
    "*.oms.opinsights.azure.com",
    "aefd.nelreports.net", # Microsoft Network Error Logging (NEL)
    "arc.msn.com",         # Microsoft browser/Edge homepage feed
    "global.handler.control.monitor.azure.com",
    "ntp.msn.com", # Microsoft NTP-as-HTTPS check
    "r.bing.com",  # Bing browser asset / web GUI dependency
    "settings-win.data.microsoft.com",
    "th.bing.com",
    "thf.bing.com",
  ]))

  fqdns_development = sort(distinct([
    "*.azurecr.io",
    "*.data.mcr.microsoft.com",
    "*.dev.azure.com",
    "*.github.com",
    "*.githubusercontent.com",
    "*.gitlab.com",
    "*.nuget.org",
    "*.powershellgallery.com",
    "*.visualstudio.com",
    "api.github.com",
    "github.com",
    "gitlab.com",
    "mcr.microsoft.com",
    "psg-prod-eastus.azureedge.net",
    "raw.githubusercontent.com",
  ]))

  fqdns_servicebus = sort(distinct([
    "*.servicebus.windows.net",
  ]))

  fqdns_keyvault = sort(distinct([
    "*.vault.azure.net",
  ]))

  fqdns_database = sort(distinct([
    "*.database.windows.net",
  ]))

  # Microsoft Defender for SQL on Azure Arc-enabled SQL hosts.
  # Arc agent + Defender data plane talk to *.arcdataservices.com regional endpoints.
  fqdns_arcdata = sort(distinct([
    "*.arcdataservices.com",
  ]))

  # Common browser web assets (Google fonts, Chrome update, gstatic).
  # These show up from any host running a browser-based admin UI.
  fqdns_browser_google = sort(distinct([
    "clients2.google.com",
    "fonts.googleapis.com",
    "*.gstatic.com",
  ]))

  # Azure Site Recovery FQDNs (required for A2A replication)
  # These are explicit FQDNs in case the AzureSiteRecovery FQDN tag doesn't cover all endpoints
  # Reference: https://learn.microsoft.com/en-us/azure/site-recovery/azure-to-azure-about-networking
  fqdns_site_recovery = sort(distinct([
    "*.hypervrecoverymanager.windowsazure.com", # Site Recovery service communication
    "*.attest.azure.net",                       # Azure Attestation (required for Trusted Launch VMs with ASR)
  ]))

  # FQDNs for spoke segments
  spokes_allowed_fqdns = sort(distinct(tolist(var.spokes_allowed_fqdns)))
}

###############################################################################
# Troubleshooting
###############################################################################

locals {
  troubleshooting_default_cidrs = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
  troubleshooting_destination_cidrs = local.settings.enable_troubleshooting ? (
    length(var.troubleshooting_destination_cidrs) > 0
    ? sort(distinct(tolist(var.troubleshooting_destination_cidrs)))
    : local.troubleshooting_default_cidrs
  ) : []
}

###############################################################################
# LogicMonitor
###############################################################################

locals {
  logicmonitor_address_pattern = "^(\\d{1,3}\\.){3}\\d{1,3}(/\\d{1,2})?$"
  logicmonitor_destinations = {
    addresses = distinct(sort([
      for destination in var.logicmonitor_platform :
      destination
      if can(regex(local.logicmonitor_address_pattern, destination))
    ]))
    fqdns = distinct(sort([
      for destination in var.logicmonitor_platform :
      destination
      if !can(regex(local.logicmonitor_address_pattern, destination))
    ]))
  }
}

###############################################################################
# Diagnostics
###############################################################################

locals {
  diagnostics_enabled = coalesce(try(var.diagnostics.enabled, null), false)
  diagnostics_logs = local.diagnostics_enabled ? (try(var.diagnostics.logs, null) != null
    ? sort(distinct(tolist(var.diagnostics.logs)))
    : [
      "AzureFirewallApplicationRule",
      "AzureFirewallNetworkRule",
      "AzureFirewallDnsProxy",
      "AzureFirewallNatRule",
  ]) : []

  diagnostics_metrics = local.diagnostics_enabled ? (try(var.diagnostics.metrics, null) != null
    ? sort(distinct(tolist(var.diagnostics.metrics)))
  : ["AllMetrics"]) : []

  diagnostics_destinations = {
    log_analytics_workspace_id     = try(var.diagnostics.log_analytics_workspace_id, null)
    storage_account_id             = try(var.diagnostics.storage_account_id, null)
    eventhub_authorization_rule_id = try(var.diagnostics.eventhub_authorization_rule_id, null)
    eventhub_name                  = try(var.diagnostics.eventhub_name, null)
  }

  diagnostics_has_destination = local.diagnostics_enabled && anytrue([
    local.diagnostics_destinations.log_analytics_workspace_id != null,
    local.diagnostics_destinations.storage_account_id != null,
    local.diagnostics_destinations.eventhub_authorization_rule_id != null,
  ])

  diagnostics_configuration = local.diagnostics_enabled && local.diagnostics_has_destination ? {
    logs         = local.diagnostics_logs
    metrics      = local.diagnostics_metrics
    destinations = local.diagnostics_destinations
  } : null
}
