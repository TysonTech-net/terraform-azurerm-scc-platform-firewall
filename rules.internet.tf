###############################################################################
# Internet Network Rule Collection Group
# Network-level rules: Azure infrastructure, NTP, LogicMonitor IPs
###############################################################################

resource "azurerm_firewall_policy_rule_collection_group" "rcg_internet" {
  name               = "Default_Internet_Network_Rules"
  priority           = local.settings.rcg_internet_network_priority
  firewall_policy_id = var.firewall_policy_id

  depends_on = [azurerm_ip_group.this]

  lifecycle {
    precondition {
      condition     = var.firewall_policy_id != null && var.firewall_policy_id != ""
      error_message = "firewall_policy_id is required to create rule collection groups."
    }
  }

  #############################################################################
  # Azure Infrastructure - Critical internal Azure services
  # Wire Server (168.63.129.16): VM extensions, DHCP, DNS, health probes
  # IMDS (169.254.169.254): Managed Identity, instance metadata
  # KMS: Windows activation (port 1688)
  #############################################################################

  dynamic "network_rule_collection" {
    for_each = local.settings.enable_az_mgmt_rules ? [1] : []
    content {
      name     = "Azure_Infrastructure"
      priority = local.p_az_infra
      action   = "Allow"

      # Azure Wire Server - Required for VM Agent, extensions, DHCP, DNS
      rule {
        name                  = "Azure_Wire_Server"
        source_addresses      = ["*"]
        destination_ports     = ["80", "443", "32526"]
        protocols             = ["TCP"]
        destination_addresses = ["168.63.129.16"]
      }

      # Azure Instance Metadata Service (IMDS) - Required for Managed Identity
      rule {
        name                  = "Azure_IMDS"
        source_addresses      = ["*"]
        destination_ports     = ["80"]
        protocols             = ["TCP"]
        destination_addresses = ["169.254.169.254"]
      }

      # Azure KMS - Windows Activation
      rule {
        name              = "Azure_KMS_Activation"
        source_addresses  = ["*"]
        destination_ports = ["1688"]
        protocols         = ["TCP"]
        destination_fqdns = ["kms.core.windows.net", "azkms.core.windows.net"]
      }
    }
  }

  #############################################################################
  # NTP - Time synchronization for all VMs (optional)
  #############################################################################

  dynamic "network_rule_collection" {
    for_each = local.settings.enable_ntp ? [1] : []
    content {
      name     = "Outbound_NTP"
      priority = local.p_ntp
      action   = "Allow"
      rule {
        name                  = "All_to_NTP"
        source_addresses      = ["*"]
        destination_ports     = ["123"]
        protocols             = ["UDP"]
        destination_addresses = ["*"]
      }
    }
  }

  #############################################################################
  # LogicMonitor Outbound IPs (auto-enabled when collectors defined)
  #############################################################################

  dynamic "network_rule_collection" {
    for_each = local.has_logicmonitor && length(local.logicmonitor_destinations.addresses) > 0 ? [1] : []
    content {
      name     = "LogicMonitor_Outbound_IPs"
      priority = local.p_lm
      action   = "Allow"
      rule {
        name                  = "LogicMonitor_Platform_IPs"
        source_addresses      = ["*"]
        destination_addresses = local.logicmonitor_destinations.addresses
        destination_ports     = ["443"]
        protocols             = ["TCP"]
      }
    }
  }

  #############################################################################
  # Nerdio Manager (NME) outbound (optional, default off) - service-tag based.
  # NME's control plane talks to Azure App Service (its web app + licensing),
  # Entra ID, ARM and Azure Monitor; control DB is Azure SQL. Service tags replace
  # hand-maintained FQDN/IP lists. Source-scoped to ip_groups.nerdio.
  #############################################################################

  dynamic "network_rule_collection" {
    for_each = local.has_nerdio_rules ? [1] : []
    content {
      name     = "Nerdio_Outbound"
      priority = local.p_nerdio_net
      action   = "Allow"
      rule {
        name                  = "Nerdio_Azure_Services"
        source_ip_groups      = [local.ip_group_ids.nerdio]
        destination_addresses = ["AppService", "AzureActiveDirectory", "AzureResourceManager", "AzureMonitor"]
        destination_ports     = ["443"]
        protocols             = ["TCP"]
      }
      rule {
        name                  = "Nerdio_Azure_SQL"
        source_ip_groups      = [local.ip_group_ids.nerdio]
        destination_addresses = ["Sql"] # service tag - Azure SQL
        destination_ports     = ["1433", "11000-11999"]
        protocols             = ["TCP"]
      }
    }
  }

  #############################################################################
  # AVD non-HTTPS network flows (optional) - RDP Shortpath relay (WindowsVirtualDesktop
  # service tag, UDP 3478-3481 STUN/TURN), Teams media (UDP), Exchange mail ports.
  # HTTPS service traffic is the AVD_Outbound application rule.
  #############################################################################

  dynamic "network_rule_collection" {
    for_each = local.has_avd_rules ? [1] : []
    content {
      name     = "AVD_M365_Network"
      priority = local.p_avd_net
      action   = "Allow"
      # RDP Shortpath for public networks: STUN/TURN relay to the WindowsVirtualDesktop
      # service tag (51.5.0.0/16) over UDP 3478-3481. If blocked, sessions fall back to
      # TCP relay (the WindowsVirtualDesktop FQDN tag in the app rule) - so this is a
      # latency/quality rule, not a hard dependency.
      rule {
        name                  = "RDP_Shortpath_Relay"
        source_ip_groups      = [local.ip_group_ids.avd]
        destination_addresses = ["WindowsVirtualDesktop"]
        destination_ports     = ["3478", "3479", "3480", "3481"]
        protocols             = ["UDP"]
      }
      # Microsoft 365 granular service tags (Azure Firewall's built-in O365 integration,
      # auto-updated from the O365 endpoints API). The bare "Office365" tag is NOT valid,
      # but the granular Office365.<product>.<category> tags are (selectable in the portal
      # network-rule UI). Resolve to IPv4 only - avoids the IPv6-literal rejection that a
      # hand-maintained CIDR list hits (FirewallPolicyRuleIpv6AddressNotAllowed).
      rule {
        name                  = "Teams_Media_UDP"
        source_ip_groups      = [local.ip_group_ids.avd]
        destination_addresses = ["Office365.Skype.Optimize"] # Teams/Skype real-time media
        destination_ports     = ["3478", "3479", "3480", "3481"]
        protocols             = ["UDP"]
      }
      rule {
        name                  = "Exchange_Mail"
        source_ip_groups      = [local.ip_group_ids.avd]
        destination_addresses = ["Office365.Exchange.Allow.Required"] # Exchange Online
        destination_ports     = ["25", "143", "587", "993", "995"]
        protocols             = ["TCP"]
      }
    }
  }
}

###############################################################################
# Internet Application Rule Collection Group
# Application-level rules: Azure services, LogicMonitor FQDNs, internet
# IMPORTANT: Includes AzureSiteRecovery FQDN tag for ASR replication!
###############################################################################

resource "azurerm_firewall_policy_rule_collection_group" "rcg_internet_application" {
  name               = "Default_Internet_Application_Rules"
  priority           = local.settings.rcg_internet_application_priority
  firewall_policy_id = var.firewall_policy_id

  depends_on = [azurerm_ip_group.this]

  lifecycle {
    precondition {
      condition     = var.firewall_policy_id != null && var.firewall_policy_id != ""
      error_message = "firewall_policy_id is required to create rule collection groups."
    }
  }

  #############################################################################
  # Azure Core Services (includes AzureSiteRecovery!)
  # Split into categorized rules for better visibility and management
  #############################################################################

  dynamic "application_rule_collection" {
    for_each = local.settings.enable_az_mgmt_rules ? [1] : []
    content {
      name     = "AzureCoreServices"
      priority = local.p_az_net
      action   = "Allow"

      # Azure FQDN Tags (validated against az network firewall list-fqdn-tags)
      rule {
        name                  = "AzureCoreFQDNTags"
        source_addresses      = ["*"]
        destination_fqdn_tags = local.caf_platform_fqdn_tags
        protocols {
          type = "Https"
          port = 443
        }
      }

      # Authentication - Entra ID / Azure AD
      rule {
        name              = "Authentication"
        source_addresses  = ["*"]
        destination_fqdns = local.fqdns_authentication
        protocols {
          type = "Https"
          port = 443
        }
      }

      # Private Endpoints - Private Link DNS zones
      rule {
        name              = "PrivateEndpoints"
        source_addresses  = ["*"]
        destination_fqdns = local.fqdns_private_endpoints
        protocols {
          type = "Https"
          port = 443
        }
      }

      # Configuration - Guest Config, Arc, Automation
      rule {
        name              = "Configuration"
        source_addresses  = ["*"]
        destination_fqdns = local.fqdns_configuration
        protocols {
          type = "Https"
          port = 443
        }
      }

      # Updates and Security - Windows Update, Defender, CRL/OCSP
      rule {
        name              = "UpdatesAndSecurity"
        source_addresses  = ["*"]
        destination_fqdns = local.fqdns_updates_and_security
        protocols {
          type = "Https"
          port = 443
        }
      }

      # Storage - Blob, File, Table, Queue, DFS
      rule {
        name              = "Storage"
        source_addresses  = ["*"]
        destination_fqdns = local.fqdns_storage
        protocols {
          type = "Https"
          port = 443
        }
      }

      # Monitoring - Log Analytics, Azure Monitor
      rule {
        name              = "Monitoring"
        source_addresses  = ["*"]
        destination_fqdns = local.fqdns_monitoring
        protocols {
          type = "Https"
          port = 443
        }
      }

      # Development - GitHub, GitLab, Azure DevOps
      rule {
        name              = "Development"
        source_addresses  = ["*"]
        destination_fqdns = local.fqdns_development
        protocols {
          type = "Https"
          port = 443
        }
      }

      # Service Bus
      rule {
        name              = "ServiceBus"
        source_addresses  = ["*"]
        destination_fqdns = local.fqdns_servicebus
        protocols {
          type = "Https"
          port = 443
        }
      }

      # Key Vault
      rule {
        name              = "KeyVault"
        source_addresses  = ["*"]
        destination_fqdns = local.fqdns_keyvault
        protocols {
          type = "Https"
          port = 443
        }
      }

      # Database - Azure SQL
      rule {
        name              = "Database"
        source_addresses  = ["*"]
        destination_fqdns = local.fqdns_database
        protocols {
          type = "Https"
          port = 443
        }
      }

      # Microsoft Defender for SQL on Arc-enabled SQL hosts
      rule {
        name              = "ArcDatabaseDefender"
        source_addresses  = ["*"]
        destination_fqdns = local.fqdns_arcdata
        protocols {
          type = "Https"
          port = 443
        }
      }

      # Common browser web assets (Google fonts, Chrome update checks, gstatic)
      rule {
        name              = "BrowserGoogle"
        source_addresses  = ["*"]
        destination_fqdns = local.fqdns_browser_google
        protocols {
          type = "Https"
          port = 443
        }
      }

      # Site Recovery - Explicit FQDNs for A2A replication
      # Required in addition to AzureSiteRecovery FQDN tag
      rule {
        name              = "SiteRecovery"
        source_addresses  = ["*"]
        destination_fqdns = local.fqdns_site_recovery
        protocols {
          type = "Https"
          port = 443
        }
      }
    }
  }

  #############################################################################
  # Azure Workload Services
  #############################################################################

  application_rule_collection {
    name     = "AzureWorkloadServices"
    priority = local.p_az_workload
    action   = "Allow"

    rule {
      name                  = "AzureWorkloadTags"
      source_addresses      = ["*"]
      destination_fqdn_tags = local.caf_workload_fqdn_tags
      protocols {
        type = "Https"
        port = 443
      }
    }
  }

  #############################################################################
  # Azure Management Applications (optional)
  #############################################################################

  dynamic "application_rule_collection" {
    for_each = local.settings.enable_az_mgmt_app_rules ? [1] : []
    content {
      name     = "AzureMgmtApplications"
      priority = local.p_az_app
      action   = "Allow"

      rule {
        name                  = "AppServiceEnvironment"
        source_addresses      = ["*"]
        destination_fqdn_tags = ["AppServiceEnvironment"]
        protocols {
          type = "Https"
          port = 443
        }
      }
      rule {
        name              = "AzureAutomation"
        source_addresses  = ["*"]
        destination_fqdns = ["*.azure-automation.net", "*.agentsvc.azure-automation.net"]
        protocols {
          type = "Https"
          port = 443
        }
      }
      rule {
        name                  = "AzureKubernetesService"
        source_addresses      = ["*"]
        destination_fqdn_tags = ["AzureKubernetesService"]
        protocols {
          type = "Https"
          port = 443
        }
      }
      rule {
        name                  = "WindowsUpdate"
        source_addresses      = ["*"]
        destination_fqdn_tags = ["WindowsUpdate"]
        protocols {
          type = "Https"
          port = 443
        }
      }
      rule {
        name                  = "Office365Common"
        source_addresses      = ["*"]
        destination_fqdn_tags = local.caf_office365_fqdn_tags
        protocols {
          type = "Https"
          port = 443
        }
      }
      rule {
        name                  = "MicrosoftIntune"
        source_addresses      = ["*"]
        destination_fqdn_tags = ["MicrosoftIntune"]
        protocols {
          type = "Https"
          port = 443
        }
      }
    }
  }

  #############################################################################
  # LogicMonitor Outbound FQDNs (auto-enabled when collectors defined)
  #############################################################################

  dynamic "application_rule_collection" {
    for_each = local.has_logicmonitor && length(local.logicmonitor_destinations.fqdns) > 0 ? [1] : []
    content {
      name     = "LogicMonitor_Outbound_FQDNs"
      priority = local.p_lm_app
      action   = "Allow"
      rule {
        name              = "LogicMonitor_Platform_FQDNs"
        source_addresses  = ["*"]
        destination_fqdns = local.logicmonitor_destinations.fqdns
        protocols {
          type = "Https"
          port = 443
        }
      }
    }
  }

  #############################################################################
  # Internet Outbound (optional) - Allow HTTP/HTTPS to internet
  #############################################################################

  dynamic "application_rule_collection" {
    for_each = local.settings.enable_internet_outbound ? [1] : []
    content {
      name     = "Internet_Outbound"
      priority = local.p_internet_outbound
      action   = "Allow"

      rule {
        name              = "Allow_HTTP"
        source_addresses  = ["*"]
        destination_fqdns = ["*"]
        protocols {
          type = "Http"
          port = 80
        }
      }

      rule {
        name              = "Allow_HTTPS"
        source_addresses  = ["*"]
        destination_fqdns = ["*"]
        protocols {
          type = "Https"
          port = 443
        }
      }
    }
  }

  #############################################################################
  # Edge Updates + SmartScreen (optional, default on)
  #############################################################################

  dynamic "application_rule_collection" {
    for_each = local.settings.enable_edge_updates ? [1] : []
    content {
      name     = "Edge_Updates"
      priority = local.p_edge_updates
      action   = "Allow"

      rule {
        name              = "EdgeUpdatesAndSmartScreen"
        source_addresses  = ["*"]
        destination_fqdns = sort(distinct(tolist(var.edge_update_fqdns)))
        protocols {
          type = "Https"
          port = 443
        }
      }
    }
  }

  #############################################################################
  # Linux Package Updates (optional, default on)
  #############################################################################

  dynamic "application_rule_collection" {
    for_each = local.settings.enable_linux_updates ? [1] : []
    content {
      name     = "Linux_Updates"
      priority = local.p_linux_updates
      action   = "Allow"

      rule {
        name              = "LinuxPackageUpdates"
        source_addresses  = ["*"]
        destination_fqdns = sort(distinct(tolist(var.linux_update_fqdns)))
        protocols {
          type = "Https"
          port = 443
        }
        protocols {
          type = "Http"
          port = 80
        }
      }
    }
  }

  #############################################################################
  # Tenable Cloud Updates (optional, default off)
  # Requires enable_tenable = true and tenable scanner CIDRs defined
  #############################################################################

  dynamic "application_rule_collection" {
    for_each = local.has_tenable && local.settings.enable_tenable ? [1] : []
    content {
      name     = "Tenable_Updates"
      priority = local.p_tenable_updates
      action   = "Allow"

      rule {
        name              = "TenableCloudUpdates"
        source_ip_groups  = [local.ip_group_ids.tenable_scanners]
        destination_fqdns = sort(distinct(tolist(var.tenable_platform)))
        protocols {
          type = "Https"
          port = 443
        }
      }
    }
  }

  #############################################################################
  # Nerdio Manager (NME) outbound FQDNs (optional, default off)
  # NME's named application endpoints (licensing, extensions, App Insights, NME
  # web app, Graph/ARM/AAD). The Azure DB + broad platform are the Nerdio_Outbound
  # network rule (service tags) in the Internet Network RCG; these are the explicit
  # Nerdio URLs by name. Source-scoped to ip_groups.nerdio.
  #############################################################################

  dynamic "application_rule_collection" {
    for_each = local.has_nerdio_rules ? [1] : []
    content {
      name     = "Nerdio_Outbound_FQDNs"
      priority = local.p_nerdio
      action   = "Allow"

      rule {
        name              = "NerdioManagerEgress"
        source_ip_groups  = [local.ip_group_ids.nerdio]
        destination_fqdns = sort(distinct(tolist(var.nerdio_fqdns)))
        protocols {
          type = "Https"
          port = 443
        }
      }
    }
  }

  #############################################################################
  # AVD session-host + M365 outbound (optional, default off)
  # Standard egress for any AVD deployment. Source-scoped to ip_groups.avd.
  # WVD service traffic + Office365 come from FQDN tags; avd_session_host_fqdns
  # adds the platform/agent endpoints not in those tags. Teams media (UDP) +
  # Exchange mail ports are the AVD_M365_Network rule in the Internet Network RCG.
  #############################################################################

  dynamic "application_rule_collection" {
    for_each = local.has_avd_rules ? [1] : []
    content {
      name     = "AVD_Outbound"
      priority = local.p_avd
      action   = "Allow"

      # AVD service traffic (*.wvd.microsoft.com, agent, broker, etc.)
      rule {
        name                  = "AVD_Service_Traffic"
        source_ip_groups      = [local.ip_group_ids.avd]
        destination_fqdn_tags = ["WindowsVirtualDesktop"]
        protocols {
          type = "Https"
          port = 443
        }
      }

      # Microsoft 365 (Exchange/SharePoint/Teams/Common) over HTTPS
      rule {
        name                  = "AVD_M365"
        source_ip_groups      = [local.ip_group_ids.avd]
        destination_fqdn_tags = local.caf_office365_fqdn_tags
        protocols {
          type = "Https"
          port = 443
        }
      }

      # Session-host platform/agent FQDNs not covered by the tags (HTTPS + HTTP for certs)
      rule {
        name              = "AVD_Session_Host_FQDNs"
        source_ip_groups  = [local.ip_group_ids.avd]
        destination_fqdns = sort(distinct(tolist(var.avd_extra_fqdns)))
        protocols {
          type = "Https"
          port = 443
        }
        protocols {
          type = "Http"
          port = 80
        }
      }
    }
  }
}

###############################################################################
# Troubleshooting Rule Collection Group (optional)
# Temporary allow-all for debugging connectivity issues
###############################################################################

resource "azurerm_firewall_policy_rule_collection_group" "rcg_troubleshooting" {
  count              = local.settings.enable_troubleshooting ? 1 : 0
  name               = "Default_Troubleshooting_Allow_All"
  priority           = local.settings.rcg_troubleshooting_priority
  firewall_policy_id = var.firewall_policy_id

  depends_on = [azurerm_ip_group.this]

  lifecycle {
    precondition {
      condition     = var.firewall_policy_id != null && var.firewall_policy_id != ""
      error_message = "firewall_policy_id is required to create rule collection groups."
    }
  }

  network_rule_collection {
    name     = "Troubleshooting_Allow_Private"
    priority = local.p_troubleshoot_allow
    action   = "Allow"
    rule {
      name                  = "Troubleshooting_Allow_All_Private"
      source_addresses      = ["*"]
      destination_ports     = ["*"]
      protocols             = ["Any"]
      destination_addresses = local.troubleshooting_destination_cidrs
    }
    dynamic "rule" {
      for_each = local.settings.enable_troubleshooting_internet ? [1] : []
      content {
        name                  = "Troubleshooting_Allow_All_Internet"
        source_addresses      = ["*"]
        destination_ports     = ["*"]
        protocols             = ["Any"]
        destination_addresses = ["*"]
      }
    }
  }
}
