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
