###############################################################################
# Platform Network Rule Collection Group
# Network-level rules: spoke-to-spoke, on-prem, ICMP, cross-region, security
###############################################################################

resource "azurerm_firewall_policy_rule_collection_group" "rcg_spokes_on_prem" {
  count = (
    local.has_spoke_to_spoke_rules ||
    local.has_cross_region_spoke_rules ||
    local.has_spokes_to_on_prem_rules ||
    local.has_on_prem_to_spokes_rules ||
    local.has_tenable_scanning_rules ||
    local.has_jumpbox_rules
  ) ? 1 : 0

  name               = "Default_Platform_Network_Rules"
  priority           = local.settings.rcg_platform_network_priority
  firewall_policy_id = var.firewall_policy_id

  depends_on = [azurerm_ip_group.this]

  lifecycle {
    precondition {
      condition     = var.firewall_policy_id != null && var.firewall_policy_id != ""
      error_message = "firewall_policy_id is required to create rule collection groups."
    }
  }

  #############################################################################
  # Spoke to Spoke (management access, cross-spoke apps)
  # Default ports: SSH, HTTP, HTTPS, SMB, RDP, WinRM
  #############################################################################

  dynamic "network_rule_collection" {
    for_each = local.has_spoke_to_spoke_rules ? [1] : []
    content {
      name     = "Spoke_to_Spoke"
      priority = local.p_spoke_to_spoke
      action   = "Allow"
      rule {
        name                  = "SpokeToSpoke"
        source_ip_groups      = [local.ip_group_ids.spokes]
        destination_ip_groups = [local.ip_group_ids.spokes]
        destination_ports     = local.traffic.spoke_to_spoke.ports
        protocols             = local.traffic.spoke_to_spoke.protocols
      }
    }
  }

  #############################################################################
  # Jumpbox Access (SSH + RDP from management jumpboxes to all spokes)
  # Ports: 22 (SSH), 3389 (RDP)
  #############################################################################

  dynamic "network_rule_collection" {
    for_each = local.has_jumpbox_rules ? [1] : []
    content {
      name     = "Jumpbox_Access"
      priority = local.p_jumpbox_access
      action   = "Allow"
      rule {
        name                  = "JumpboxToSpokes"
        source_ip_groups      = [local.ip_group_ids.jumpboxes]
        destination_ip_groups = [local.ip_group_ids.spokes]
        destination_ports     = ["22", "3389"]
        protocols             = ["TCP"]
      }
    }
  }

  #############################################################################
  # Security Monitoring (Sentinel, Tenable, CEF, syslog, WEF)
  # Allows security subscription to collect logs from all spokes
  # Ports: 443 (HTTPS), 514/1514 (syslog), 5044 (Beats), 5985-5986 (WinRM)
  #############################################################################

  dynamic "network_rule_collection" {
    for_each = local.settings.enable_security_monitoring && local.has_spokes ? [1] : []
    content {
      name     = "Security_Monitoring"
      priority = local.p_security_monitoring
      action   = "Allow"
      rule {
        name                  = "SecurityMonitoring"
        source_ip_groups      = [local.ip_group_ids.spokes]
        destination_ip_groups = [local.ip_group_ids.spokes]
        destination_ports     = local.security_monitoring_ports.tcp_udp
        protocols             = ["TCP", "UDP"]
      }
    }
  }

  #############################################################################
  # Spokes to On-Prem
  #############################################################################

  dynamic "network_rule_collection" {
    for_each = local.has_spokes_to_on_prem_rules ? [1] : []
    content {
      name     = "Spokes_to_OnPrem"
      priority = local.p_spokes_to_on_prem
      action   = "Allow"
      rule {
        name                  = "SpokesToOnPrem"
        source_ip_groups      = [local.ip_group_ids.spokes]
        destination_ip_groups = [local.ip_group_ids.on_prem]
        destination_ports     = local.traffic.spokes_to_on_prem.ports
        protocols             = local.traffic.spokes_to_on_prem.protocols
      }
    }
  }

  #############################################################################
  # On-Prem to Spokes
  #############################################################################

  dynamic "network_rule_collection" {
    for_each = local.has_on_prem_to_spokes_rules ? [1] : []
    content {
      name     = "OnPrem_to_Spokes"
      priority = local.p_on_prem_to_spokes
      action   = "Allow"
      rule {
        name                  = "OnPremToSpokes"
        source_ip_groups      = [local.ip_group_ids.on_prem]
        destination_ip_groups = [local.ip_group_ids.spokes]
        destination_ports     = local.traffic.on_prem_to_spokes.ports
        protocols             = local.traffic.on_prem_to_spokes.protocols
      }
    }
  }

  #############################################################################
  # Cross-Region Spoke to Spoke (optional - when remote_spokes defined)
  # Same TCP ports as spoke-to-spoke: SSH, HTTP, HTTPS, SMB, RDP, WinRM
  #############################################################################

  dynamic "network_rule_collection" {
    for_each = local.has_cross_region_spoke_rules ? [1] : []
    content {
      name     = "Cross_Region_Spoke_to_Spoke"
      priority = local.p_cross_region_spoke
      action   = "Allow"
      rule {
        name                  = "SpokesToRemoteSpokes"
        source_ip_groups      = [local.ip_group_ids.spokes]
        destination_ip_groups = [local.ip_group_ids.remote_spokes]
        destination_ports     = local.traffic.spoke_to_spoke.ports
        protocols             = local.traffic.spoke_to_spoke.protocols
      }
      rule {
        name                  = "RemoteSpokesToSpokes"
        source_ip_groups      = [local.ip_group_ids.remote_spokes]
        destination_ip_groups = [local.ip_group_ids.spokes]
        destination_ports     = local.traffic.spoke_to_spoke.ports
        protocols             = local.traffic.spoke_to_spoke.protocols
      }
    }
  }

  #############################################################################
  # Cross-Region Security Monitoring (optional - when remote_spokes defined)
  # Same TCP/UDP ports as security monitoring: HTTPS, syslog, Beats, WinRM
  #############################################################################

  dynamic "network_rule_collection" {
    for_each = local.has_cross_region_spoke_rules && local.settings.enable_security_monitoring ? [1] : []
    content {
      name     = "Cross_Region_Security_Monitoring"
      priority = local.p_cross_region_secmon
      action   = "Allow"
      rule {
        name                  = "CrossRegionSecurityMonitoring"
        source_ip_groups      = [local.ip_group_ids.spokes, local.ip_group_ids.remote_spokes]
        destination_ip_groups = [local.ip_group_ids.spokes, local.ip_group_ids.remote_spokes]
        destination_ports     = local.security_monitoring_ports.tcp_udp
        protocols             = ["TCP", "UDP"]
      }
    }
  }

  #############################################################################
  # Tenable Vulnerability Scanning (optional, default off)
  # Scanner → Spokes: NetBIOS (TCP 139) for authenticated scanning
  # Spokes → Scanner: Management UI (TCP 8000, 8090)
  #############################################################################

  dynamic "network_rule_collection" {
    for_each = local.has_tenable_scanning_rules ? [1] : []
    content {
      name     = "Tenable_Scanning"
      priority = local.p_tenable_scanning
      action   = "Allow"

      rule {
        name                  = "Tenable_to_Spokes_NetBIOS"
        source_ip_groups      = [local.ip_group_ids.tenable_scanners]
        destination_ip_groups = [local.ip_group_ids.spokes]
        destination_ports     = ["139"]
        protocols             = ["TCP"]
      }

      rule {
        name                  = "Spokes_to_Tenable_Management"
        source_ip_groups      = [local.ip_group_ids.spokes]
        destination_ip_groups = [local.ip_group_ids.tenable_scanners]
        destination_ports     = ["8000", "8090"]
        protocols             = ["TCP"]
      }
    }
  }

  #############################################################################
  # ICMP Between All Segments (optional - for troubleshooting/monitoring)
  #############################################################################

  dynamic "network_rule_collection" {
    for_each = local.settings.enable_icmp && (local.has_spokes || local.has_on_prem) ? [1] : []
    content {
      name     = "ICMP_Between_Segments"
      priority = local.p_icmp
      action   = "Allow"

      # Spokes ↔ On-Prem ICMP (if both exist)
      dynamic "rule" {
        for_each = local.has_spokes && local.has_on_prem ? [1] : []
        content {
          name                  = "ICMP_Spokes_OnPrem"
          source_ip_groups      = [local.ip_group_ids.spokes, local.ip_group_ids.on_prem]
          destination_ports     = ["*"]
          protocols             = ["ICMP"]
          destination_ip_groups = [local.ip_group_ids.spokes, local.ip_group_ids.on_prem]
        }
      }

      # Spokes ↔ DCs ICMP (if spokes exist)
      dynamic "rule" {
        for_each = local.has_spokes ? [1] : []
        content {
          name                  = "ICMP_Spokes_DCs"
          source_ip_groups      = [local.ip_group_ids.spokes, local.ip_group_ids.identity_dcs]
          destination_ports     = ["*"]
          protocols             = ["ICMP"]
          destination_ip_groups = [local.ip_group_ids.spokes, local.ip_group_ids.identity_dcs]
        }
      }

      # On-Prem ↔ DCs ICMP (if on-prem exists)
      dynamic "rule" {
        for_each = local.has_on_prem ? [1] : []
        content {
          name                  = "ICMP_OnPrem_DCs"
          source_ip_groups      = [local.ip_group_ids.on_prem, local.ip_group_ids.identity_dcs]
          destination_ports     = ["*"]
          protocols             = ["ICMP"]
          destination_ip_groups = [local.ip_group_ids.on_prem, local.ip_group_ids.identity_dcs]
        }
      }

      # Spokes ↔ Remote Spokes ICMP (cross-region)
      dynamic "rule" {
        for_each = local.has_cross_region_spoke_rules ? [1] : []
        content {
          name                  = "ICMP_Spokes_RemoteSpokes"
          source_ip_groups      = [local.ip_group_ids.spokes, local.ip_group_ids.remote_spokes]
          destination_ports     = ["*"]
          protocols             = ["ICMP"]
          destination_ip_groups = [local.ip_group_ids.spokes, local.ip_group_ids.remote_spokes]
        }
      }
    }
  }
}

###############################################################################
# Platform Application Rule Collection Group
# Application-level rules: Spoke FQDN access
###############################################################################

resource "azurerm_firewall_policy_rule_collection_group" "rcg_platform_application" {
  count = local.has_spokes && length(local.spokes_allowed_fqdns) > 0 ? 1 : 0

  name               = "Default_Platform_Application_Rules"
  priority           = local.settings.rcg_platform_application_priority
  firewall_policy_id = var.firewall_policy_id

  depends_on = [azurerm_ip_group.this]

  lifecycle {
    precondition {
      condition     = var.firewall_policy_id != null && var.firewall_policy_id != ""
      error_message = "firewall_policy_id is required to create rule collection groups."
    }
  }

  #############################################################################
  # Spokes to FQDNs
  #############################################################################

  application_rule_collection {
    name     = "Spokes_To_FQDNs"
    priority = local.p_spokes_to_fqdns
    action   = "Allow"
    rule {
      name              = "SpokesFQDNs"
      source_ip_groups  = [local.ip_group_ids.spokes]
      destination_fqdns = local.spokes_allowed_fqdns
      protocols {
        type = "Https"
        port = 443
      }
    }
  }
}
