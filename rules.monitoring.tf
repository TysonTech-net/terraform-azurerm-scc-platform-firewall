###############################################################################
# Monitoring Rule Collection Group
# Handles LogicMonitor collector to target rules
###############################################################################

resource "azurerm_firewall_policy_rule_collection_group" "rcg_monitoring" {
  count              = length(try(var.ip_groups.logicmonitor.collectors, [])) > 0 && length(try(var.ip_groups.logicmonitor.targets, [])) > 0 ? 1 : 0
  name               = "Default_Monitoring_Rules"
  priority           = local.settings.rcg_monitoring_priority
  firewall_policy_id = var.firewall_policy_id

  depends_on = [azurerm_ip_group.this]

  lifecycle {
    precondition {
      condition     = var.firewall_policy_id != null && var.firewall_policy_id != ""
      error_message = "firewall_policy_id is required to create rule collection groups."
    }
  }

  #############################################################################
  # General Monitoring (ICMP, HTTP/HTTPS, LogicMonitor collector)
  #############################################################################

  network_rule_collection {
    name     = "Monitoring_General"
    priority = local.p_monitoring_general
    action   = "Allow"
    rule {
      name                  = "General_ICMP"
      source_ip_groups      = [local.ip_group_ids.lm_collectors]
      destination_ports     = ["*"]
      protocols             = ["ICMP"]
      destination_ip_groups = [local.ip_group_ids.lm_targets]
    }
    rule {
      name                  = "General_Web_LM"
      source_ip_groups      = [local.ip_group_ids.lm_collectors]
      destination_ports     = ["80", "443", "24158"] # HTTP, HTTPS, LogicMonitor collector
      protocols             = ["TCP"]
      destination_ip_groups = [local.ip_group_ids.lm_targets]
    }
  }

  #############################################################################
  # Windows Monitoring (RPC, WMI, RDP, SQL) - optional via enable_monitoring_windows
  #############################################################################

  dynamic "network_rule_collection" {
    for_each = local.settings.enable_monitoring_windows ? [1] : []
    content {
      name     = "Monitoring_Windows"
      priority = local.p_monitoring_windows
      action   = "Allow"
      rule {
        name                  = "Windows_RPC_WMI"
        source_ip_groups      = [local.ip_group_ids.lm_collectors]
        destination_ports     = ["135", "139", "445"]
        protocols             = ["TCP", "UDP"]
        destination_ip_groups = [local.ip_group_ids.lm_targets]
      }
      rule {
        name                  = "Windows_RDP"
        source_ip_groups      = [local.ip_group_ids.lm_collectors]
        destination_ports     = ["3389"]
        protocols             = ["TCP"]
        destination_ip_groups = [local.ip_group_ids.lm_targets]
      }
      rule {
        name                  = "Windows_SQL"
        source_ip_groups      = [local.ip_group_ids.lm_collectors]
        destination_ports     = ["1433", "1434"] # SQL Server, SQL Browser
        protocols             = ["TCP", "UDP"]
        destination_ip_groups = [local.ip_group_ids.lm_targets]
      }
    }
  }

  #############################################################################
  # Linux Monitoring (SSH, SNMP) - optional via enable_monitoring_linux
  #############################################################################

  dynamic "network_rule_collection" {
    for_each = local.settings.enable_monitoring_linux ? [1] : []
    content {
      name     = "Monitoring_Linux"
      priority = local.p_monitoring_linux
      action   = "Allow"
      rule {
        name                  = "Linux_SSH"
        source_ip_groups      = [local.ip_group_ids.lm_collectors]
        destination_ports     = ["22"]
        protocols             = ["TCP"]
        destination_ip_groups = [local.ip_group_ids.lm_targets]
      }
      rule {
        name                  = "Linux_SNMP"
        source_ip_groups      = [local.ip_group_ids.lm_collectors]
        destination_ports     = ["161", "162"]
        protocols             = ["UDP"]
        destination_ip_groups = [local.ip_group_ids.lm_targets]
      }
      rule {
        name                  = "Linux_SNMP_TLS"
        source_ip_groups      = [local.ip_group_ids.lm_collectors]
        destination_ports     = ["10161"] # SNMP over TLS (uses TCP)
        protocols             = ["TCP"]
        destination_ip_groups = [local.ip_group_ids.lm_targets]
      }
    }
  }
}
