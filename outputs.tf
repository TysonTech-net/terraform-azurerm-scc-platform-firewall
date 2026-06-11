###############################################################################
# IP Group Outputs
###############################################################################

output "ip_group_ids" {
  description = "Map of all IP group resource IDs (null if not created)"
  value       = local.ip_group_ids
}

output "ipg_identity_dcs_id" {
  description = "IP Group resource ID for identity domain controllers"
  value       = local.ip_group_ids.identity_dcs
}

output "ipg_spokes_id" {
  description = "IP Group resource ID for Azure spokes (null if not created)"
  value       = local.ip_group_ids.spokes
}

output "ipg_on_prem_id" {
  description = "IP Group resource ID for on-premises networks (null if not created)"
  value       = local.ip_group_ids.on_prem
}

output "ipg_replication_dcs_id" {
  description = "IP Group resource ID for replication domain controllers (null if not created)"
  value       = local.ip_group_ids.replication_dcs
}

output "ipg_remote_spokes_id" {
  description = "IP Group resource ID for remote spoke networks (null if not created)"
  value       = local.ip_group_ids.remote_spokes
}

###############################################################################
# Rule Collection Group IDs
###############################################################################

output "rule_collection_group_ids" {
  description = "Map of rule collection group resource IDs"
  value = {
    dnat                 = try(azurerm_firewall_policy_rule_collection_group.rcg_dnat[0].id, null)
    troubleshooting      = try(azurerm_firewall_policy_rule_collection_group.rcg_troubleshooting[0].id, null)
    identity             = azurerm_firewall_policy_rule_collection_group.rcg_identity.id
    internet_network     = azurerm_firewall_policy_rule_collection_group.rcg_internet.id
    internet_application = azurerm_firewall_policy_rule_collection_group.rcg_internet_application.id
    platform_network     = try(azurerm_firewall_policy_rule_collection_group.rcg_spokes_on_prem[0].id, null)
    platform_application = try(azurerm_firewall_policy_rule_collection_group.rcg_platform_application[0].id, null)
    monitoring           = try(azurerm_firewall_policy_rule_collection_group.rcg_monitoring[0].id, null)
    custom_network       = try(azurerm_firewall_policy_rule_collection_group.rcg_custom_network[0].id, null)
    custom_application   = try(azurerm_firewall_policy_rule_collection_group.rcg_custom_application[0].id, null)
  }
}

###############################################################################
# Rule Collection Summary
###############################################################################

output "rule_collection_summary" {
  description = "Summary of rule collection enablement and priorities"
  value = {
    # Priority order: DNAT(100) → Troubleshoot(200) → Identity(300) → Internet Net(400) / App(410) → Platform Net(500) / App(510) → Monitoring(600) → Custom(700-800)
    dnat = {
      priority = 100
      enabled  = length(var.custom_dnat_collections) > 0
    }
    troubleshooting = {
      priority = local.settings.rcg_troubleshooting_priority
      enabled  = local.settings.enable_troubleshooting
    }
    identity = {
      priority        = local.settings.rcg_identity_priority
      spokes_adds     = local.has_spokes
      on_prem_adds    = local.has_on_prem && local.settings.enable_on_prem_adds
      replication_dcs = length(var.ip_groups.replication_dcs) > 0
    }
    internet_network = {
      priority               = local.settings.rcg_internet_network_priority
      azure_management_rules = local.settings.enable_az_mgmt_rules
      logicmonitor_outbound  = local.has_logicmonitor
      nerdio                 = local.has_nerdio_rules
      avd_m365_network       = local.has_avd_rules
    }
    internet_application = {
      priority              = local.settings.rcg_internet_application_priority
      azure_management_apps = local.settings.enable_az_mgmt_app_rules
      logicmonitor_outbound = local.has_logicmonitor
      avd                   = local.has_avd_rules
    }
    platform_network = {
      priority            = local.settings.rcg_platform_network_priority
      spoke_to_spoke      = local.has_spoke_to_spoke_rules
      cross_region_spokes = local.has_cross_region_spoke_rules
      security_monitoring = local.settings.enable_security_monitoring && local.has_spokes
      spokes_to_on_prem   = local.has_spokes_to_on_prem_rules
      on_prem_to_spokes   = local.has_on_prem_to_spokes_rules
      icmp                = local.settings.enable_icmp
    }
    platform_application = {
      priority        = local.settings.rcg_platform_application_priority
      spokes_to_fqdns = local.has_spokes && length(local.spokes_allowed_fqdns) > 0
    }
    monitoring = {
      priority = local.settings.rcg_monitoring_priority
      enabled  = local.has_logicmonitor
    }
    custom_network = {
      priority = local.settings.rcg_custom_network_priority
      enabled  = length(var.custom_network_collections) > 0
    }
    custom_application = {
      priority = local.settings.rcg_custom_application_priority
      enabled  = length(var.custom_application_collections) > 0
    }
  }
}
