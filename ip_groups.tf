###############################################################################
# IP Group Definitions
###############################################################################

locals {
  ip_group_definitions = {
    identity_dcs     = { cidrs = var.ip_groups.identity_dcs, required = true }
    spokes           = { cidrs = var.ip_groups.spokes, required = false }
    on_prem          = { cidrs = var.ip_groups.on_prem, required = false }
    replication_dcs  = { cidrs = var.ip_groups.replication_dcs, required = false }
    remote_spokes    = { cidrs = var.ip_groups.remote_spokes, required = false }
    jumpboxes        = { cidrs = var.ip_groups.jumpboxes, required = false }
    lm_collectors    = { cidrs = try(var.ip_groups.logicmonitor.collectors, []), required = false }
    lm_targets       = { cidrs = try(var.ip_groups.logicmonitor.targets, []), required = false }
    tenable_scanners = { cidrs = try(var.ip_groups.tenable.scanners, []), required = false }
  }

  # Custom IP groups (from var.custom_ip_groups) merged into the same resource
  custom_ip_group_definitions = {
    for key, cidrs in var.custom_ip_groups :
    key => { cidrs = cidrs, required = false }
  }

  # Only create IP groups that are required or have CIDRs defined
  ip_groups_to_create = merge(
    {
      for key, cfg in local.ip_group_definitions :
      key => cfg if cfg.required || length(cfg.cidrs) > 0
    },
    {
      for key, cfg in local.custom_ip_group_definitions :
      key => cfg if length(cfg.cidrs) > 0
    }
  )

  # Simple try() mapping — includes both default and custom IP groups
  ip_group_ids = {
    for key in keys(merge(local.ip_group_definitions, local.custom_ip_group_definitions)) :
    key => try(azurerm_ip_group.this[key].id, null)
  }

  # Segment availability flags
  has_spokes        = contains(keys(local.ip_groups_to_create), "spokes")
  has_on_prem       = contains(keys(local.ip_groups_to_create), "on_prem")
  has_remote_spokes = contains(keys(local.ip_groups_to_create), "remote_spokes")
  has_jumpboxes     = contains(keys(local.ip_groups_to_create), "jumpboxes")
  has_logicmonitor  = contains(keys(local.ip_groups_to_create), "lm_collectors") && contains(keys(local.ip_groups_to_create), "lm_targets")
  has_tenable       = contains(keys(local.ip_groups_to_create), "tenable_scanners")
}

###############################################################################
# IP Group Resources
###############################################################################

resource "azurerm_ip_group" "this" {
  for_each = local.ip_groups_to_create

  name                = "${local.ip_group_prefix}-${replace(each.key, "_", "-")}"
  resource_group_name = var.resource_group_name
  location            = var.location
  cidrs               = sort(tolist(each.value.cidrs))
  tags                = var.tags

  lifecycle {
    create_before_destroy = true
  }
}

###############################################################################
# Rule Enablement Flags
###############################################################################

locals {
  has_spoke_to_spoke_rules = alltrue([
    local.settings.enable_spoke_to_spoke,
    local.has_spokes,
    length(local.traffic.spoke_to_spoke.ports) > 0,
    length(local.traffic.spoke_to_spoke.protocols) > 0,
  ])

  has_spokes_to_on_prem_rules = alltrue([
    local.settings.enable_spokes_to_on_prem,
    local.has_spokes,
    local.has_on_prem,
    length(local.traffic.spokes_to_on_prem.ports) > 0,
    length(local.traffic.spokes_to_on_prem.protocols) > 0,
  ])

  has_on_prem_to_spokes_rules = alltrue([
    local.settings.enable_spokes_to_on_prem,
    local.has_on_prem,
    local.has_spokes,
    length(local.traffic.on_prem_to_spokes.ports) > 0,
    length(local.traffic.on_prem_to_spokes.protocols) > 0,
  ])

  has_cross_region_spoke_rules = alltrue([
    local.settings.enable_cross_region_spokes,
    local.has_spokes,
    local.has_remote_spokes,
  ])

  has_tenable_scanning_rules = alltrue([
    local.settings.enable_tenable,
    local.has_tenable,
    local.has_spokes,
  ])

  has_jumpbox_rules = alltrue([
    local.settings.enable_jumpbox_access,
    local.has_jumpboxes,
    local.has_spokes,
  ])
}
