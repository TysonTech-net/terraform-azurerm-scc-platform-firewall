###############################################################################
# Custom Network Rule Collection Group
# Supports multiple named collections with configurable priorities
# Use for customer-specific network rules (e.g., security services, management)
#
# IP Group References:
# source_ip_groups and destination_ip_groups can reference:
# - Module-managed IP groups by key name: "spokes", "identity_dcs", "lm_collectors", "lm_targets", "on_prem", "replication_dcs"
# - Full Azure resource IDs for external IP groups
###############################################################################

# Helper local to resolve IP group references (key names → resource IDs)
locals {
  # Function to resolve a list of IP group references
  # If the value is a key in local.ip_group_ids, use the ID; otherwise assume it's a full resource ID
  resolve_ip_groups = { for key, id in local.ip_group_ids : key => id if id != null }
}

resource "azurerm_firewall_policy_rule_collection_group" "rcg_custom_network" {
  count              = length(var.custom_network_collections) > 0 ? 1 : 0
  name               = "Custom_Network_Rules"
  priority           = local.settings.rcg_custom_network_priority
  firewall_policy_id = var.firewall_policy_id

  depends_on = [azurerm_ip_group.this]

  lifecycle {
    precondition {
      condition     = var.firewall_policy_id != null && var.firewall_policy_id != ""
      error_message = "firewall_policy_id is required to create rule collection groups."
    }
  }

  #############################################################################
  # Dynamic Network Rule Collections (one per collection in the map)
  #############################################################################

  dynamic "network_rule_collection" {
    for_each = var.custom_network_collections
    content {
      name     = network_rule_collection.key
      priority = network_rule_collection.value.priority
      action   = "Allow"

      dynamic "rule" {
        for_each = network_rule_collection.value.rules
        content {
          name             = rule.value.name
          source_addresses = rule.value.source_addresses
          # Resolve IP group key names to resource IDs
          source_ip_groups = rule.value.source_ip_groups != null ? [
            for ref in rule.value.source_ip_groups :
            lookup(local.resolve_ip_groups, ref, ref)
          ] : null
          destination_addresses = rule.value.destination_addresses
          # Resolve IP group key names to resource IDs
          destination_ip_groups = rule.value.destination_ip_groups != null ? [
            for ref in rule.value.destination_ip_groups :
            lookup(local.resolve_ip_groups, ref, ref)
          ] : null
          destination_fqdns = rule.value.destination_fqdns
          destination_ports = rule.value.destination_ports
          protocols         = rule.value.protocols
        }
      }
    }
  }
}

###############################################################################
# Custom Application Rule Collection Group
# Supports multiple named collections with configurable priorities
# Use for customer-specific application rules (e.g., vendor services, SaaS)
#
# IP Group References:
# source_ip_groups can reference:
# - Module-managed IP groups by key name: "spokes", "identity_dcs", "lm_collectors", "lm_targets", "on_prem", "replication_dcs"
# - Full Azure resource IDs for external IP groups
###############################################################################

resource "azurerm_firewall_policy_rule_collection_group" "rcg_custom_application" {
  count              = length(var.custom_application_collections) > 0 ? 1 : 0
  name               = "Custom_Application_Rules"
  priority           = local.settings.rcg_custom_application_priority
  firewall_policy_id = var.firewall_policy_id

  depends_on = [azurerm_ip_group.this]

  lifecycle {
    precondition {
      condition     = var.firewall_policy_id != null && var.firewall_policy_id != ""
      error_message = "firewall_policy_id is required to create rule collection groups."
    }
  }

  #############################################################################
  # Dynamic Application Rule Collections (one per collection in the map)
  #############################################################################

  dynamic "application_rule_collection" {
    for_each = var.custom_application_collections
    content {
      name     = application_rule_collection.key
      priority = application_rule_collection.value.priority
      action   = "Allow"

      dynamic "rule" {
        for_each = application_rule_collection.value.rules
        content {
          name             = rule.value.name
          source_addresses = rule.value.source_addresses
          # Resolve IP group key names to resource IDs
          source_ip_groups = rule.value.source_ip_groups != null ? [
            for ref in rule.value.source_ip_groups :
            lookup(local.resolve_ip_groups, ref, ref)
          ] : null
          destination_fqdns     = rule.value.destination_fqdns
          destination_fqdn_tags = rule.value.destination_fqdn_tags

          dynamic "protocols" {
            for_each = rule.value.protocols
            content {
              type = protocols.value.type
              port = protocols.value.port
            }
          }
        }
      }
    }
  }
}
