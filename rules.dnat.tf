###############################################################################
# DNAT Rule Collection Group
# Handles inbound services through the firewall (e.g., RDP, SSH, HTTPS)
# Uses custom_dnat_collections for named rule collections with priorities
###############################################################################

resource "azurerm_firewall_policy_rule_collection_group" "rcg_dnat" {
  count              = length(var.custom_dnat_collections) > 0 ? 1 : 0
  name               = "DNAT_Rules"
  priority           = 100 # DNAT rules need high priority (Azure minimum is 100)
  firewall_policy_id = var.firewall_policy_id

  lifecycle {
    precondition {
      condition     = var.firewall_policy_id != null && var.firewall_policy_id != ""
      error_message = "firewall_policy_id is required to create rule collection groups."
    }
  }

  #############################################################################
  # Dynamic NAT Rule Collections (one per collection in the map)
  #############################################################################

  dynamic "nat_rule_collection" {
    for_each = var.custom_dnat_collections
    content {
      name     = nat_rule_collection.key
      priority = nat_rule_collection.value.priority
      action   = "Dnat"

      dynamic "rule" {
        for_each = nat_rule_collection.value.rules
        content {
          name                = rule.value.name
          source_addresses    = rule.value.source_addresses
          destination_address = rule.value.destination_address
          destination_ports   = [rule.value.destination_port]
          translated_address  = rule.value.translated_address
          translated_port     = rule.value.translated_port
          protocols           = rule.value.protocols
        }
      }
    }
  }
}
