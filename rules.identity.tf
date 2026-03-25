###############################################################################
# Identity Rule Collection Group
# Handles DNS, Azure AD, Bastion, and ADDS rules
###############################################################################

resource "azurerm_firewall_policy_rule_collection_group" "rcg_identity" {
  name               = "Default_Identity_Rules"
  priority           = local.settings.rcg_identity_priority
  firewall_policy_id = var.firewall_policy_id

  depends_on = [azurerm_ip_group.this]

  lifecycle {
    precondition {
      condition     = var.firewall_policy_id != null && var.firewall_policy_id != ""
      error_message = "firewall_policy_id is required to create rule collection groups."
    }
  }

  #############################################################################
  # Outbound DNS - DCs to any DNS
  #############################################################################

  network_rule_collection {
    name     = "Outbound_DNS"
    priority = local.p_dns
    action   = "Allow"
    rule {
      name                  = "DCs_to_DNS_TCP"
      source_ip_groups      = [local.ip_group_ids.identity_dcs]
      destination_ports     = ["53"]
      protocols             = ["TCP"]
      destination_addresses = ["*"]
    }
    rule {
      name                  = "DCs_to_DNS_UDP"
      source_ip_groups      = [local.ip_group_ids.identity_dcs]
      destination_ports     = ["53"]
      protocols             = ["UDP"]
      destination_addresses = ["*"]
    }
  }

  #############################################################################
  # Inbound DNS - Spokes to DCs (optional - DNS resolution via DCs)
  #############################################################################

  dynamic "network_rule_collection" {
    for_each = local.has_spokes ? [1] : []
    content {
      name     = "Inbound_DNS_From_Spokes"
      priority = local.p_spokes_dns
      action   = "Allow"
      rule {
        name                  = "Spokes_to_DCs_DNS_TCP"
        source_ip_groups      = [local.ip_group_ids.spokes]
        destination_ports     = ["53"]
        protocols             = ["TCP"]
        destination_ip_groups = [local.ip_group_ids.identity_dcs]
      }
      rule {
        name                  = "Spokes_to_DCs_DNS_UDP"
        source_ip_groups      = [local.ip_group_ids.spokes]
        destination_ports     = ["53"]
        protocols             = ["UDP"]
        destination_ip_groups = [local.ip_group_ids.identity_dcs]
      }
    }
  }

  #############################################################################
  # Outbound Azure AD Connect
  #############################################################################

  network_rule_collection {
    name     = "Outbound_AzureADConnect"
    priority = local.p_aad
    action   = "Allow"
    rule {
      name                  = "DCs_to_AzureAD_TCP"
      source_ip_groups      = [local.ip_group_ids.identity_dcs]
      destination_ports     = ["*"]
      protocols             = ["TCP"]
      destination_addresses = ["AzureActiveDirectory"]
    }
  }

  #############################################################################
  # Inbound Azure Bastion to Identity VMs (optional - only if Bastion configured)
  #############################################################################

  dynamic "network_rule_collection" {
    for_each = var.azure_bastion_subnet_prefix != null ? [1] : []
    content {
      name     = "Inbound_AzureBastion"
      priority = local.p_bastion
      action   = "Allow"
      rule {
        name                  = "AzureBastion_to_IdentityVMs_RDP"
        source_addresses      = [var.azure_bastion_subnet_prefix]
        destination_ports     = ["3389"]
        protocols             = ["TCP"]
        destination_ip_groups = [local.ip_group_ids.identity_dcs]
      }
    }
  }

  #############################################################################
  # Inbound ADDS from Azure Spokes (optional)
  #############################################################################

  dynamic "network_rule_collection" {
    for_each = local.has_spokes ? [1] : []
    content {
      name     = "Inbound_ADDS_From_Spokes"
      priority = local.p_spokes_adds
      action   = "Allow"
      rule {
        name                  = "ADDS_TCP"
        source_ip_groups      = [local.ip_group_ids.spokes]
        destination_ports     = local.adds_ports.tcp
        protocols             = ["TCP"]
        destination_ip_groups = [local.ip_group_ids.identity_dcs]
      }
      rule {
        name                  = "ADDS_UDP"
        source_ip_groups      = [local.ip_group_ids.spokes]
        destination_ports     = local.adds_ports.udp
        protocols             = ["UDP"]
        destination_ip_groups = [local.ip_group_ids.identity_dcs]
      }
      rule {
        name                  = "ADDS_ICMP"
        source_ip_groups      = [local.ip_group_ids.spokes]
        destination_ports     = ["*"]
        protocols             = ["ICMP"]
        destination_ip_groups = [local.ip_group_ids.identity_dcs]
      }
    }
  }

  #############################################################################
  # Inbound ADDS from On-Prem (optional - controlled by enable_on_prem_adds)
  #############################################################################

  dynamic "network_rule_collection" {
    for_each = local.has_on_prem && local.settings.enable_on_prem_adds ? [1] : []
    content {
      name     = "Inbound_ADDS_From_OnPrem"
      priority = local.p_on_prem_adds
      action   = "Allow"
      rule {
        name                  = "ADDS_TCP"
        source_ip_groups      = [local.ip_group_ids.on_prem]
        destination_ports     = local.adds_ports.tcp
        protocols             = ["TCP"]
        destination_ip_groups = [local.ip_group_ids.identity_dcs]
      }
      rule {
        name                  = "ADDS_UDP"
        source_ip_groups      = [local.ip_group_ids.on_prem]
        destination_ports     = local.adds_ports.udp
        protocols             = ["UDP"]
        destination_ip_groups = [local.ip_group_ids.identity_dcs]
      }
      rule {
        name                  = "ADDS_ICMP"
        source_ip_groups      = [local.ip_group_ids.on_prem]
        destination_ports     = ["*"]
        protocols             = ["ICMP"]
        destination_ip_groups = [local.ip_group_ids.identity_dcs]
      }
    }
  }

  #############################################################################
  # Inbound Kerberos-only from On-Prem (optional - lighter than full ADDS)
  # Use when on-prem only needs authentication, not full domain services
  #############################################################################

  dynamic "network_rule_collection" {
    for_each = local.has_on_prem && local.settings.enable_on_prem_kerberos && !local.settings.enable_on_prem_adds ? [1] : []
    content {
      name     = "Inbound_Kerberos_From_OnPrem"
      priority = local.p_on_prem_kerberos
      action   = "Allow"
      rule {
        name                  = "Kerberos_TCP"
        source_ip_groups      = [local.ip_group_ids.on_prem]
        destination_ports     = local.kerberos_ports.tcp
        protocols             = ["TCP"]
        destination_ip_groups = [local.ip_group_ids.identity_dcs]
      }
      rule {
        name                  = "Kerberos_UDP"
        source_ip_groups      = [local.ip_group_ids.on_prem]
        destination_ports     = local.kerberos_ports.udp
        protocols             = ["UDP"]
        destination_ip_groups = [local.ip_group_ids.identity_dcs]
      }
    }
  }

  #############################################################################
  # Bidirectional AD Replication with External DCs (optional)
  # Used for DC enrollment, promotion, and cross-forest trusts
  #############################################################################

  dynamic "network_rule_collection" {
    for_each = length(var.ip_groups.replication_dcs) > 0 ? [1] : []
    content {
      name     = "Bidirectional_AD_Replication"
      priority = local.p_replication
      action   = "Allow"
      rule {
        name                  = "AD_Replication_TCP"
        source_ip_groups      = [local.ip_group_ids.replication_dcs, local.ip_group_ids.identity_dcs]
        destination_ports     = local.adds_ports.tcp
        protocols             = ["TCP"]
        destination_ip_groups = [local.ip_group_ids.replication_dcs, local.ip_group_ids.identity_dcs]
      }
      rule {
        name                  = "AD_Replication_UDP"
        source_ip_groups      = [local.ip_group_ids.replication_dcs, local.ip_group_ids.identity_dcs]
        destination_ports     = local.adds_ports.udp
        protocols             = ["UDP"]
        destination_ip_groups = [local.ip_group_ids.replication_dcs, local.ip_group_ids.identity_dcs]
      }
      rule {
        name                  = "AD_Replication_ICMP"
        source_ip_groups      = [local.ip_group_ids.replication_dcs, local.ip_group_ids.identity_dcs]
        destination_ports     = ["*"]
        protocols             = ["ICMP"]
        destination_ip_groups = [local.ip_group_ids.replication_dcs, local.ip_group_ids.identity_dcs]
      }
    }
  }
}
