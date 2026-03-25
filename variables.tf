###############################################################################
# Required Variables
###############################################################################

variable "environment" {
  type        = string
  description = "Environment (prod, nonprod)"
}

variable "workload" {
  type        = string
  description = "Workload identifier for naming"
}

variable "location" {
  type        = string
  description = "Azure region"
}

variable "resource_group_name" {
  type        = string
  description = "Resource group for IP groups"
}

variable "firewall_policy_id" {
  type        = string
  description = "Existing firewall policy resource ID (from platform_shared)"

  validation {
    condition     = var.firewall_policy_id != null && var.firewall_policy_id != ""
    error_message = "firewall_policy_id is required and cannot be empty."
  }
}

variable "azure_bastion_subnet_prefix" {
  type        = string
  description = "Bastion subnet CIDR for identity access rules (optional - omit if no Bastion)"
  default     = null
}

###############################################################################
# IP Groups - CIDRs passed from stack tfvars
# These define what networks are allowed through the firewall
###############################################################################

variable "ip_groups" {
  description = "IP group CIDR definitions - passed from stack tfvars"
  type = object({
    # Required - Domain controller subnets
    identity_dcs = set(string)

    # All Azure spoke networks (get ADDS access + spoke ↔ on_prem traffic)
    spokes = optional(set(string), [])

    # On-premises/external networks via VPN/ExpressRoute
    on_prem = optional(set(string), [])

    # External DCs for AD replication/enrollment (full AD ports bidirectional)
    replication_dcs = optional(set(string), [])

    # Spoke networks in other regions (for cross-region connectivity)
    remote_spokes = optional(set(string), [])

    # Jumpbox/management subnets (SSH + RDP access to all spokes)
    jumpboxes = optional(set(string), [])

    # LogicMonitor monitoring
    logicmonitor = optional(object({
      collectors = optional(set(string), [])
      targets    = optional(set(string), [])
    }), {})

    # Tenable vulnerability scanning
    tenable = optional(object({
      scanners = optional(set(string), [])
    }), {})
  })

  validation {
    condition     = length(var.ip_groups.identity_dcs) > 0
    error_message = "At least one identity domain controller CIDR is required."
  }
}

###############################################################################
# Optional - Traffic Rules & Settings
###############################################################################

variable "traffic_rules" {
  description = "Optional: Override default ports/protocols for directional rules"
  type = object({
    spokes_to_on_prem = optional(object({ ports = list(string), protocols = list(string) }))
    on_prem_to_spokes = optional(object({ ports = list(string), protocols = list(string) }))
    spoke_to_spoke    = optional(object({ ports = list(string), protocols = list(string) }))
  })
  default = {}
}

variable "rule_settings" {
  description = "Rule enablement and priority settings"
  type = object({
    # Azure management rules
    enable_az_mgmt_rules            = optional(bool, true)  # Includes ASR!
    enable_az_mgmt_app_rules        = optional(bool, true)
    enable_ntp                      = optional(bool, true)  # NTP for all VMs

    # LogicMonitor monitoring (auto-enabled when ip_groups.logicmonitor defined)
    enable_monitoring_windows       = optional(bool, true)  # Windows monitoring (RPC, WMI, RDP, SQL)
    enable_monitoring_linux         = optional(bool, true)  # Linux monitoring (SSH, SNMP, SNMP-TLS)

    # Security monitoring (Sentinel, Tenable, syslog, CEF, WEF)
    enable_security_monitoring      = optional(bool, true)  # Security sub → Spokes (443, 514, 1514, 5044, 5985-5986)

    # Internet outbound
    enable_internet_outbound        = optional(bool, false) # Allow HTTP/HTTPS to internet

    # Troubleshooting
    enable_troubleshooting          = optional(bool, false)
    enable_troubleshooting_internet = optional(bool, false)

    # Spoke traffic
    enable_spoke_to_spoke           = optional(bool, true)  # Spoke ↔ Spoke traffic (management, cross-spoke apps)
    enable_cross_region_spokes      = optional(bool, true)  # Cross-region spoke ↔ remote spoke traffic
    enable_icmp                     = optional(bool, true)  # ICMP between segments

    # Jumpbox access (SSH + RDP from jumpboxes to all spokes)
    enable_jumpbox_access           = optional(bool, true)   # Jumpboxes → Spokes (SSH, RDP)

    # On-prem traffic (enable if VPN/ExpressRoute connected)
    enable_spokes_to_on_prem        = optional(bool, true)  # Spoke ↔ On-prem traffic
    enable_on_prem_adds             = optional(bool, false) # Full ADDS access from on-prem
    enable_on_prem_kerberos         = optional(bool, false) # Kerberos-only from on-prem (lighter than full ADDS)

    # OS updates and security tooling
    enable_edge_updates             = optional(bool, true)  # Edge browser updates + SmartScreen
    enable_linux_updates            = optional(bool, true)  # Linux package repo access (Ubuntu ESM etc.)
    enable_tenable                  = optional(bool, false) # Tenable vulnerability scanning (opt-in)

    # Rule collection group priorities
    # Order: DNAT(100) → Troubleshoot(200) → Identity(300) → Internet Net(400) / App(410) → Platform Net(500) / App(510) → Monitoring(600) → Custom(700-800)
    rcg_troubleshooting_priority        = optional(number, 200)
    rcg_identity_priority               = optional(number, 300)
    rcg_internet_network_priority       = optional(number, 400)
    rcg_internet_application_priority   = optional(number, 410)
    rcg_platform_network_priority       = optional(number, 500)
    rcg_platform_application_priority   = optional(number, 510)
    rcg_monitoring_priority             = optional(number, 600)
    rcg_custom_network_priority         = optional(number, 700)
    rcg_custom_application_priority     = optional(number, 800)
  })
  default = {}
}

###############################################################################
# DNAT Rules - Inbound NAT through the firewall
###############################################################################

variable "custom_dnat_collections" {
  description = "DNAT rule collections for inbound services (e.g., vendor access, applications)"
  type = map(object({
    priority = number
    rules = list(object({
      name                = string
      source_addresses    = optional(list(string), ["*"])
      destination_address = string # Firewall public IP
      destination_port    = string
      translated_address  = string # Internal target IP
      translated_port     = string
      protocols           = optional(list(string), ["TCP"])
    }))
  }))
  default = {}
}

###############################################################################
# Custom Network Rules - Customer-specific network rule collections
###############################################################################

variable "custom_network_collections" {
  description = "Custom network rule collections with configurable names and priorities"
  type = map(object({
    priority = number
    rules = list(object({
      name                  = string
      source_addresses      = optional(list(string))
      source_ip_groups      = optional(list(string))
      destination_addresses = optional(list(string))
      destination_ip_groups = optional(list(string))
      destination_fqdns     = optional(list(string))
      destination_ports     = list(string)
      protocols             = list(string) # TCP, UDP, ICMP, Any
    }))
  }))
  default = {}
}

###############################################################################
# Custom Application Rules - Customer-specific application rule collections
###############################################################################

variable "custom_application_collections" {
  description = "Custom application rule collections with configurable names and priorities"
  type = map(object({
    priority = number
    rules = list(object({
      name                  = string
      source_addresses      = optional(list(string))
      source_ip_groups      = optional(list(string))
      destination_fqdns     = optional(list(string))
      destination_fqdn_tags = optional(list(string))
      protocols = list(object({
        type = string # Http, Https, Mssql
        port = number
      }))
    }))
  }))
  default = {}
}

variable "diagnostics" {
  type = object({
    enabled                        = optional(bool, false)
    log_analytics_workspace_id     = optional(string)
    storage_account_id             = optional(string)
    eventhub_authorization_rule_id = optional(string)
    eventhub_name                  = optional(string)
    logs                           = optional(set(string))
    metrics                        = optional(set(string))
  })
  description = "Diagnostics configuration applied to the firewall policy."
  default     = {}
}

variable "logicmonitor_platform" {
  type        = set(string)
  description = "LogicMonitor platform endpoints (FQDNs or IPs/CIDRs)"
  default = [
    "*.logicmonitor.com",
    "scc.logicmonitor.com",
    "3.68.188.192/26",
    "3.106.118.64/26",
    "13.43.19.192/26",
    "15.156.210.128/26",
    "18.139.118.192/26",
    "18.246.78.128/25",
    "34.223.95.64/26",
    "52.52.63.0/26",
    "52.202.255.64/26",
    "52.215.168.128/26",
    "54.193.15.255/32",
    "54.194.232.54/32",
    "54.209.7.170/32",
    "54.254.224.41/32",
    "100.28.156.128/25"
  ]
}

variable "tenable_platform" {
  type        = set(string)
  description = "Tenable platform FQDNs for scanner cloud updates"
  default = [
    "appliance.cloud.tenable.com",
    "*.cloud.tenable.com"
  ]
}

variable "linux_update_fqdns" {
  type        = set(string)
  description = "Linux package repository FQDNs (override for other distros)"
  default     = ["esm.ubuntu.com"]
}

variable "edge_update_fqdns" {
  type        = set(string)
  description = "Edge browser update and SmartScreen FQDNs"
  default = [
    "msedge.api.cdp.microsoft.com",
    "unitedkingdom.smartscreen.microsoft.com"
  ]
}

variable "custom_ip_groups" {
  description = "Additional IP groups to create (key = group name, value = list of CIDRs). Referenceable in custom rules via source_ip_groups/destination_ip_groups by key name."
  type        = map(set(string))
  default     = {}
}

variable "spokes_allowed_fqdns" {
  type        = set(string)
  description = "Optional FQDN destinations reachable from spoke networks"
  default     = []
}

variable "troubleshooting_destination_cidrs" {
  type        = set(string)
  description = "CIDRs to target when troubleshooting rules are enabled (defaults to RFC1918)"
  default     = []
}

variable "tags" {
  type        = map(string)
  description = "Tags applied to all resources"
  default     = {}
}
