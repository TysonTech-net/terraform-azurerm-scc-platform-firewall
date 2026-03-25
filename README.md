## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.3 |
| <a name="requirement_azurerm"></a> [azurerm](#requirement\_azurerm) | >= 3.71.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_azurerm"></a> [azurerm](#provider\_azurerm) | 4.60.0 |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [azurerm_firewall_policy_rule_collection_group.rcg_custom_application](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/firewall_policy_rule_collection_group) | resource |
| [azurerm_firewall_policy_rule_collection_group.rcg_custom_network](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/firewall_policy_rule_collection_group) | resource |
| [azurerm_firewall_policy_rule_collection_group.rcg_dnat](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/firewall_policy_rule_collection_group) | resource |
| [azurerm_firewall_policy_rule_collection_group.rcg_identity](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/firewall_policy_rule_collection_group) | resource |
| [azurerm_firewall_policy_rule_collection_group.rcg_internet](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/firewall_policy_rule_collection_group) | resource |
| [azurerm_firewall_policy_rule_collection_group.rcg_monitoring](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/firewall_policy_rule_collection_group) | resource |
| [azurerm_firewall_policy_rule_collection_group.rcg_spokes_on_prem](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/firewall_policy_rule_collection_group) | resource |
| [azurerm_firewall_policy_rule_collection_group.rcg_troubleshooting](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/firewall_policy_rule_collection_group) | resource |
| [azurerm_ip_group.this](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/ip_group) | resource |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_azure_bastion_subnet_prefix"></a> [azure\_bastion\_subnet\_prefix](#input\_azure\_bastion\_subnet\_prefix) | Bastion subnet CIDR for identity access rules (optional - omit if no Bastion) | `string` | `null` | no |
| <a name="input_custom_application_collections"></a> [custom\_application\_collections](#input\_custom\_application\_collections) | Custom application rule collections with configurable names and priorities | <pre>map(object({<br/>    priority = number<br/>    rules = list(object({<br/>      name                  = string<br/>      source_addresses      = optional(list(string))<br/>      source_ip_groups      = optional(list(string))<br/>      destination_fqdns     = optional(list(string))<br/>      destination_fqdn_tags = optional(list(string))<br/>      protocols = list(object({<br/>        type = string # Http, Https, Mssql<br/>        port = number<br/>      }))<br/>    }))<br/>  }))</pre> | `{}` | no |
| <a name="input_custom_dnat_collections"></a> [custom\_dnat\_collections](#input\_custom\_dnat\_collections) | DNAT rule collections for inbound services (e.g., vendor access, applications) | <pre>map(object({<br/>    priority = number<br/>    rules = list(object({<br/>      name                = string<br/>      source_addresses    = optional(list(string), ["*"])<br/>      destination_address = string # Firewall public IP<br/>      destination_port    = string<br/>      translated_address  = string # Internal target IP<br/>      translated_port     = string<br/>      protocols           = optional(list(string), ["TCP"])<br/>    }))<br/>  }))</pre> | `{}` | no |
| <a name="input_custom_network_collections"></a> [custom\_network\_collections](#input\_custom\_network\_collections) | Custom network rule collections with configurable names and priorities | <pre>map(object({<br/>    priority = number<br/>    rules = list(object({<br/>      name                  = string<br/>      source_addresses      = optional(list(string))<br/>      source_ip_groups      = optional(list(string))<br/>      destination_addresses = optional(list(string))<br/>      destination_ip_groups = optional(list(string))<br/>      destination_fqdns     = optional(list(string))<br/>      destination_ports     = list(string)<br/>      protocols             = list(string) # TCP, UDP, ICMP, Any<br/>    }))<br/>  }))</pre> | `{}` | no |
| <a name="input_diagnostics"></a> [diagnostics](#input\_diagnostics) | Diagnostics configuration applied to the firewall policy. | <pre>object({<br/>    enabled                        = optional(bool, false)<br/>    log_analytics_workspace_id     = optional(string)<br/>    storage_account_id             = optional(string)<br/>    eventhub_authorization_rule_id = optional(string)<br/>    eventhub_name                  = optional(string)<br/>    logs                           = optional(set(string))<br/>    metrics                        = optional(set(string))<br/>  })</pre> | `{}` | no |
| <a name="input_environment"></a> [environment](#input\_environment) | Environment (prod, nonprod) | `string` | n/a | yes |
| <a name="input_firewall_policy_id"></a> [firewall\_policy\_id](#input\_firewall\_policy\_id) | Existing firewall policy resource ID (from platform\_shared) | `string` | n/a | yes |
| <a name="input_ip_groups"></a> [ip\_groups](#input\_ip\_groups) | IP group CIDR definitions - passed from stack tfvars | <pre>object({<br/>    # Required - Domain controller subnets<br/>    identity_dcs = set(string)<br/><br/>    # All Azure spoke networks (get ADDS access + spoke ↔ on_prem traffic)<br/>    spokes = optional(set(string), [])<br/><br/>    # On-premises/external networks via VPN/ExpressRoute<br/>    on_prem = optional(set(string), [])<br/><br/>    # External DCs for AD replication/enrollment (full AD ports bidirectional)<br/>    replication_dcs = optional(set(string), [])<br/><br/>    # LogicMonitor monitoring<br/>    logicmonitor = optional(object({<br/>      collectors = optional(set(string), [])<br/>      targets    = optional(set(string), [])<br/>    }), {})<br/>  })</pre> | n/a | yes |
| <a name="input_location"></a> [location](#input\_location) | Azure region | `string` | n/a | yes |
| <a name="input_logicmonitor_platform"></a> [logicmonitor\_platform](#input\_logicmonitor\_platform) | LogicMonitor platform endpoints (FQDNs or IPs/CIDRs) | `set(string)` | <pre>[<br/>  "*.logicmonitor.com",<br/>  "scc.logicmonitor.com",<br/>  "3.68.188.192/26",<br/>  "3.106.118.64/26",<br/>  "13.43.19.192/26",<br/>  "15.156.210.128/26",<br/>  "18.139.118.192/26",<br/>  "18.246.78.128/25",<br/>  "34.223.95.64/26",<br/>  "52.52.63.0/26",<br/>  "52.202.255.64/26",<br/>  "52.215.168.128/26",<br/>  "54.193.15.255/32",<br/>  "54.194.232.54/32",<br/>  "54.209.7.170/32",<br/>  "54.254.224.41/32",<br/>  "100.28.156.128/25"<br/>]</pre> | no |
| <a name="input_resource_group_name"></a> [resource\_group\_name](#input\_resource\_group\_name) | Resource group for IP groups | `string` | n/a | yes |
| <a name="input_rule_settings"></a> [rule\_settings](#input\_rule\_settings) | Rule enablement and priority settings | <pre>object({<br/>    # Azure management rules<br/>    enable_az_mgmt_rules            = optional(bool, true)  # Includes ASR!<br/>    enable_az_mgmt_app_rules        = optional(bool, true)<br/>    enable_ntp                      = optional(bool, true)  # NTP for all VMs<br/><br/>    # LogicMonitor monitoring (auto-enabled when ip_groups.logicmonitor defined)<br/>    enable_monitoring_windows       = optional(bool, true)  # Windows monitoring (RPC, WMI, RDP, SQL)<br/>    enable_monitoring_linux         = optional(bool, true)  # Linux monitoring (SSH, SNMP, SNMP-TLS)<br/><br/>    # Security monitoring (Sentinel, Tenable, syslog, CEF, WEF)<br/>    enable_security_monitoring      = optional(bool, true)  # Security sub → Spokes (443, 514, 1514, 5044, 5985-5986)<br/><br/>    # Internet outbound<br/>    enable_internet_outbound        = optional(bool, false) # Allow HTTP/HTTPS to internet<br/><br/>    # Troubleshooting<br/>    enable_troubleshooting          = optional(bool, false)<br/>    enable_troubleshooting_internet = optional(bool, false)<br/><br/>    # Spoke traffic<br/>    enable_spoke_to_spoke           = optional(bool, true)  # Spoke ↔ Spoke traffic (management, cross-spoke apps)<br/>    enable_icmp                     = optional(bool, true)  # ICMP between segments<br/><br/>    # On-prem traffic (enable if VPN/ExpressRoute connected)<br/>    enable_spokes_to_on_prem        = optional(bool, true)  # Spoke ↔ On-prem traffic<br/>    enable_on_prem_adds             = optional(bool, false) # Full ADDS access from on-prem<br/>    enable_on_prem_kerberos         = optional(bool, false) # Kerberos-only from on-prem (lighter than full ADDS)<br/><br/>    # Rule collection group priorities<br/>    # Order: DNAT(100) → Troubleshoot(200) → Identity(300) → Internet(400) → Platform(500) → Monitoring(600) → Custom(700-800)<br/>    rcg_troubleshooting_priority    = optional(number, 200)<br/>    rcg_identity_priority           = optional(number, 300)<br/>    rcg_internet_priority           = optional(number, 400)<br/>    rcg_platform_priority           = optional(number, 500)<br/>    rcg_monitoring_priority         = optional(number, 600)<br/>    rcg_custom_network_priority     = optional(number, 700)<br/>    rcg_custom_application_priority = optional(number, 800)<br/>  })</pre> | `{}` | no |
| <a name="input_spokes_allowed_fqdns"></a> [spokes\_allowed\_fqdns](#input\_spokes\_allowed\_fqdns) | Optional FQDN destinations reachable from spoke networks | `set(string)` | `[]` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | Tags applied to all resources | `map(string)` | `{}` | no |
| <a name="input_traffic_rules"></a> [traffic\_rules](#input\_traffic\_rules) | Optional: Override default ports/protocols for directional rules | <pre>object({<br/>    spokes_to_on_prem = optional(object({ ports = list(string), protocols = list(string) }))<br/>    on_prem_to_spokes = optional(object({ ports = list(string), protocols = list(string) }))<br/>    spoke_to_spoke    = optional(object({ ports = list(string), protocols = list(string) }))<br/>  })</pre> | `{}` | no |
| <a name="input_troubleshooting_destination_cidrs"></a> [troubleshooting\_destination\_cidrs](#input\_troubleshooting\_destination\_cidrs) | CIDRs to target when troubleshooting rules are enabled (defaults to RFC1918) | `set(string)` | `[]` | no |
| <a name="input_workload"></a> [workload](#input\_workload) | Workload identifier for naming | `string` | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_ip_group_ids"></a> [ip\_group\_ids](#output\_ip\_group\_ids) | Map of all IP group resource IDs (null if not created) |
| <a name="output_ipg_identity_dcs_id"></a> [ipg\_identity\_dcs\_id](#output\_ipg\_identity\_dcs\_id) | IP Group resource ID for identity domain controllers |
| <a name="output_ipg_on_prem_id"></a> [ipg\_on\_prem\_id](#output\_ipg\_on\_prem\_id) | IP Group resource ID for on-premises networks (null if not created) |
| <a name="output_ipg_replication_dcs_id"></a> [ipg\_replication\_dcs\_id](#output\_ipg\_replication\_dcs\_id) | IP Group resource ID for replication domain controllers (null if not created) |
| <a name="output_ipg_spokes_id"></a> [ipg\_spokes\_id](#output\_ipg\_spokes\_id) | IP Group resource ID for Azure spokes (null if not created) |
| <a name="output_rule_collection_group_ids"></a> [rule\_collection\_group\_ids](#output\_rule\_collection\_group\_ids) | Map of rule collection group resource IDs |
| <a name="output_rule_collection_summary"></a> [rule\_collection\_summary](#output\_rule\_collection\_summary) | Summary of rule collection enablement and priorities |
