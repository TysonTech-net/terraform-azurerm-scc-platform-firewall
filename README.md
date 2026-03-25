# terraform-azurerm-scc-platform-firewall

Azure platform firewall module. Creates IP groups and firewall rule collection groups (identity, internet, monitoring, platform, DNAT, custom) attached to an existing firewall policy.

## Usage

```hcl
module "firewall_rules" {
  source = "git::https://github.com/TysonTech-net/terraform-azurerm-scc-platform-firewall.git?ref=v1.0.0"

  firewall_policy_id = data.terraform_remote_state.platform_shared.outputs.firewall_policies["primary"]
  environment        = "prod"
  workload           = "hub"
  location           = "uksouth"
  resource_group_name = "rg-hub-prod-uks-001"
  ip_groups          = var.ip_groups
  rule_settings      = var.rule_settings
  traffic_rules      = var.traffic_rules
}
```

## Features

- IP group management (standard + custom)
- Identity domain rules (AD, LDAP, Kerberos, DNS)
- Internet egress rules (Windows Update, Azure services)
- Monitoring rules (Log Analytics, diagnostics)
- Platform rules (management, backup, KMS)
- Custom DNAT, network, and application rule collections

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.3 |
| azurerm | ~> 4.0 |
