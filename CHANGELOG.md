# Changelog

All notable changes to this module are documented here. Versions are git tags.

## v1.6.4

### Added
- **`avd_extra_fqdns`** aligned to the official **AVD session-host required-FQDN list** (`aka.ms/required-fqdn-endpoint`). Adds `pas.windows.net` (Entra ID token / Conditional Access — was blocking session-host **sign-in**), `catalogartifact.azureedge.net` (Marketplace), `mrsglobalsteus2prod.blob.core.windows.net` (agent + SXS stack updates), `wvdportalstorageblob.blob.core.windows.net` (portal support), the AIK certificate hosts (`*.aikcertaia.microsoft.com`, `azcsprodeusaikpublish.blob.core.windows.net`, `*.microsoftaik.azure.net`), and the AVD service-traffic hosts (`*.service.windows.cloud.microsoft`, `*.windows.cloud.microsoft`, `*.windows.static.microsoft`). All Microsoft-owned / agnostic. KMS (1688), `aka.ms` (Azure Local only), and the AAD / WindowsUpdate FQDNs already covered by the `enable_az_mgmt_*` platform baseline are intentionally not duplicated.

## v1.6.3

### Added
- **`enable_avd` RDP Shortpath relay** — new `RDP_Shortpath_Relay` rule in the AVD network collection (`AVD_M365_Network`) allows the **`WindowsVirtualDesktop`** service tag over **UDP 3478-3481** (STUN/TURN). RDP Shortpath for public networks was being denied (it can't be expressed as an application/FQDN rule); without it sessions fall back to slower TCP relay. Agnostic to any AVD deployment.
- **`avd_extra_fqdns`** default extended with **`intstreamreleases.z22.web.core.windows.net`** — the Microsoft-hosted Azure Storage static-site endpoint serving the **Remote Desktop WebRTC Redirector Service** installer/updates (Teams media optimisation). Hit by AVD session-host image builds; Microsoft-owned, so agnostic to any AVD deployment.

## v1.6.2

### Fixed
- **AVD `Teams_Media_UDP` / `Exchange_Mail` network rules** now use Azure Firewall's granular **`Office365.*` service tags** (`Office365.Skype.Optimize`, `Office365.Exchange.Allow.Required`) instead of hand-maintained M365 IP CIDRs. The v1.6.1 CIDR lists contained IPv6 ranges, which Azure Firewall network rules reject (`FirewallPolicyRuleIpv6AddressNotAllowed`) — this broke apply. The service tags are IPv4-only, auto-updated from the O365 endpoints API, and the correct mechanism (selectable in the portal network-rule UI). Removed the now-unused `avd_teams_media_cidrs` / `avd_exchange_online_cidrs` variables.

## v1.6.1

### Fixed
- **`enable_avd` Teams/Exchange network rule** used an invalid `Office365` service tag — there is no `Office365` *network* service tag in Azure, so the rule was a silent no-op. Replaced with the published Microsoft 365 IP ranges via new `var.avd_teams_media_cidrs` + `var.avd_exchange_online_cidrs`. (O365 *web* egress remains on the `Office365.*` FQDN tags in the application rule, which are valid.)

### Added
- **`enable_nerdio` now also emits an application rule** (`var.nerdio_fqdns`) with NME's named endpoints, alongside the service-tag network rule — Nerdio URLs allowed by name, not just broad service tags.
- `*.ingest.monitor.azure.com` added to the monitoring baseline (`fqdns_monitoring`) — Azure Monitor Agent (AMA) DCR/DCE log + metric ingestion.
- `avd_extra_fqdns` default extended with `login.windows.net` + `*.sfx.ms` (optional M365 / OneDrive per Nerdio's AVD session-host requirements).

## v1.6.0

### Added
- **`enable_nerdio`** rule setting (default `false`) — emits a source-scoped **Nerdio Manager (NME)** egress profile when `ip_groups.nerdio` is supplied. Network rules to the `AppService`, `AzureActiveDirectory`, `AzureResourceManager`, `AzureMonitor` service tags (443/TCP) plus `Sql` (1433, 11000-11999). Reusable default for any Nerdio deployment.
- **`enable_avd`** rule setting (default `false`) — emits a source-scoped **AVD session-host + M365** egress profile when `ip_groups.avd` is supplied. Application rules using the `WindowsVirtualDesktop` + `Office365` FQDN tags plus `var.avd_extra_fqdns` (agent/cert FQDNs); network rules to the `Office365` service tag for Teams media (UDP 3478-3481) and Exchange mail ports (TCP 25/143/587/993/995). Reusable default for any AVD deployment.
- New `ip_groups.nerdio` and `ip_groups.avd` source CIDR sets (auto-create `ipg-…-nerdio` / `ipg-…-avd`).
- New `var.avd_extra_fqdns` (tunable, defaults to AVD agent telemetry + certificate FQDNs not covered by the FQDN tags or service tags).

### Notes
- Both toggles are **off by default**, so existing consumers are unaffected.
- Service tags are preferred over hand-maintained FQDN/IP lists wherever Azure provides one. Destinations already covered by the platform baseline (`enable_az_mgmt_*`, source `*` — e.g. `*.blob.core.windows.net`, `*.azureedge.net`, GitHub, Key Vault, Graph) are intentionally not duplicated.

## v1.0.0 – v1.5.0

Pre-changelog. See git history (`git log`) and tags for prior changes.
