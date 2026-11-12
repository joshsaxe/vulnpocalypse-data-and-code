# Data dictionary

Every file in `data/`, and every column. The tables are a frozen snapshot: vulnerability records as downloaded on November 10, 2026. How they were built is in `pipeline/README.md`.

## flaws.csv.gz

One row per CVE record in the reference class (see METHODOLOGY.md, section 2): 78,992 rows, sorted by publication date. `src/study.py` loads it and skips the 12 rows dated after November 9, 2026. Booleans are `1` or `0`.

| Column | Meaning |
|---|---|
| `id` | CVE identifier |
| `pub` | Date published in the National Vulnerability Database (UTC) |
| `src` | The numbering authority that issued the record, as NVD's source identifier |
| `vendor` | Vendor name from the record's product list or numbering authority, lower case. Empty for some records |
| `prod` | First product named in the record, lower case. Sometimes a downstream product (a PHP vulnerability can read `pan-os`, a Tomcat one `debian linux`). Used for display and two product checks, never for grouping |
| `rce` | 1 if the record meets the remote-code-execution test |
| `basis` | Which branch of that test fired: `explicit` (the description says remote code or command execution), `phrase` (says code or commands can be executed), `cwe` (injection, deserialization or dangerous upload scored as full compromise), `memory` (remotely reachable memory-corruption write scored as full compromise), `file` (code execution when a user opens attacker-supplied content). Empty if `rce` is 0 |
| `pop2` | 1 if CVSS gives a network attack vector and High impact on confidentiality, integrity and availability. Every row has `rce` or `pop2` |
| `score` | CVSS base score |
| `av`, `ac`, `pr`, `ui`, `c`, `i`, `a` | CVSS components: attack vector, complexity, privileges required, user interaction, and impact on confidentiality, integrity, availability |
| `delivery` | `open` (no login, no user action, network or adjacent vector), `creds` (needs a login), `user` (needs a user's action), `unknown` |
| `wk` | Weakness family: `memory`, `auth`, `sqli`, `cmd` (command injection), `upload`, `inject` (other injection), `deser` (deserialization), `other` |
| `role` | Kind of product: `edge` (firewalls, VPN gateways and other perimeter devices), `srv_exposed` (internet-facing server software), `srv_internal` (internal servers), `client_os` (PCs, phones, browsers and their apps), `iot` (routers, cameras, small devices), `ics` (industrial), `cloud` (vendor-run services), `component` (libraries), `plugin`, `hobby` (student and demonstration projects), `other`, `other_web` (not classified) |
| `group` | Maker group: `hyperscale` (Google, Apple, Meta, Amazon), `microsoft`, `large`, `midmarket`, `oss`, `small`, `device`. See METHODOLOGY.md, section 3 |
| `group_basis` | How the group was set: `revenue` (a revenue figure), `named` (a named hyperscaler), `rule` (from the product role and numbering authority), `override` (a line in `group_overrides.csv`) |
| `company` | For the `hyperscale` and `microsoft` groups: Google, Apple, Meta, Amazon or Microsoft |
| `pv` | The vendor's name in the 86-vendor panel, if it is one of them |
| `upd` | Who installs the fix: `vendor`, `optional`, `customer`, `downstream` |
| `upd_basis` | `table` (researched for the product family), `recalled` (the author's knowledge of the product, not checked against a source), `type` (inferred from the kind of product) |
| `kev` | 1 if in CISA's Known Exploited Vulnerabilities catalog |
| `kev_date` | Date CISA listed it |
| `kev_rw` | 1 if CISA marks it as used in ransomware campaigns |
| `expl` | 1 if known to be exploited: in CISA's catalog or in any researched list of exploited vulnerabilities |
| `zd` | 1 if a researched source says it was exploited before a fix existed |
| `ev_wide` | Kinds of evidence that it was exploited widely, separated by `\|`. The kinds are listed below |
| `camp` | 1 if it was used in a campaign in `campaigns.csv` |
| `victims` | The largest published count of compromised systems or organizations across those campaigns, if any |
| `pkp` | Number of earlier vulnerabilities in the same product already in CISA's catalog when this one was published. Not used by the charts |
| `cna` | 1 if the vendor is a CVE numbering authority. Not used by the charts |

Kinds of evidence in `ev_wide`, with the number of records carrying each: `ransomware flag in CISA catalog` (189), `botnet` (125), `government most-exploited list` (98), `sensor or telemetry ranking` (77), `Rapid7 classification` (74), `ransomware advisory` (59), `named campaign with scale figure` (32), `other report` (6), `spyware vendor` (4), `Google or Mandiant zero-day review` (2), `MITRE ATT&CK` (2). The last four do not count toward mass exploitation. The source and URL for each entry are in `pipeline/inputs/exploitation_evidence_lists.csv`.

## sensor_lists.csv

CIRCL's lists of the 100 most-sighted exploited vulnerabilities, one row per vulnerability per list. 1,200 rows.

| Column | Meaning |
|---|---|
| `id` | CVE identifier (any year; many are older than 2019 and not in `flaws.csv.gz`) |
| `period_start`, `period_end` | The period the list covers |
| `count` | Sightings in the period |
| `kind` | `quarter`: one of nine quarterly lists from October 2024, the only kind the study uses. `pre_feed`: the July–September 2024 list, which predates the Shadowserver honeypot feed. `all_time`: lists covering the whole record |

## kev_coverage.csv

Every entry in CISA's catalog, used to measure what the reference class leaves out. 1,773 rows.

| Column | Meaning |
|---|---|
| `id`, `vendor`, `product`, `date_added` | As in the catalog |
| `cve_year` | Year in the CVE identifier |
| `ransomware_flag` | 1 if CISA marks ransomware use |
| `role` | Kind of product, by the same rules as `flaws.csv.gz` |
| `no_login`, `no_login_no_click` | From the CVSS vector |
| `in_flaw_table` | 1 if the record is in `flaws.csv.gz` |

## campaigns.csv

121 named mass-exploitation campaigns, researched from vendor, government and press reports. Used for Chart 4's hosted comparison and Chart 8.

| Column | Meaning |
|---|---|
| `event`, `vendor`, `product` | The campaign and what it hit |
| `cves` | Vulnerabilities used |
| `start_month` | First reported exploitation |
| `zero_day` | Whether exploitation began before a fix |
| `days_patch_to_mass_exploitation` | Days from fix to mass exploitation, where reported |
| `exposed_instances`, `exposed_kind`, `exposed_source_url` | Systems exposed to the internet at the time, what was counted, and the source |
| `compromised_count`, `compromised_unit`, `compromised_source_url` | The published count of victims, what it counts, and the source |
| `share_compromised_pct` | Compromised as a share of exposed, where both are known |
| `product_role` | Kind of product |
| `operated_by` | `customer`, `vendor`, or `both` (the product is sold both as software the customer runs and as a service the vendor hosts) |
| `vendor_hosted_version_affected` | For `both`: `Y`, `N`, `partly` or unknown, from the vendor's statements |
| `actor_type` | Who ran the campaign |
| `unpatched_after_30d_pct` | Share of exposed systems still unpatched a month later, where reported |
| `notes` | Free text |

## vendor_panel.csv

86 vendors of enterprise software with company attributes from annual filings and vendor pages. `group` here is the panel's own grouping (`platform`, `large`, `midsize`, `netsec`, `saas`), not the maker group in `flaws.csv.gz`.

| Column | Meaning |
|---|---|
| `vendor`, `group` | Name and panel grouping |
| `revenue` | Latest annual revenue, $m |
| `rev_cert`, `rev_period` | How firm the figure is (audited, reported, estimate) and the fiscal year |
| `employees` | Head count |
| `rnd_pct` | R&D as a percentage of revenue |
| `founded`, `codebase_year` | Year the company was founded; year the flagship product's codebase dates from |
| `acquired` | 1 if the flagship product was acquired, 0 if built in-house, 0.5 where the product line is part acquired and part built |
| `pe`, `ownership`, `pe_sponsor` | 1 if private-equity owned; ownership in words; the sponsor |
| `bounty`, `bounty_raw`, `bounty_max` | 2 public paid bug bounty, 1 private, 0 none found, empty unverified; the finding in words; top payout |
| `pledge` | 1 if the vendor signed CISA's Secure by Design pledge |

## group_overrides.csv and role_overrides.csv

Hand corrections applied when the snapshot was built. Each line has a reason.

| Column | Meaning |
|---|---|
| `vendor` | Vendor name as in `flaws.csv.gz` |
| `applies_to_group` | Only rows in this group are changed; `*` means any |
| `new_group`, `company` | The corrected group, and the company for hyperscaler groups |
| `product`, `new_role` | In `role_overrides.csv`: the product and its corrected role |
| `reason` | Why |

## budget_inputs.csv and budget_assumptions.csv

Inputs to Chart 6. `budget_inputs.csv` has one row per company: fiscal year, employees, the assumed range of software engineers and its basis, reported R&D (or, for Amazon, technology and infrastructure expense), the range taken as software development and its basis, and the filing it comes from. `budget_assumptions.csv` has the four judgments (application-security staff per engineer, cost per head, overhead, share of development spending), each with a low, a high and its basis.

## open_source_budgets.csv

The two open-source figures on Chart 6, in $m, with basis and source.

## layers.csv

Chart 7: the nine layers, the group each belongs to, the public result quoted beneath it, the author's placement (`0` AI does most of it today, `1` within reach soon, `2` people still lead) and the source. The last row's text has two placeholders that `src/chart7.py` fills with Chart 4's zero-day shares.
