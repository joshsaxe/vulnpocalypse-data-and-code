# How the snapshot in data/ was built

This folder is provenance. It shows how the frozen tables in `data/` were made from the raw sources, so a reader can check a label or rebuild the snapshot from fresh downloads. **It is not runnable from this repository**: the scripts read several gigabytes of raw downloads that are not included, and they use the absolute paths of the machine they ran on. Everything downstream of `data/` is runnable (`python run_all.py`).

## The chain

| Step | Script | What it does | Reads |
|---|---|---|---|
| 1 | `upstream/parse_nvd2.py`, `upstream/parse_sel.py` | Parse the National Vulnerability Database's yearly JSON feeds into one record per CVE: description, CVSS vector, CWE numbers, affected products, numbering authority | NVD feeds, downloaded November 10, 2026 |
| 2 | `upstream/rcedef.py`, `upstream/build.py` | Apply the remote-code-execution test, parse CVSS, assign the weakness family and delivery; attach CISA catalog entries and counts of earlier catalog entries per product | Step 1; CISA's Known Exploited Vulnerabilities catalog of November 9, 2026 |
| 3 | `upstream/roles2.py` | Assign the kind of product to every record: a vendor table, then bounded keyword rules on product names and descriptions | The record only |
| 4 | `upstream/labels.py`, `upstream/labels2.py` | Attach exploitation evidence to each CVE: which lists name it, whether each list implies wide or targeted use, whether it was a zero-day | `inputs/exploitation_evidence_lists.csv` and two further research tables on attackers and volumes that the essay does not use |
| 5 | `upstream/update.py` | Assign who installs the fix | `inputs/update_models_major_products.csv`, `inputs/vendor_attributes_extension.csv`, the product role |
| 6 | `upstream/registries.py`, `upstream/panelmap.py`, `upstream/vendattr.py` | Match each record to a vendor in the 86-vendor panel where possible and assign the maker tier, ownership and security-program flags | The vendor panel; public lists of numbering authorities and bug-bounty programs; `inputs/vendor_attributes_extension.csv` |
| 7 | `upstream/load.py`, `upstream/load3.py`, `upstream/feat.py` | Assemble the per-vulnerability table; attach campaigns and victim counts | Steps 2 to 6; the campaign table |
| 8 | `build_snapshot.py` | Split the hyperscale tier into the four model hyperscalers and Microsoft, apply `data/group_overrides.csv` and `data/role_overrides.csv`, and write every table in `data/` | Step 7 |

`upstream/ext_features.py` extracts exploit-availability features (public exploit code, Metasploit modules, EPSS scores) used in earlier analysis; none of them is used by the essay.

## The research tables in inputs/

These were compiled with heavy AI assistance from public sources, each row with a URL, and spot-checked. The `verified` column says whether the row was checked against its source.

- `exploitation_evidence_lists.csv` (1,937 rows): one row per CVE per list that names it. `breadth` is `wide`, `targeted` or `unclear`; `list_name` and `source` say which list; `zero_day` marks exploitation before a fix. The `ev_wide` column in `data/flaws.csv.gz` is built from the `wide` rows.
- `update_models_major_products.csv` (62 product families): who installs the fix, since when, the basis and a URL.
- `vendor_attributes_extension.csv` (66 vendors outside the panel): owner, revenue, bug bounty and update model, with sources.

The campaign table and the vendor panel are in `data/` (`campaigns.csv`, `vendor_panel.csv`). The sensor lists in `data/sensor_lists.csv` are CIRCL's published rankings, copied as published.

## What a rebuild would need

Fresh copies of the NVD feeds and CISA's catalog, the three tables above, the campaign table and the vendor panel, and the paths at the top of each script changed. A rebuild on a later date will not reproduce the essay's numbers: records are added and revised daily, and evidence of exploitation keeps arriving.
