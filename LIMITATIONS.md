# Limitations

This is a hard domain to build certainty in. Attackers do not publish what they do, vendors disclose unevenly, and the best evidence arrives months late. The essay's conclusions are a sketch from public evidence. This file lists what that evidence cannot support, including the problems we know about and chose not to fix. Numbers are as of the snapshot (publications to November 9, 2026).

## Scope

1. **Remote vulnerabilities only.** Privilege escalation and lateral movement happen inside networks where almost nothing is published, so they are left out. So are stolen credentials and misconfigurations, which are not software vulnerabilities. The study describes how attackers get in through software flaws, not everything they do, and not every way in.
2. **Remote vulnerabilities with partial impact are left out.** Information leaks and similar flaws rated below full impact are not in the table unless the record describes code execution. Of the 353 pre-login vulnerabilities in internet-facing enterprise products that CISA lists as exploited (CVE years 2019 to 2026), 84 (24%) are outside the table for this reason (`data/kev_coverage.csv`).
3. **Only CVE records are counted.** Vendors that host their software rarely issue CVE numbers for flaws they fix on their own servers, and flaws fixed silently never appear. This flatters makers of hosted services in both the numerator and the denominator, and it is one reason Meta and Amazon have so few records.
4. **Counts follow disclosure habits.** One vendor's decision to publish more records moves a chart. Oracle published 209 of the 617 vulnerabilities of the most dangerous class in July–September 2026 (its remotely exploitable records in this table rose from 18 in 2025 to 1,298 so far in 2026), and Google published 2,123 of the four hyperscalers' 2,319 this year. Whether that is more flaws or more records for the same flaws, the data cannot say.

## Labels

5. **The labels were made by rules and research tables with heavy AI assistance, and were not audited record by record.** With nearly 80,000 records, some are wrong. Known kinds of error: the `prod` column takes the first product named in the record, which is sometimes a downstream product (two PHP vulnerabilities are labeled `pan-os`, Apache Tomcat ones `debian linux`); product roles lean on names (FortiClient EMS, a management server, was filed as client software until corrected); maker groups for small vendors follow the product role, not research on the company.
6. **"Plug-ins and small projects" is half catch-all.** Of its 5,888 vulnerabilities in 2026, 2,854 are in software whose kind of maker the rules could not classify, spread over about 1,500 maker names. Some are small commercial vendors (Devolutions, Altium, Perforce) that a reader would count as "mid-market and smaller". If every one of them were counted with the mid-market, that group's share of 2026's vulnerabilities would rise from 9% to 22% and its share of mass exploitation from 51% to 54%. The essay's contrast survives, but "about a tenth" could be as much as a fifth.
7. **Known misfilings left in place.** Inspecting the mass-exploited records turned up four: Chanjet T+ (commercial accounting software, 2026) and Weaver e-office under a second vendor spelling (2025) sit in "plug-ins and small projects" and belong with mid-market vendors; a Digiever video recorder (2025) sits there and belongs with device makers; ASUS routers (2025) sit with large vendors, not device makers. We did not move them, because we found them by reading only the exploited records, and correcting only those would tilt the comparison. Moving them would make the mid-market's 2026 count 20 of 37 mass-exploited, not 19.
8. **The $5bn line between "large" and "mid-market" rests on revenue figures of mixed quality.** Citrix is classed mid-market on its last standalone revenue ($3.2bn, fiscal 2021); it now belongs to Cloud Software Group, whose revenue we did not verify. Three of the mid-market's 19 mass-exploited vulnerabilities in 2026 are NetScaler's. Without them the share is 16 of 37 (43%), not half.
9. **Who installs the fix was researched for 62 product families only.** Everything else is inferred from the kind of product. "Optional" covers situations as different as a WordPress plug-in's auto-update switch and an Android patch that waits on a phone maker.

## Mass exploitation

10. **Every count is a floor.** A vulnerability counts only if someone published evidence of scale. Quiet, targeted use by intelligence services and spyware vendors is mostly invisible and is deliberately not counted as mass exploitation.
11. **The evidence changes with time, so years are not strictly comparable.** For vulnerabilities of the most dangerous class published in 2019–2023, 106 of the 116 that count as mass-exploited have evidence other than a sensor ranking (ransomware reports, government lists). For 2026's, 18 of 23 rest on a sensor ranking and 13 on nothing else. Sensor rankings arrive within weeks; ransomware attributions can take a year. So 2026's counts are missing slow evidence that 2025's already have, and at the same time lean on a more sensitive instrument.
12. **A place in a top-100 sighting list is a rank, not a victim count.** It shows attackers are firing an exploit at honeypots at volume. That is good evidence of mass exploitation attempts and weaker evidence of mass compromise. CIRCL's counts also mix honeypot records with other kinds of sighting.
13. **The sensors are honeypots for server software.** They cannot see attacks on phones, browsers or anything that needs a real user, so for client software only the other kinds of evidence count. Any measure that leans on sensors will make makers of client software, such as Apple and Google, look better than makers of servers.
14. **Some of the strong labels are debatable.** CISA's ransomware flag says a ransomware group used the vulnerability, not how many victims there were. Two Apple vulnerabilities from 2023 count as mass-exploited because a government list of most-exploited vulnerabilities names them, although they are best known from a spyware campaign. Those two count against the hyperscalers.
15. **Device makers read zero in 2026 for a bad reason.** The botnets that use router and camera vulnerabilities are identified months later (16 of 2025's device vulnerabilities count as mass-exploited, none of 2026's yet). Chart 3 leaves them out rather than show a misleading zero.

## The 2026 estimates

16. **They are projections.** The estimate of vulnerabilities of the class attacked this year is about 108, with a 90% range of 89 to 148; for mass exploitation about 38, range 26 to 64. The ranges for "attacked" and "mass-exploited" growth overlap, so "mass exploitation has grown least" is the reading of the middle estimates, not a certainty.
17. **The last bar of Chart 2 is three-quarters projection.** It rests on 10 attacked vulnerabilities observed in 40 days. Back-tested on 13 quarters, the rule behind it was right in total but missed single quarters by 19% on average, and by as much as 37% low and 84% high.
18. **The delay curves assume the future resembles the past.** If CISA lists more slowly when four times as many vulnerabilities are published, the estimates are too low; if defenders and sensors have become faster, too high.
19. **The mass-exploitation estimate could not be back-tested**, because the sensor record has no history before October 2024. It rests on 54 vulnerabilities. It applies the share that normally appears by the end of a quarter to a quarter only 40 days old, and it corrects only for the delay in sensor rankings, not for ransomware evidence still to come. Both push it low.
20. **Chart 1's last bar assumes October's pace continues.** October had 247; the first nine days of November had 31. Early November is usually slow, and tested on 13 quarters the first-month rule was 1% high in total with a typical miss of 10%, but its worst miss was 49% high. The 90% range for the quarter is about 580 to 940.

## Comparisons between makers

21. **Every rate is per vulnerability.** Nothing accounts for how many machines run the software, how exposed they are, or how much attackers want what is on them.
22. **The four hyperscalers were chosen as the model after looking at the data.** That is a forking path. Their record rests mostly on Google and Apple (345 and 205 of the 626 no-login vulnerabilities in 2019–2025; Meta 56, Amazon 20), whose products are mostly phones and browsers that sensors cannot see (item 13). We cannot separate "delivers the fix" from sandboxing, memory-safe code, the kind of product, or disclosure habits.
23. **Chart 4 is observational and its numbers are small.** The zero-day comparison is 5 of 20 against 45 of 52. The 20 are mostly Apple, Mozilla, Sophos and Barracuda products; the 52 are servers and edge devices. The two groups differ in far more than who installs the fix. The hosted comparison is 33 campaigns and relies on vendors' own statements about whether their hosted service was hit.
24. **Microsoft's "products that customers patch" is 63 vulnerabilities, 7 mass-exploited**, six of them in Exchange and SharePoint. That is two product lines.
25. **The vendor-attribute tests have little power.** 48 vendors, 107 mass-exploited vulnerabilities. Finding no effect of bug bounties or the Secure by Design pledge may say more about the data than about those practices, and the pledge dates from 2024 while the vulnerabilities span 2019–2025. Nine attributes were tested; the size and private-equity results should be read with that in mind.

## Budgets, Chart 7 and Chart 8

26. **No company publishes an application-security budget.** Chart 6's figures are the author's estimates from head counts, R&D spending and assumed shares. The stated range is a factor of about 2.6 either way and is itself a judgment. The comparison with mid-market revenue is an order-of-magnitude illustration.
27. **The essay's sentence about AI token budgets is a suspicion, not a finding.** Nothing in this repository measures token spending.
28. **Chart 7 is the author's judgment.** The public results quoted on it are real and cited, but where each layer sits is an opinion.
29. **Chart 8's counts measure different things**: implanted devices, leaked credentials, breached organizations, servers seen attacking others. Most are lower bounds from a single source. Incidents with no identified vulnerability are left out, and so are incidents nobody counted.

## What would change the conclusions

- A full audit of maker groups that moved many exploited vulnerabilities out of the mid-market, or many unexploited ones into it.
- Evidence that hyperscaler vulnerabilities are mass-exploited on clients at a rate sensors miss.
- 2026's slow evidence (ransomware attributions, botnet reports) arriving in the coming year and landing mostly outside the mid-market.
- A measure of exposure, such as installed base, showing the per-vulnerability rates here are driven by deployment and not by how fixes are delivered.
