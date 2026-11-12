# Decisions

Each choice that shaped the numbers, why it was made, and what the alternative shows where we computed it. Several were made after seeing early results; those are marked, because a choice made after looking at the data deserves less trust.

## Scope

**1. Only remotely exploitable vulnerabilities.** The essay is about software vulnerabilities, and the only evidence of scale that arrives quickly is from honeypot sensors, which record attacks arriving over the internet. Privilege escalation and lateral movement happen after a break-in, inside networks nobody outside can observe; the public record on them is thin and comes from a handful of vendors. Folding them in would have mixed a well-observed class with a badly observed one.

**2. Remote code execution plus other remote, high-impact vulnerabilities.** An earlier version counted only remote code execution. Mass-exploitation campaigns also use login bypasses and SQL injection (MOVEit, the 2022 Fortinet firewall campaign), so the class was widened to any network-reachable vulnerability that CVSS rates high on confidentiality, integrity and availability. Misconfigurations and stolen credentials stay out: they are not software vulnerabilities.

**3. "The most dangerous class" for Charts 1 and 2: no login, no click, internet-facing enterprise software.** This is the class behind nearly every mass break-in in Chart 8, and the one sensors observe best. Charts 3 and 5 use the whole reference class, because the question there is where the flood of new records landed.

**4. Time is the date of publication.** Exploitation dates are known for few vulnerabilities; publication dates for all. The cost is that recent cohorts have had less time to be attacked, which the estimates in decision 8 try to repair.

**5. The snapshot ends on November 9, 2026.** The download was made on November 10. That day's 12 records are a partial day and are skipped so every chart covers the same period.

## Mass exploitation

**6. A definition built on evidence of scale, not on "known exploited".** CISA's catalog says a vulnerability was exploited, not how widely. The essay's argument is about broad harm, so a vulnerability must have evidence of scale: ransomware or botnet use, a government or Rapid7 list of widely exploited vulnerabilities, a place in a quarterly top-100 sensor list, or a named campaign with a victim count.

**7. What the final audit removed from that definition.** Reviewing every flagged record before publication showed three kinds of evidence that did not mean scale. The count of mass-exploited records fell from 501 to 465.

| Removed | Why | Example |
|---|---|---|
| The July–September 2024 sighting list | It predates the Shadowserver honeypot feed (October 24, 2024); entries have as few as one sighting. 33 records were flagged by it alone | |
| Sensor rankings for client software | The sensors are honeypots for servers; a client vulnerability reaches a sighting list through mentions, not attacks | Chrome CVE-2025-2783, Apple CVE-2025-43300 |
| Spyware-vendor use and zero-day reviews as evidence of scale | They say who used a vulnerability, not how widely | Barracuda CVE-2023-7102 |

The removals cut both ways for the essay's argument: they lower counts for hyperscalers' client software and for server vendors alike.

## Estimates

**8. Estimate 2026 instead of showing raw counts.** Raw counts make recent quarters look safe simply because evidence has not arrived. Showing them would understate attacks; the estimates carry stated ranges and back-tests instead. _Requested after seeing a first version in which the last bar was misleadingly short._

**9. October–December: pace, not rate.** The first version multiplied projected publications by the previous quarter's attacked share. Back-tested on 13 quarters that ran 17% high with a typical miss of 29%, because attacks have not kept pace with publications. The rule now used (what is published so far, lag-adjusted, plus the rest of the quarter at the previous quarter's pace of attacked vulnerabilities) was 1% high with a typical miss of 19%. The change moved the last bar from about 47 to about 40.

**10. CISA listing delays measured only on vulnerabilities published since 2022.** CISA's catalog began in November 2021 and listed older vulnerabilities in bulk, which makes their delays meaningless. Including them made the adjustment 2.4 times too large in testing.

**11. No special color or hatching for estimated bars.** A bracket and a callout say which bars contain estimates. _The author's design choice_: a second color read as a different category of data.

## Makers

**12. Google, Apple, Meta and Amazon as the model group; Microsoft shown apart.** _Made after seeing the data._ With all five hyperscalers together, the group's share of vulnerabilities mass-exploited since 2019 was no better than everyone else's. The difference inside the group is who installs the fix: Microsoft leaves customers to patch Exchange, SharePoint and Windows Server, and those products account for most of its mass-exploited vulnerabilities. Splitting on that line is the essay's thesis, and it is also a choice that makes the thesis look better. The four's record rests mostly on Google and Apple.

**13. "Mid-market and smaller vendors" at under $5bn of revenue, including vendors with no revenue on record.** The threshold separates the companies with large security organizations from the rest. About 1,800 vendor names of commercial enterprise and industrial products have no revenue figure; they are almost certainly small, so they are grouped with the mid-market and the label says so.

**14. The unclassified are not merged into the mid-market.** About 2,900 of 2026's vulnerabilities are in software whose maker could not be classified. Some belong to small commercial vendors. Merging them would rest the headline on a guess, so they stay in "plug-ins and small projects", the chart's footnote says so, and the essay gives the result both ways (a tenth to a fifth of vulnerabilities; about half of mass exploitation either way).

**15. Corrections by rule, not by outcome.** Hand corrections (`data/group_overrides.csv`) were made for systematic errors found by scanning vendor names: name collisions with hyperscalers (appleple, chromedriver), subsidiaries (GitHub and LinkedIn to Microsoft, VirusTotal to Google), companies over $5bn filed as mid-market, and community open-source projects filed as mid-market. Four misfilings found later by reading only the mass-exploited records were left alone (see LIMITATIONS.md, item 7): fixing only exploited records would bias the comparison.

**16. Device makers left out of Chart 3.** Router and camera vulnerabilities are used by botnets that researchers identify months later. Their 2026 count reads zero, which would look like safety. They are computed and reported in `output/chart3_numbers.json`.

## Chart 4

**17. Zero-days as the test of "who installs the fix".** For an ordinary vulnerability, whether it is mass-exploited depends on whether attackers bother to build an exploit at all. A zero-day is one attackers already hold, so what happens next depends mostly on how fast the fix reaches machines. Comparing zero-days in vendor-updated and customer-patched products isolates that step better than comparing all vulnerabilities, at the cost of small numbers (20 and 52).

**18. Bug bounties replaced by the hyperscaler comparison.** _The author's choice after the bounty test showed nothing._ The bounty, pledge, age and R&D tests are still run (`src/maturity.py`) and reported in the methodology section as null results.

**19. Telemetry shown as untested.** The essay argues product telemetry matters. No public record says which vendors mine it, so the chart says so instead of dropping the row.

## Budgets

**20. Two routes, pooled, with wide ranges.** A head-count route and a spending route are each weak; where they agree the estimate is more credible. The pooled spread is widened by half because the routes share a judgment (the share of engineering effort that is application security). The earlier chart used three point estimates supplied by the author; they were replaced by ranges for four companies on one method, with Microsoft in the footnote.

**21. The sentence the estimates forced us to change.** The draft said a hyperscaler's application-security budget "exceeds" mid-market revenue. On these estimates it is about the size of the median ($0.5bn to $0.9bn against $0.6bn), so the post says that.

## Presentation

**22. "Vulnerabilities" throughout.** Earlier charts said "flaws"; the essay says "vulnerabilities" and "bugs". Charts and text now use the essay's words.

**23. Counts on Chart 8 are quoted as their sources give them**, with the unit on each bar, because they measure different things and adding or normalizing them would invent precision.
