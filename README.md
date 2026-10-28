# Conditional Access Baseline Kit: Top 5 (free)

Most Microsoft Entra tenants need the same five Conditional Access controls first: two emergency access accounts that every policy excludes and that raise an alert when used, a report-only habit so no policy goes straight to On, MFA for all users on all resources with an authentication strength, legacy authentication blocked, and phishing-resistant MFA for administrators. This kit checks those five and turns them into a project.

| File | What it is |
|---|---|
| `conditional-access-baseline-kit-top-5-guide.md` | Why, steps, impact, rollback, check, verify, licence, effort and the Microsoft Learn source for each control |
| `conditional-access-baseline-kit-top-5-jira-import.csv` | Jira Cloud import: epics + stories with parent links, priority, sprint and labels |
| `conditional-access-baseline-kit-top-5-tracker.csv` | Same backlog for Planner, Azure DevOps, Excel or Linear |
| `conditional-access-baseline-kit-top-5-project-plan.xlsx` | Excel project plan for teams without Jira: owner, dates, status drop-down, % complete and a progress dashboard |
| `conditional-access-baseline-kit-top-5-readonly-checks.ps1` | Get-* cmdlets and Graph GET requests only. Changes nothing. Writes `hardening-check-results.csv` |

| # | Control |
|---|---|
| CA01 | Create two emergency access accounts, exclude them from every policy and alert on their use |
| CA02 | Name policies by persona and create every new policy in Report-only first |
| CA03 | Require MFA for all users on all resources with an authentication strength |
| CA04 | Block legacy authentication for all users |
| CA05 | Require phishing-resistant MFA for administrators |

## Run the checks
```powershell
Connect-MgGraph -Scopes Policy.Read.All,AuditLog.Read.All,UserAuthenticationMethod.Read.All,Directory.Read.All
./conditional-access-baseline-kit-top-5-readonly-checks.ps1
```
Global Reader or Security Reader is enough. Needs the Microsoft.Graph PowerShell SDK.

## Scope and limits
- Built from Microsoft Learn pages re-read on 28 October 2026 (links in the guide). Validated before release: every control has why, steps, impact, rollback, verify, licence and a Learn source; the script contains read commands only and parses cleanly in PowerShell 7.4; the Excel plan recalculates with no errors. If a check misreads your setup, open an issue.
- Conditional Access needs Microsoft Entra ID P1 (Microsoft 365 Business Premium, E3, E5).
- The Complete kit adds 15 controls: passkeys, Temporary Access Pass, registration campaign, SMS/voice retirement, security info registration, device code flow, sign-in and user risk, session lifetime, token protection, guests, named locations, insights workbook, exclusion reviews and policy backups.

## Complete kit
All 20 controls (passkeys, Temporary Access Pass, SMS/voice retirement, device code flow, risk policies, session lifetime, token protection, guests, quarterly reviews) plus a 12-policy target set and rollout routine: https://runbooklab.gumroad.com/l/entra-conditional-access-kit?utm_source=github&utm_campaign=ca-free-repo

MIT licence. Not affiliated with or endorsed by Microsoft. Create every policy in Report-only first and keep your emergency access accounts excluded.
