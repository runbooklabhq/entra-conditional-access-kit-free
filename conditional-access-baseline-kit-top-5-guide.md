# Conditional Access Baseline Kit: Top 5

_Version 1.0 (2026-10-28; facts re-read on Microsoft Learn 2026-10-28; validated: quality gate, read-only guard, PowerShell 7.4 parse, Excel recalc)_

Five Conditional Access controls to put in place first in Microsoft Entra ID: emergency access accounts excluded and monitored, report-only discipline, MFA for all users with an authentication strength, legacy authentication blocked, and phishing-resistant MFA for administrators. Free. Each control has why, steps, impact, rollback, a read-only PowerShell check, how to verify, licence, effort and the Microsoft Learn page it is based on.

Read-only checks: run `conditional-access-baseline-kit-top-5-readonly-checks.ps1` (read-only, changes nothing).

| # | Control | Area | Sprint | Priority | Effort |
|---|---|---|---|---|---|
| CA01 | Create two emergency access accounts, exclude them from every policy and alert on their use | Foundation and emergency access | Sprint 1 - Foundation | Highest | 2 h |
| CA02 | Name policies by persona and create every new policy in Report-only first | Foundation and emergency access | Sprint 1 - Foundation | Highest | 1 h |
| CA03 | Require MFA for all users on all resources with an authentication strength | Strong authentication for everyone | Sprint 2 - Enforce MFA and block legacy | Highest | 2 h + 7 days report-only |
| CA04 | Block legacy authentication for all users | Block weak sign-in paths | Sprint 2 - Enforce MFA and block legacy | Highest | 1 h + 7 days report-only |
| CA05 | Require phishing-resistant MFA for administrators | Strong authentication for everyone | Sprint 2 - Enforce MFA and block legacy | Highest | 2 h + 7 days report-only |

## CA01. Create two emergency access accounts, exclude them from every policy and alert on their use

**Why:** A Conditional Access mistake can lock every administrator out of the tenant. Microsoft recommends at least two cloud-only emergency access accounts, excluded from policies that block or restrict access, protected with a passkey (FIDO2) or certificate-based authentication, and monitored so every sign-in raises an alert.

**Steps:**
1. Create two cloud-only accounts on the *.onmicrosoft.com domain with the Global Administrator role assigned permanently. Do not tie them to a person, phone or federated domain.
2. Register a passkey (FIDO2 security key) or certificate-based authentication for each account and store the keys in two separate safe places.
3. Create a group (for example EmergencyAccess) with both accounts and exclude that group from every Conditional Access policy that blocks or restricts access.
4. Send sign-in logs to Log Analytics and create an alert rule: SigninLogs where the UserId is one of the two accounts, severity 0, action group that emails and texts the security team.
5. Put a 90-day review in the calendar: sign in with each account, confirm the alert fires, and check the accounts are still excluded.

**Impact:** None for users. Two privileged accounts exist that bypass policy, which is why they need strong keys and alerting.

**Rollback:** Remove the accounts from the role and disable them if the organisation decides on another recovery process. Do not remove the exclusion while the accounts exist.

**Check (read-only PowerShell):**

```powershell
$p = Get-MgIdentityConditionalAccessPolicy -All; $p | Where-Object { $_.State -ne 'disabled' } | ForEach-Object { "$($_.DisplayName) | $($_.State) | excluded users: $(@($_.Conditions.Users.ExcludeUsers).Count) | excluded groups: $(@($_.Conditions.Users.ExcludeGroups).Count)" }; "Active policies with NO user or group exclusion (break-glass not excluded?): $(@($p | Where-Object { $_.State -ne 'disabled' -and -not $_.Conditions.Users.ExcludeUsers -and -not $_.Conditions.Users.ExcludeGroups }).Count)"
```

**Verify:** Two emergency accounts exist with phishing-resistant credentials; every active policy that blocks or restricts excludes them; a test sign-in raised the alert within minutes.

**Licence:** Accounts: any edition. Alert rule: Azure Monitor / Log Analytics (pay-as-you-go ingestion, usually small). · **Effort:** 2 h · **Priority:** Highest · **Sprint 1 - Foundation**

**Microsoft Learn:** https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access

## CA02. Name policies by persona and create every new policy in Report-only first

**Why:** Policies that are created straight to On are the usual cause of lockouts. Report-only mode evaluates a policy on every sign-in and logs the result without enforcing it, so you see who would be blocked before anyone is. A naming convention (number, persona, app, control) keeps 15+ policies readable.

**Steps:**
1. Agree a naming convention, for example CA001-AllUsers-AllApps-RequireMFA, CA010-Admins-AllApps-PhishingResistant, CA020-AllUsers-Legacy-Block.
2. Run the read-only check to list every policy with its state and last change. Rename existing policies to the convention.
3. Rule for the team: every new or edited policy goes to Report-only for at least 7 days, then On after the sign-in log review.
4. Use What If (Conditional Access > Policies > What If) for a test user before switching a policy to On.

**Impact:** None. Renaming and report-only change nothing for users.

**Rollback:** Nothing to roll back.

**Check (read-only PowerShell):**

```powershell
$p = Get-MgIdentityConditionalAccessPolicy -All; $p | Sort-Object DisplayName | ForEach-Object { "$($_.DisplayName) | $($_.State) | modified: $($_.ModifiedDateTime)" }; $p | Group-Object State | ForEach-Object { "State $($_.Name): $($_.Count)" }
```

**Verify:** Every policy follows the naming convention; new policies show state 'enabledForReportingButNotEnforced' for at least 7 days before 'enabled'.

**Licence:** Microsoft Entra ID P1 (included in Microsoft 365 Business Premium, E3 and E5). · **Effort:** 1 h · **Priority:** Highest · **Sprint 1 - Foundation**

**Microsoft Learn:** https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-report-only · https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-insights-reporting

## CA03. Require MFA for all users on all resources with an authentication strength

**Why:** Microsoft's baseline is one policy for all users and all resources, with no app exclusions, that requires multifactor authentication. Using the built-in 'Multifactor authentication' authentication strength (instead of the older 'Require MFA' checkbox) lets you raise the bar to passwordless or phishing-resistant later without rebuilding the policy.

**Steps:**
1. Run the read-only check: it lists policies that target All users + All resources with MFA or an authentication strength, and counts users who are not registered for MFA.
2. New policy: Users = All users; exclude the EmergencyAccess group and, in hybrid tenants, the Directory Synchronization Accounts role. Target resources = All resources, no exclusions.
3. Grant = Grant access > Require authentication strength > Multifactor authentication. Enable policy = Report-only.
4. After 7 days, open the sign-in logs (Conditional Access / Report-only tab) and the Insights workbook: fix the users who would fail, then switch to On.
5. If you use external authentication methods, use 'Require multifactor authentication' instead: Microsoft says they are not compatible with authentication strength yet.

**Impact:** Every user is asked for MFA when the session is evaluated. Users with no MFA method registered are prompted to register.

**Rollback:** Set the policy back to Report-only (this stops enforcement immediately) or Off.

**Check (read-only PowerShell):**

```powershell
$p = Get-MgIdentityConditionalAccessPolicy -All; $m = $p | Where-Object { $_.Conditions.Users.IncludeUsers -contains 'All' -and $_.Conditions.Applications.IncludeApplications -contains 'All' -and ($_.GrantControls.BuiltInControls -contains 'mfa' -or $_.GrantControls.AuthenticationStrength.Id) }; "All users + all resources MFA policies: $(@($m).Count)"; $m | ForEach-Object { "$($_.DisplayName) | $($_.State) | strength: $($_.GrantControls.AuthenticationStrength.DisplayName) | built-in: $($_.GrantControls.BuiltInControls -join ',')" }; $r = Get-MgReportAuthenticationMethodUserRegistrationDetail -All; "Users not registered for MFA: $(@($r | Where-Object { -not $_.IsMfaRegistered }).Count) of $(@($r).Count)"
```

**Verify:** One policy with All users + All resources + an authentication strength is On; the sign-in logs show no unexpected failures for 7 days.

**Licence:** Microsoft Entra ID P1 (included in Microsoft 365 Business Premium, E3 and E5). Authentication strengths need P1. · **Effort:** 2 h + 7 days report-only · **Priority:** Highest · **Sprint 2 - Enforce MFA and block legacy**

**Microsoft Learn:** https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-mfa-strength · https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths

## CA04. Block legacy authentication for all users

**Why:** Legacy protocols (IMAP, POP, SMTP AUTH from old clients, Exchange ActiveSync with basic credentials) cannot do MFA, so a stolen password is enough. A single Block policy on the legacy client app types closes that path.

**Steps:**
1. Run the read-only check: it lists block policies on legacy client types and groups the last 7 days of sign-ins by client app.
2. New policy: Users = All users, exclude EmergencyAccess and any service account you still have to migrate. Target resources = All resources.
3. Conditions > Client apps > Configure = Yes; select only Exchange ActiveSync clients and Other clients. Grant = Block access. Enable policy = Report-only.
4. Review report-only results for 7 days, move the remaining apps to modern authentication, then switch to On.

**Impact:** Apps and devices that sign in with legacy protocols stop working (old mail clients, scanners using SMTP AUTH with basic credentials, scripts).

**Rollback:** Set the policy to Report-only or Off; add a temporary exclusion for one account while it is migrated.

**Check (read-only PowerShell):**

```powershell
$p = Get-MgIdentityConditionalAccessPolicy -All; $b = $p | Where-Object { $_.GrantControls.BuiltInControls -contains 'block' -and ($_.Conditions.ClientAppTypes -contains 'exchangeActiveSync' -or $_.Conditions.ClientAppTypes -contains 'other') }; "Legacy-auth block policies: $(@($b).Count)"; $b | ForEach-Object { "$($_.DisplayName) | $($_.State)" }; $since = (Get-Date).ToUniversalTime().AddDays(-7).ToString('yyyy-MM-ddTHH:mm:ssZ'); Get-MgAuditLogSignIn -Filter "createdDateTime ge $since" -Top 1000 | Group-Object ClientAppUsed | Sort-Object Count -Descending | ForEach-Object { "Client app '$($_.Name)': $($_.Count) sign-ins (last 7 days, first 1000)" }
```

**Verify:** A legacy-auth block policy is On; the sign-in logs show no successful sign-ins with Exchange ActiveSync or Other clients.

**Licence:** Microsoft Entra ID P1 (included in Microsoft 365 Business Premium, E3 and E5). · **Effort:** 1 h + 7 days report-only · **Priority:** Highest · **Sprint 2 - Enforce MFA and block legacy**

**Microsoft Learn:** https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-legacy-authentication

## CA05. Require phishing-resistant MFA for administrators

**Why:** Administrators are the target of adversary-in-the-middle phishing, which defeats SMS, voice and push. Microsoft recommends the built-in Phishing-resistant MFA strength (passkeys/FIDO2, Windows Hello for Business or platform credential, multifactor certificate-based authentication) for at least 14 admin roles, including Global, Security, Exchange, SharePoint, User, Helpdesk and Conditional Access Administrator.

**Steps:**
1. Run the read-only check: it lists policies that apply the phishing-resistant strength to directory roles and shows the methods each admin has registered.
2. Make sure every admin has registered a passkey or Windows Hello for Business before you enforce (use a Temporary Access Pass to bootstrap).
3. New policy: Users = Directory roles (Global, Application, Authentication, Billing, Cloud Application, Conditional Access, Exchange, Helpdesk, Password, Privileged Authentication, Privileged Role, Security, SharePoint and User Administrator); exclude EmergencyAccess.
4. Target resources = All resources. Grant = Require authentication strength > Phishing-resistant MFA. Enable policy = Report-only, then On after the review.

**Impact:** Admins who have only SMS, voice or Authenticator push are blocked from admin sign-ins until they register a phishing-resistant method.

**Rollback:** Set the policy to Report-only or Off; issue a Temporary Access Pass to an admin who lost their key.

**Check (read-only PowerShell):**

```powershell
$p = Get-MgIdentityConditionalAccessPolicy -All; $a = $p | Where-Object { $_.Conditions.Users.IncludeRoles -and ($_.GrantControls.AuthenticationStrength.Id -eq '00000000-0000-0000-0000-000000000004' -or $_.GrantControls.AuthenticationStrength.DisplayName -like 'Phishing*') }; "Admin phishing-resistant policies: $(@($a).Count)"; $a | ForEach-Object { "$($_.DisplayName) | $($_.State) | roles: $(@($_.Conditions.Users.IncludeRoles).Count)" }; Get-MgReportAuthenticationMethodUserRegistrationDetail -All | Where-Object { $_.IsAdmin } | ForEach-Object { "Admin $($_.UserPrincipalName) | methods: $($_.MethodsRegistered -join ',')" }
```

**Verify:** A policy with the Phishing-resistant MFA strength covers at least the 14 recommended roles and is On; every admin shows a passkey, FIDO2 or Windows Hello method.

**Licence:** Microsoft Entra ID P1 (included in Microsoft 365 Business Premium, E3 and E5). Passkeys (FIDO2) are available in all editions. · **Effort:** 2 h + 7 days report-only · **Priority:** Highest · **Sprint 2 - Enforce MFA and block legacy**

**Microsoft Learn:** https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-admin-phish-resistant-mfa · https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths

---
Not affiliated with or endorsed by Microsoft. Test every change in Report-only or on a pilot group first. Licence names and portal paths change; check Microsoft Learn if a menu has moved.
