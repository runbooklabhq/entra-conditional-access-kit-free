<#
 Conditional Access Baseline Kit: Top 5 - read-only checks (Runbook Lab)
 Read-only: Get-* cmdlets and Microsoft Graph GET requests only. Changes nothing in your tenant.
 Requires: Microsoft.Graph PowerShell SDK (Microsoft.Graph.Identity.SignIns, .Reports, .Identity.DirectoryManagement).
 Connect first:
   Connect-MgGraph -Scopes Policy.Read.All,AuditLog.Read.All,UserAuthenticationMethod.Read.All,Directory.Read.All
 Role: Global Reader or Security Reader is enough for these reads.
 Output: .\hardening-check-results.csv (ID, Control, Status, Output).
#>
$ErrorActionPreference = 'Stop'
$results = @()
function Invoke-Check($Id, $Title, [scriptblock]$Block) {
  try { $o = & $Block | Out-String -Width 400; $s = 'OK' } catch { $o = $_.Exception.Message; $s = 'ERROR' }
  Write-Host "[$Id] $Title -> $s"
  $script:results += [pscustomobject]@{ ID = $Id; Control = $Title; Status = $s; Output = $o.Trim() }
}

Invoke-Check 'CA01' 'Create two emergency access accounts, exclude them from every policy and alert on their use' { $p = Get-MgIdentityConditionalAccessPolicy -All; $p | Where-Object { $_.State -ne 'disabled' } | ForEach-Object { "$($_.DisplayName) | $($_.State) | excluded users: $(@($_.Conditions.Users.ExcludeUsers).Count) | excluded groups: $(@($_.Conditions.Users.ExcludeGroups).Count)" }; "Active policies with NO user or group exclusion (break-glass not excluded?): $(@($p | Where-Object { $_.State -ne 'disabled' -and -not $_.Conditions.Users.ExcludeUsers -and -not $_.Conditions.Users.ExcludeGroups }).Count)" }
Invoke-Check 'CA02' 'Name policies by persona and create every new policy in Report-only first' { $p = Get-MgIdentityConditionalAccessPolicy -All; $p | Sort-Object DisplayName | ForEach-Object { "$($_.DisplayName) | $($_.State) | modified: $($_.ModifiedDateTime)" }; $p | Group-Object State | ForEach-Object { "State $($_.Name): $($_.Count)" } }
Invoke-Check 'CA03' 'Require MFA for all users on all resources with an authentication strength' { $p = Get-MgIdentityConditionalAccessPolicy -All; $m = $p | Where-Object { $_.Conditions.Users.IncludeUsers -contains 'All' -and $_.Conditions.Applications.IncludeApplications -contains 'All' -and ($_.GrantControls.BuiltInControls -contains 'mfa' -or $_.GrantControls.AuthenticationStrength.Id) }; "All users + all resources MFA policies: $(@($m).Count)"; $m | ForEach-Object { "$($_.DisplayName) | $($_.State) | strength: $($_.GrantControls.AuthenticationStrength.DisplayName) | built-in: $($_.GrantControls.BuiltInControls -join ',')" }; $r = Get-MgReportAuthenticationMethodUserRegistrationDetail -All; "Users not registered for MFA: $(@($r | Where-Object { -not $_.IsMfaRegistered }).Count) of $(@($r).Count)" }
Invoke-Check 'CA04' 'Block legacy authentication for all users' { $p = Get-MgIdentityConditionalAccessPolicy -All; $b = $p | Where-Object { $_.GrantControls.BuiltInControls -contains 'block' -and ($_.Conditions.ClientAppTypes -contains 'exchangeActiveSync' -or $_.Conditions.ClientAppTypes -contains 'other') }; "Legacy-auth block policies: $(@($b).Count)"; $b | ForEach-Object { "$($_.DisplayName) | $($_.State)" }; $since = (Get-Date).ToUniversalTime().AddDays(-7).ToString('yyyy-MM-ddTHH:mm:ssZ'); Get-MgAuditLogSignIn -Filter "createdDateTime ge $since" -Top 1000 | Group-Object ClientAppUsed | Sort-Object Count -Descending | ForEach-Object { "Client app '$($_.Name)': $($_.Count) sign-ins (last 7 days, first 1000)" } }
Invoke-Check 'CA05' 'Require phishing-resistant MFA for administrators' { $p = Get-MgIdentityConditionalAccessPolicy -All; $a = $p | Where-Object { $_.Conditions.Users.IncludeRoles -and ($_.GrantControls.AuthenticationStrength.Id -eq '00000000-0000-0000-0000-000000000004' -or $_.GrantControls.AuthenticationStrength.DisplayName -like 'Phishing*') }; "Admin phishing-resistant policies: $(@($a).Count)"; $a | ForEach-Object { "$($_.DisplayName) | $($_.State) | roles: $(@($_.Conditions.Users.IncludeRoles).Count)" }; Get-MgReportAuthenticationMethodUserRegistrationDetail -All | Where-Object { $_.IsAdmin } | ForEach-Object { "Admin $($_.UserPrincipalName) | methods: $($_.MethodsRegistered -join ',')" } }

$results | Export-Csv -NoTypeInformation -Encoding UTF8 .\hardening-check-results.csv
Write-Host "Done: $($results.Count) checks -> hardening-check-results.csv"
