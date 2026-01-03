$ErrorActionPreference = "Stop"
$ConfigPath = "C:\Program Files (x86)\ossec-agent\ossec.conf"
$Content = [System.IO.File]::ReadAllText($ConfigPath)

# Define the bad block exact text (we use regex to slightly flexible on whitespace)
# We search for <localfile> ... OneDrive ... </localfile>
$Pattern = "(?s)\s*<localfile>\s*<location>.*?OneDrive.*?ars_events\.json</location>\s*<log_format>json</log_format>\s*</localfile>"

# Replace with empty string
$NewContent = $Content -replace $Pattern, ""

# Write back
[System.IO.File]::WriteAllText($ConfigPath, $NewContent)

Write-Host "Repaired ossec.conf: Removed Bad Block."
Restart-Service -Name WazuhSvc
Write-Host "Agent Restarted."
