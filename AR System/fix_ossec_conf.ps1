$ErrorActionPreference = "Stop"
$ConfigPath = "C:\Program Files (x86)\ossec-agent\ossec.conf"
$BackupPath = "C:\Program Files (x86)\ossec-agent\ossec.conf.bak"

Write-Host "Reading ossec.conf..."
$lines = Get-Content $ConfigPath

# create backup
Copy-Item $ConfigPath $BackupPath -Force

$newLines = @()
$skip = $false

foreach ($line in $lines) {
    if ($line -match "ars_events.json") {
        # This is a line we want to remove (we will add the clean one later)
        # We also want to remove the surrounding <localfile> tags if possible, 
        # but simpler is just to filter out the bad lines if they are single-line blocks.
        # However, XML implies multi-line.
        
        # Let's try a different approach: Reconstruction.
        continue
    }
    
    # Primitive XML cleaning: 
    # If we are inside a <localfile> block that contains our target, we drop it.
    # But since we can't easily look ahead/behind in a simple loop without state...
    
    $newLines += $line
}

# The above loop is risky if the config is multiline. 
# Let's just APPEND the correct one and assume the old ones are failing silently or harmlessly?
# NO, the user says "still not showing". Conflicting configs can break the agent (it might not start).

# BETTER APPROACH: Use regex to remove the whole block textually.
$text = [System.IO.File]::ReadAllText($ConfigPath)

# Regex to find <localfile>...ars_events.json...</localfile>
# The (?s) flag makes . match newlines.
$pattern = "(?s)<localfile>.*?ars_events\.json.*?</localfile>"

# Remove all instances of our previous attempts
$cleanText = $text -replace $pattern, ""

# Now remove any empty lines left behind or weird artifacts if any
# (Optional, but good for hygiene)

# Construct the CLEAN block
$cleanBlock = @"

  <!-- Added by AR System (Clean) -->
  <localfile>
    <location>C:\ProgramData\AR_System\ars_events.json</location>
    <log_format>json</log_format>
  </localfile>
</ossec_config>
"@

# The regex replace might have removed the closing </ossec_config> if it was adjacent.
# But usually localfiles are in the middle.
# Let's simple append the block BEFORE the last </ossec_config> tag.

# Remove the closing tag temporarily
$cleanText = $cleanText -replace "</ossec_config>", ""

# Append our block and the closing tag
$finalText = $cleanText.Trim() + $cleanBlock

# Write back
[System.IO.File]::WriteAllText($ConfigPath, $finalText)

Write-Host "Cleaned and Updated ossec.conf."
Restart-Service -Name WazuhSvc
Write-Host "Agent Restarted."
