$ErrorActionPreference = "Stop"
$ConfigPath = "C:\Program Files (x86)\ossec-agent\ossec.conf"

Write-Host "Loading ossec.conf as XML..."
try {
    [xml]$xml = Get-Content $ConfigPath
}
catch {
    Write-Error "Could not parse XML. The file might be corrupted bytes."
    exit 1
}

# Select all localfile nodes
$localFiles = $xml.ossec_config.localfile

$removedCount = 0

# We iterate backwards to safely remove from collection
for ($i = $localFiles.Count - 1; $i -ge 0; $i--) {
    $node = $localFiles[$i]
    if ($node.location -match "OneDrive" -and $node.location -match "ars_events.json") {
        Write-Host "Reducing Corrupt Node: $($node.location)"
        $xml.ossec_config.RemoveChild($node) | Out-Null
        $removedCount++
    }
}

if ($removedCount -gt 0) {
    Write-Host "Removed $removedCount bad entries."
    $xml.Save($ConfigPath)
    Write-Host "Saved Clean Config."
    Restart-Service -Name WazuhSvc
    Write-Host "Agent Restarted."
}
else {
    Write-Host "No bad entries found via XML parsing. File might be clean?"
}
