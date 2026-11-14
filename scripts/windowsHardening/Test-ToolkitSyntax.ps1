#requires -Version 5.1
# Read-only syntax validation. Run in Windows PowerShell 5.1 before using modules.
# Parsing does NOT execute a hardening script or prove client compatibility.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$failures=0
$files=@(Get-ChildItem -LiteralPath $PSScriptRoot -Recurse -File | Where-Object { $_.Extension -in @('.ps1','.psm1') })
foreach ($file in $files) {
    $tokens=$null
    $parseErrors=$null
    $null=[Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$parseErrors)
    if ($parseErrors.Count) {
        $failures+=$parseErrors.Count
        foreach ($e in $parseErrors) { Write-Host "$($file.Name):$($e.Extent.StartLineNumber) $($e.Message)" -ForegroundColor Red }
    }
}
if ($failures) { throw "$failures parse errors." }
Write-Host "Syntax passed: $($files.Count) scripts/modules; PowerShell $($PSVersionTable.PSVersion)."
