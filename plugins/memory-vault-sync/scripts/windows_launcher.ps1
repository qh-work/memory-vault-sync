[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("session-start", "user-prompt-submit", "stop")]
    [string]$Event
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Get-NormalizedAbsolutePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw "A required path is empty."
    }
    $expanded = [Environment]::ExpandEnvironmentVariables($Path)
    if (-not [IO.Path]::IsPathRooted($expanded)) {
        throw "A required path is not absolute."
    }
    return [IO.Path]::GetFullPath($expanded)
}

function Test-PathWithin {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Root
    )

    $fullPath = Get-NormalizedAbsolutePath -Path $Path
    $fullRoot = Get-NormalizedAbsolutePath -Path $Root
    if ($fullPath.Equals($fullRoot, [StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }
    $separatorChars = [char[]]@(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
    $rootPrefix = $fullRoot.TrimEnd($separatorChars) +
        [IO.Path]::DirectorySeparatorChar
    return $fullPath.StartsWith(
        $rootPrefix,
        [StringComparison]::OrdinalIgnoreCase
    )
}

function Test-IsUnsafeInterpreterPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string[]]$ForbiddenRoots
    )

    foreach ($root in $ForbiddenRoots) {
        if ([string]::IsNullOrWhiteSpace($root)) {
            continue
        }
        try {
            if (Test-PathWithin -Path $Path -Root $root) {
                return $true
            }
        }
        catch {
            return $true
        }
    }
    return $false
}

if ([string]::IsNullOrWhiteSpace($env:PLUGIN_ROOT)) {
    throw "Codex did not provide PLUGIN_ROOT."
}

$pluginRoot = Get-NormalizedAbsolutePath -Path $env:PLUGIN_ROOT
$vaultScript = Get-NormalizedAbsolutePath -Path (
    Join-Path $pluginRoot "scripts\vault_sync.py"
)
if (-not (Test-PathWithin -Path $vaultScript -Root $pluginRoot)) {
    throw "The Memory Vault script resolved outside PLUGIN_ROOT."
}
if (-not (Test-Path -LiteralPath $vaultScript -PathType Leaf)) {
    throw "The Memory Vault script is missing."
}
$vaultScriptItem = Get-Item -LiteralPath $vaultScript -Force
if (($vaultScriptItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "The Memory Vault script cannot be a reparse point."
}

$forbiddenRoots = @(
    [IO.Path]::GetFullPath($PWD.Path),
    $env:TEMP,
    $env:TMP,
    $env:PLUGIN_DATA,
    $pluginRoot
)

# Resolve Python only from PEP 514 registration. Never invoke a bare `py` or
# `python` command, because Windows command lookup can be influenced by a
# workspace or PATH entry.
$candidatePaths = @()
$registryHives = @(
    [Microsoft.Win32.RegistryHive]::LocalMachine,
    [Microsoft.Win32.RegistryHive]::CurrentUser
)
$registryViews = @(
    [Microsoft.Win32.RegistryView]::Registry64,
    [Microsoft.Win32.RegistryView]::Registry32
)
$securityModule = Join-Path (
    Get-NormalizedAbsolutePath -Path $PSHOME
) "Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1"
if (-not (Test-Path -LiteralPath $securityModule -PathType Leaf)) {
    throw "The built-in PowerShell security module is missing."
}
Import-Module -Name $securityModule -Force -ErrorAction Stop

foreach ($hive in $registryHives) {
    foreach ($view in $registryViews) {
        $baseKey = $null
        $pythonCoreKey = $null
        try {
            $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, $view)
            $pythonCoreKey = $baseKey.OpenSubKey(
                "Software\Python\PythonCore",
                $false
            )
            if ($null -eq $pythonCoreKey) {
                continue
            }
            foreach ($tag in $pythonCoreKey.GetSubKeyNames()) {
                $installKey = $null
                try {
                    $installKey = $pythonCoreKey.OpenSubKey(
                        "$tag\InstallPath",
                        $false
                    )
                    if ($null -eq $installKey) {
                        continue
                    }
                    $executablePath = [string]$installKey.GetValue(
                        "ExecutablePath"
                    )
                    if (-not [string]::IsNullOrWhiteSpace($executablePath)) {
                        $candidatePaths += $executablePath
                    }
                    $installRoot = [string]$installKey.GetValue("")
                    if (-not [string]::IsNullOrWhiteSpace($installRoot)) {
                        $candidatePaths += Join-Path $installRoot "python.exe"
                    }
                }
                finally {
                    if ($null -ne $installKey) {
                        $installKey.Dispose()
                    }
                }
            }
        }
        finally {
            if ($null -ne $pythonCoreKey) {
                $pythonCoreKey.Dispose()
            }
            if ($null -ne $baseKey) {
                $baseKey.Dispose()
            }
        }
    }
}

$pythonExe = $null
$seenCandidates = @{}
foreach ($rawCandidate in $candidatePaths) {
    try {
        $candidate = Get-NormalizedAbsolutePath -Path $rawCandidate
    }
    catch {
        continue
    }
    $candidateKey = $candidate.ToLowerInvariant()
    if ($seenCandidates.ContainsKey($candidateKey)) {
        continue
    }
    $seenCandidates[$candidateKey] = $true
    if (Test-IsUnsafeInterpreterPath `
            -Path $candidate `
            -ForbiddenRoots $forbiddenRoots) {
        continue
    }
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        continue
    }
    $candidateItem = Get-Item -LiteralPath $candidate -Force
    if (($candidateItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        continue
    }
    $signature = Microsoft.PowerShell.Security\Get-AuthenticodeSignature `
        -FilePath $candidate
    if ([string]$signature.Status -ne "Valid") {
        continue
    }
    try {
        & $candidate -I -c (
            "import sys; raise SystemExit(" +
            "0 if sys.version_info >= (3, 10) else 91)"
        ) *> $null
        $versionExitCode = $LASTEXITCODE
    }
    catch {
        continue
    }
    if ($versionExitCode -eq 0) {
        $pythonExe = $candidate
        break
    }
}

if ([string]::IsNullOrWhiteSpace([string]$pythonExe)) {
    throw (
        "No signed Python 3.10+ interpreter was found through PEP 514. " +
        "Install a signed python.org build for all users."
    )
}

$env:MEMORY_VAULT_POWERSHELL_HOST = (
    [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
)
& $pythonExe -I $vaultScript "hook" $Event
if ($null -eq $LASTEXITCODE) {
    exit 1
}
exit [int]$LASTEXITCODE
