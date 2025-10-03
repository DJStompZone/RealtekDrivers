<#
.SYNOPSIS
    Downloads a Realtek driver bundle ZIP, extracts it, and installs the contained drivers with pnputil.

.DESCRIPTION
    This script automates Realtek driver installation end-to-end:
      1) Ensures elevation (UAC admin).
      2) Downloads a ZIP (e.g., GitHub release asset).
      3) Optionally verifies SHA256.
      4) Extracts to a deterministic directory and detects the true root.
      5) Installs drivers via pnputil using a known list of INF paths or a recursive scan.

.PARAMETER ZipUrl
    HTTPS URL of the driver ZIP to download. Defaults to your repo ZIP.

.PARAMETER DestDir
    Directory to download/extract into. Defaults to $env:TEMP\RealtekDrivers_<timestamp>.

.PARAMETER Sha256
    Optional expected SHA256 checksum (64 hex chars). If provided, the ZIP is verified before extraction.

.PARAMETER KeepArchive
    Keep the downloaded ZIP after extraction. By default it is removed on success.

.PARAMETER ScanAllInfs
    If set, recursively scan under the detected root for all *.inf files and attempt to install each with pnputil.
    When used, /subdirs is implied unnecessary since we feed pnputil concrete file paths.

.PARAMETER PnPUtilExtra
    Optional extra arguments to pass through to pnputil for each install (e.g., '/reboot'). Do not include /add-driver or /install here.

.PARAMETER WhatIf
    Shows what would happen without changing anything (respects SupportsShouldProcess).

.EXAMPLE
    PS> .\Install-RealtekDrivers.ps1 -Verbose
    Uses default ZipUrl, extracts, and installs the known INF set.

.EXAMPLE
    PS> .\Install-RealtekDrivers.ps1 -ZipUrl "https://github.com/DJStompZone/RealtekDrivers/raw/refs/heads/main/RealtekDrivers.zip" -Sha256 "4e99478a6a2a0e6abb93f5316d7b8503e7ebe6607c5e3e733079f204b3b36610" -ScanAllInfs -Verbose

.NOTES
    Author: DJ Stomp <85457381+DJStompZone@users.noreply.github.com>
    License: MIT
    GitHub: https://github.com/djstompzone/RealtekDrivers
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
[OutputType([int])]
param(
    [Parameter(Mandatory = $False)]
    [ValidateNotNullOrEmpty()]
    [string]$ZipUrl = "https://github.com/DJStompZone/RealtekDrivers/raw/refs/heads/main/RealtekDrivers.zip",

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$DestDir,

    [Parameter(Mandatory = $false)]
    [ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [string]$Sha256 = "4e99478a6a2a0e6abb93f5316d7b8503e7ebe6607c5e3e733079f204b3b36610",

    [switch]$KeepArchive,

    [switch]$ScanAllInfs,

    [Parameter(Mandatory = $false)]
    [string]$PnPUtilExtra
)

# Nudge old WMF into modern TLS so Invoke-WebRequest doesn't throw a tantrum.
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}

function Assert-Admin {
    <#
    .SYNOPSIS
        Ensures the script is running elevated; relaunches with RunAs if not.
    #>
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = [Security.Principal.WindowsPrincipal]::new($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Verbose "Elevation required; relaunching as Administrator."
        $pwsh = (Get-Process -Id $PID).Path
        $args = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $MyInvocation.MyCommand.Definition, '-ZipUrl', $ZipUrl)
        if ($DestDir)      { $args += @('-DestDir', $DestDir) }
        if ($Sha256)       { $args += @('-Sha256', $Sha256) }
        if ($KeepArchive)  { $args += @('-KeepArchive') }
        if ($ScanAllInfs)  { $args += @('-ScanAllInfs') }
        if ($PnPUtilExtra) { $args += @('-PnPUtilExtra', $PnPUtilExtra) }
        if ($PSBoundParameters['Verbose']) { $args += @('-Verbose') }
        if ($WhatIfPreference) { $args += @('-WhatIf') }
        $psi = @{ FilePath = $pwsh; Verb = 'RunAs'; ArgumentList = $args }
        try { Start-Process @psi | Out-Null } catch { throw "Failed to relaunch elevated: $_" }
        exit 0
    }
}

function Invoke-RetryDownload {
    <#
    .SYNOPSIS
        Downloads a file with simple retry/backoff.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][string]$OutFile,
        [int]$MaxAttempts = 4,
        [int]$BaseDelaySeconds = 2
    )
    $attempt = 0
    while ($attempt -lt $MaxAttempts) {
        $attempt++
        try {
            Write-Verbose "Downloading ($attempt/$MaxAttempts): $Url -> $OutFile"
            Invoke-WebRequest -Uri $Url -OutFile $OutFile -Headers @{ 'User-Agent' = 'Realtek-Installer/1.0' }
            if (-not (Test-Path $OutFile)) { throw "Download did not produce a file." }
            if ((Get-Item $OutFile).Length -lt 1024) { Write-Warning "Downloaded file is suspiciously small." }
            return Get-Item $OutFile
        } catch {
            if ($attempt -ge $MaxAttempts) { throw "Download failed after $MaxAttempts attempts: $_" }
            $delay = [Math]::Pow(2, $attempt - 1) * $BaseDelaySeconds
            Write-Warning "Download attempt $attempt failed: $_. Retrying in $delay seconds..."
            Start-Sleep -Seconds $delay
        }
    }
}

function Test-FileSha256 {
    <#
    .SYNOPSIS
        Validates SHA256 checksum of a file.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Expected
    )
    $actual = (Get-FileHash -Path $Path -Algorithm SHA256).Hash
    if ($actual -ne $Expected) { throw "Checksum mismatch for $Path. Expected $Expected but got $actual." }
    Write-Verbose "Checksum OK: $actual"
}

function Expand-ZipDeterministic {
    <#
    .SYNOPSIS
        Extracts a ZIP to a clean destination (creates or empties it).
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ZipPath,
        [Parameter(Mandatory = $true)][string]$ExtractDir
    )
    if (Test-Path $ExtractDir) {
        Write-Verbose "Clearing existing directory: $ExtractDir"
        if ($PSCmdlet.ShouldProcess($ExtractDir, "Remove-Item -Recurse -Force")) { Remove-Item -LiteralPath $ExtractDir -Recurse -Force }
    }
    if ($PSCmdlet.ShouldProcess($ExtractDir, "New-Item -ItemType Directory")) { New-Item -ItemType Directory -Path $ExtractDir -Force | Out-Null }
    Write-Verbose "Expanding archive: $ZipPath -> $ExtractDir"
    Expand-Archive -LiteralPath $ZipPath -DestinationPath $ExtractDir -Force
    return Get-Item $ExtractDir
}

function Get-UnzippedRoot {
    <#
    .SYNOPSIS
        Figures out the actual content root inside the extracted directory.
    .DESCRIPTION
        If there is exactly one child directory and no top-level files, treat that as root (typical GitHub zip layout).
    #>
    param([Parameter(Mandatory = $true)][string]$ExtractDir)
    $top = Get-ChildItem -LiteralPath $ExtractDir -Force
    $dirs  = $top | Where-Object { $_.PSIsContainer }
    $files = $top | Where-Object { -not $_.PSIsContainer }
    if ($dirs.Count -eq 1 -and $files.Count -eq 0) {
        Write-Verbose "Detected single-folder root: $($dirs[0].FullName)"
        return $dirs[0].FullName
    }
    return "$ExtractDir\Realtek"
}

function Get-DriverInfPaths {
    <#
    .SYNOPSIS
        Returns the list of expected driver INF paths under a given root (static list).
    #>
    param([Parameter(Mandatory = $true)][string]$Root)
    $rel = @(
        "Realtek\ExtRtk_9658.1\HDX_MorshowExt_RTK.inf",
        "Realtek\Codec_9658.1\HDXMorshow.inf",
        "Realtek\Codec_9658.1\HDXSSTMorshow.inf",
        "Realtek\RealtekAPO_12_1167\RealtekAPO.inf",
        "Realtek\RealtekAPO_13_1167\RealtekAPO.inf",
        "Realtek\RealtekHSA_327\RealtekHSA.inf",
        "Realtek\RealtekService_744\RealtekService.inf"
    )
    return $rel | ForEach-Object { Join-Path $Root $_ }
}

function Get-InfPathsRecursive {
    <#
    .SYNOPSIS
        Recursively finds all *.inf files under a given root.
    .DESCRIPTION
        Filters out common non-driver crumbs like 'autorun.inf' at the root; otherwise returns all INFs.
    #>
    param([Parameter(Mandatory = $true)][string]$Root)
    $all = Get-ChildItem -LiteralPath $Root -Recurse -Include *.inf -ErrorAction SilentlyContinue
    # Basic filter: skip root-level autorun.inf type files
    $filtered = $all | Where-Object { $_.Name -notmatch '^(autorun|setup)\.inf$' }
    return $filtered.FullName
}

function Install-Drivers {
    <#
    .SYNOPSIS
        Installs a set of INF files using pnputil.
    #>
    param(
        [Parameter(Mandatory = $true)][string[]]$InfPaths,
        [string]$ExtraArgs
    )
    $installed = 0
    foreach ($path in $InfPaths) {
        if (-not (Test-Path -LiteralPath $path)) {
            Write-Warning "Missing INF (skipping): $path"
            continue
        }
        $argList = @('/add-driver', $path, '/install')
        if ($ExtraArgs) {
            # split on whitespace but keep quoted groups
            $argList += [System.Management.Automation.PSParser]::Tokenize($ExtraArgs, [ref]$null) | Where-Object { $_.Type -eq 'String' } | ForEach-Object { $_.Content }
        }
        $pretty = 'pnputil ' + ($argList | ForEach-Object { if ($_ -match '\s') { '"{0}"' -f $_ } else { $_ } }) -join ' '
        if ($PSCmdlet.ShouldProcess($path, "Install driver via pnputil")) {
            try {
                Write-Verbose $pretty
                $out = & pnputil @argList 2>&1
                $installed++
                $out | Write-Output
            } catch {
                Write-Warning "Install failed: $path : $_"
            }
        } else {
            Write-Host "[WhatIf] Would install: $pretty"
        }
    }
    return $installed
}

# =========================
# Main
# =========================

try {
    Assert-Admin

    if (-not $DestDir) {
        $stamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
        $DestDir = Join-Path $env:TEMP "RealtekDrivers_$stamp"
    }
    $ZipPath = Join-Path $DestDir "bundle.zip"

    Write-Verbose "Destination directory: $DestDir"
    if (-not (Test-Path $DestDir)) {
        if ($PSCmdlet.ShouldProcess($DestDir, "Create directory")) { New-Item -ItemType Directory -Path $DestDir -Force | Out-Null }
    }

    if ($PSCmdlet.ShouldProcess($ZipPath, "Download ZIP")) {
        Invoke-RetryDownload -Url $ZipUrl -OutFile $ZipPath | Out-Null
    } else {
        Write-Host "[WhatIf] Would download: $ZipUrl -> $ZipPath"
    }

    if ($Sha256) {
        if ($PSCmdlet.ShouldProcess($ZipPath, "Verify SHA256")) {
            Test-FileSha256 -Path $ZipPath -Expected $Sha256
        } else {
            Write-Host "[WhatIf] Would verify SHA256 for: $ZipPath"
        }
    }

    $ExtractDir = Join-Path $DestDir "extracted"
    if ($PSCmdlet.ShouldProcess($ExtractDir, "Extract archive")) {
        Expand-ZipDeterministic -ZipPath $ZipPath -ExtractDir $ExtractDir | Out-Null
    } else {
        Write-Host "[WhatIf] Would extract: $ZipPath -> $ExtractDir"
    }

    $Root = Get-UnzippedRoot -ExtractDir $ExtractDir
    Write-Verbose "Content root: $Root"

    $infPaths = if ($ScanAllInfs) {
        Write-Verbose "Scanning recursively for *.inf under $Root"
        Get-InfPathsRecursive -Root $Root
    } else {
        Get-DriverInfPaths -Root $Root
    }

    if (-not $infPaths -or $infPaths.Count -eq 0) {
        throw "No INF files were found to install. Check the ZIP layout or use -ScanAllInfs."
    }

    Write-Verbose ("Will process these INFs:`n" + ($infPaths -join "`n"))

    $count = Install-Drivers -InfPaths $infPaths -ExtraArgs $PnPUtilExtra
    Write-Host "Driver install attempts (existing files only): $count"

    if (-not $KeepArchive -and (Test-Path $ZipPath)) {
        if ($PSCmdlet.ShouldProcess($ZipPath, "Remove archive")) {
            Remove-Item -LiteralPath $ZipPath -Force
            Write-Verbose "Removed archive: $ZipPath"
        } else {
            Write-Host "[WhatIf] Would remove archive: $ZipPath"
        }
    }

    Write-Host "Done. If some INFs were skipped or failed, check the ZIP and pnputil output above."
    # Return a non-negative integer (attempt count) as exit code for CI scripting ergonomics.
    exit ([int][Math]::Max(0, $count))
} catch {
    Write-Error $_
    exit 1
}