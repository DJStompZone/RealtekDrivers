<#
.SYNOPSIS
    Downloads a Realtek driver bundle ZIP, extracts it, and installs the contained drivers with pnputil.

.DESCRIPTION
    This script automates Realtek driver installation end-to-end

.PARAMETER ZipUrl
    The HTTPS URL of the driver ZIP to download.

.PARAMETER DestDir
    Directory to download/extract into. Defaults to a new folder under $env:TEMP named RealtekDrivers_<timestamp>.

.PARAMETER Sha256
    Optional expected SHA256 checksum of the ZIP. If provided, the file will be verified before extraction.

.PARAMETER KeepArchive
    If specified, the downloaded ZIP is kept after extraction. By default, it is removed on success.

.PARAMETER WhatIf
    Shows what would happen if the command runs. No files are modified and no drivers are installed.

.EXAMPLE
    PS> .\Install-RealtekDrivers.ps1 -ZipUrl "https://example.com/RealtekDrivers.zip" -Verbose

.NOTES
    Author: DJ Stomp <85457381+DJStompZone@users.noreply.github.com>
    License: MIT
    GitHub: https://github.com/djstompzone/RealtekDrivers
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ZipUrl,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$DestDir,

    [Parameter(Mandatory = $false)]
    [ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [string]$Sha256,

    [switch]$KeepArchive
)

function Assert-Admin {
    <#
    .SYNOPSIS
        Ensures the script is running elevated; relaunches with RunAs if not.
    #>
    $current = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($current)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Verbose "Elevation required; relaunching as Administrator."
        $psi = @{
            FilePath   = (Get-Process -Id $PID).Path
            Verb       = 'RunAs'
            ArgumentList = @(
                '-NoProfile',
                '-ExecutionPolicy', 'Bypass',
                '-File', ('"{0}"' -f $MyInvocation.MyCommand.Definition),
                '-ZipUrl', ('"{0}"' -f $ZipUrl)
            ) + ($(if ($DestDir) { @('-DestDir', ('"{0}"' -f $DestDir)) } else { @() })) + ($(if ($Sha256) { @('-Sha256', $Sha256) } else { @() })) + ($(if ($KeepArchive) { @('-KeepArchive') } else { @() })) + ($(if ($PSBoundParameters['Verbose']) { @('-Verbose') } else { @() })) + ($(if ($WhatIfPreference) { @('-WhatIf') } else { @() }))
        }
        try {
            Start-Process @psi | Out-Null
        } catch {
            throw "Failed to relaunch elevated: $_"
        }
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
            Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing -Headers @{ 'User-Agent' = 'Realtek-Installer/1.0' }
            if (-not (Test-Path $OutFile)) { throw "Download did not produce a file." }
            if ((Get-Item $OutFile).Length -lt 1024) { Write-Warning "Downloaded file is suspiciously small."; }
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
    if ($actual -ne $Expected) {
        throw "Checksum mismatch for $Path. Expected $Expected but got $actual."
    }
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
        GitHub release ZIPs typically create a single top-level folder like Repo-1.2.3. If there is exactly one child directory and no files at the top level, we treat that child as the real root.
    #>
    param([Parameter(Mandatory = $true)][string]$ExtractDir)
    $topFiles = Get-ChildItem -LiteralPath $ExtractDir -Force
    $dirs = $topFiles | Where-Object { $_.PSIsContainer }
    $files = $topFiles | Where-Object { -not $_.PSIsContainer }
    if ($dirs.Count -eq 1 -and $files.Count -eq 0) {
        Write-Verbose "Detected single-folder root: $($dirs[0].FullName)"
        return $dirs[0].FullName
    }
    return $ExtractDir
}

function Get-DriverInfPaths {
    <#
    .SYNOPSIS
        Returns the list of expected driver INF paths under a given root.
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

function Install-Drivers {
    <#
    .SYNOPSIS
        Installs a set of INF files using pnputil.
    #>
    param([Parameter(Mandatory = $true)][string[]]$InfPaths)
    $installed = 0
    foreach ($path in $InfPaths) {
        if (-not (Test-Path -LiteralPath $path)) {
            Write-Warning "Missing INF (skipping): $path"
            continue
        }
        $msg = "pnputil /add-driver `"$path`" /install"
        if ($PSCmdlet.ShouldProcess($path, "Install driver via pnputil")) {
            try {
                Write-Verbose $msg
                $out = & pnputil /add-driver "$path" /install 2>&1
                $installed++
                $out | Write-Output
            } catch {
                Write-Warning "Install failed: $path : $_"
            }
        } else {
            Write-Host "[WhatIf] Would install: $path"
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

    $infPaths = Get-DriverInfPaths -Root $Root
    Write-Verbose ("Will process these INFs:`n" + ($infPaths -join "`n"))

    $count = Install-Drivers -InfPaths $infPaths
    Write-Host "Driver install attempts (existing files only): $count"

    if (-not $KeepArchive -and (Test-Path $ZipPath)) {
        if ($PSCmdlet.ShouldProcess($ZipPath, "Remove archive")) {
            Remove-Item -LiteralPath $ZipPath -Force
            Write-Verbose "Removed archive: $ZipPath"
        } else {
            Write-Host "[WhatIf] Would remove archive: $ZipPath"
        }
    }

    Write-Host "Done. If some INFs were missing, check the ZIP layout or update the INF list."
} catch {
    Write-Error $_
    exit 1
}