#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Turn XFilter client (ClientST) on or off without uninstalling or stopping NetActvity.

.PARAMETER Off   Disable ClientST until you run -On.
.PARAMETER On    Restore the .exe and start the client.
.PARAMETER Status Show on/off (default).
#>
[CmdletBinding(DefaultParameterSetName = 'Status')]
param(
    [Parameter(ParameterSetName = 'Off')][switch]$Off,
    [Parameter(ParameterSetName = 'On')][switch]$On,
    [Parameter(ParameterSetName = 'Status')][switch]$Status
)

$ErrorActionPreference = 'Stop'
$InstallDir = 'C:\Program Files (x86)\XFilter'
$ExeName = 'ClientST.exe'
$Active = Join-Path $InstallDir $ExeName
$Disabled = "$Active.disabled"

function Get-ClientPaths {
    if (Test-Path -LiteralPath $Active) {
        return @{ Active = $Active; Disabled = $Disabled }
    }
    if (Test-Path -LiteralPath $Disabled) {
        return @{ Active = $null; Disabled = $Disabled }
    }
    throw "ClientST.exe not found under $InstallDir (expected $ExeName or ClientST.exe.disabled)."
}

function Stop-ClientProcess {
    Get-Process -Name 'ClientST' -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Milliseconds 800
    Get-Process -Name 'ClientST' -ErrorAction SilentlyContinue | Stop-Process -Force
}

function Get-ClientState {
    $paths = Get-ClientPaths
    $running = Get-Process -Name 'ClientST' -ErrorAction SilentlyContinue
    if ($paths.Active) {
        [PSCustomObject]@{
            State   = if ($running) { 'ON (running)' } else { 'ON (not running)' }
            Exe     = $ExeName
            Process = if ($running) { "PID $($running.Id)" } else { '(none)' }
        }
    }
    else {
        [PSCustomObject]@{
            State   = 'OFF'
            Exe     = 'ClientST.exe.disabled'
            Process = if ($running) { 'still running — try -Off again as Admin' } else { '(none)' }
        }
    }
}

switch ($PSCmdlet.ParameterSetName) {
    'Status' {
        $s = Get-ClientState
        $net = Get-Service NetActvity -ErrorAction SilentlyContinue
        Write-Host "XFilter client: $($s.State)"
        Write-Host "  File:     $($s.Exe)"
        Write-Host "  Process:  $($s.Process)"
        if ($net) { Write-Host "NetActvity: $($net.Status)" }
        return
    }
    'Off' {
        Stop-ClientProcess
        $paths = Get-ClientPaths
        if (-not $paths.Active) {
            Write-Host 'XFilter client is already OFF.'
            return
        }
        Rename-Item -LiteralPath $paths.Active -NewName 'ClientST.exe.disabled'
        Start-Sleep -Seconds 6
        $still = Get-Process -Name 'ClientST' -ErrorAction SilentlyContinue
        if ($still) {
            Write-Warning "Process still running (PID $($still.Id)). Run this script as Administrator."
        }
        else {
            Write-Host 'XFilter client is OFF. NetActvity was not stopped.'
        }
        return
    }
    'On' {
        $paths = Get-ClientPaths
        if ($paths.Active) {
            if (-not (Get-Process -Name 'ClientST' -ErrorAction SilentlyContinue)) {
                Start-Process -FilePath $paths.Active -WorkingDirectory $InstallDir
            }
            Write-Host 'XFilter client is already ON.'
            return
        }
        Rename-Item -LiteralPath $paths.Disabled -NewName $ExeName
        Start-Process -FilePath $Active -WorkingDirectory $InstallDir
        Write-Host 'XFilter client is ON.'
        return
    }
}
