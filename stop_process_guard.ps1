$ErrorActionPreference = "Stop"

$root = $PSScriptRoot
$pidFile = Join-Path $root "process_guard.pid"

if (-not (Test-Path $pidFile)) {
    "No PID file found ($pidFile). If the guard is running, stop it via Task Manager."
    exit 0
}

$pidText = (Get-Content -Path $pidFile -ErrorAction Stop | Select-Object -First 1).Trim()
if (-not $pidText) {
    "PID file is empty ($pidFile)."
    exit 1
}

$guardPid = [int]$pidText

try {
    Stop-Process -Id $guardPid -Force -ErrorAction Stop
    "Stopped process_guard PID=$guardPid"
} catch {
    "Failed to stop PID=$guardPid (maybe already exited): $($_.Exception.Message)"
}

try { Remove-Item -Force $pidFile -ErrorAction SilentlyContinue | Out-Null } catch {}

