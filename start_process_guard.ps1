param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $GuardArgs
)

$ErrorActionPreference = "Stop"

$root = $PSScriptRoot
$guardPy = Join-Path $root "process_guard.py"
$pidFile = Join-Path $root "process_guard.pid"
$logFile = Join-Path $root "process_guard.log"

if (-not (Test-Path $guardPy)) {
    throw "Missing $guardPy"
}

# If you don't pass arguments, use a safe default targeting only the hash svchost.
if (-not $GuardArgs -or $GuardArgs.Count -eq 0) {
    $GuardArgs = @(
        "--only-name", "svchost.exe",
        "--match-mode", "exact",
        "--allow-critical",
        "--enforce"
    )
}

$pythonCmd = Get-Command "pythonw.exe" -ErrorAction SilentlyContinue
if (-not $pythonCmd) { $pythonCmd = Get-Command "python.exe" -ErrorAction Stop }

$hasLog = @($GuardArgs | Where-Object { $_ -ieq "--log" }).Count -gt 0
$hasPidFile = @($GuardArgs | Where-Object { $_ -ieq "--pid-file" }).Count -gt 0

$argList = @(
    $guardPy
) + $GuardArgs

if (-not $hasPidFile) {
    $argList += @("--pid-file", $pidFile)
}
if (-not $hasLog) {
    $argList += @("--log", $logFile)
}

$p = Start-Process -FilePath $pythonCmd.Path -ArgumentList $argList -WorkingDirectory $root -WindowStyle Hidden -PassThru

"Started process_guard PID=$($p.Id)"

$logMsg = $logFile
if ($hasLog) { $logMsg = "(custom --log provided)" }

$pidMsg = $pidFile
if ($hasPidFile) { $pidMsg = "(custom --pid-file provided)" }

"Log: $logMsg"
"PID file: $pidMsg"

