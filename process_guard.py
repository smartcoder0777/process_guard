import argparse
import os
import signal
import sys
import time
from datetime import datetime, timezone

import psutil

BUILD_ID = "process-guard-ppid-v1"

# Common prefix of known malware cmdlines; use --match-mode substring to match any variant.
MALWARE_CMD_PREFIX = "74B286833FFBA0D2DB1B6BA3F58858AB"

DEFAULT_MATCH_TOKENS = [
    # Exact full cmdlines (use with --match-mode exact) or substrings (use with --match-mode substring).
    MALWARE_CMD_PREFIX,  # substring: catches any cmdline containing this prefix
    "74B286833FFBA0D2DB1B6BA3F58858AB78771BEF49F10A4FACE60B07C4E9DF0F",
    "74B286833FFBA0D2DB1B6BA3F58858ABD2A140ACA150E1C84708EF246C107F36",
    "74B286833FFBA0D2DB1B6BA3F58858AB515824129EA5872251C6ADBA3001D1B2",
]

DEFAULT_CRITICAL_PROCESS_NAMES = {
    # Default denylist to avoid bricking Windows if a token matches broadly.
    # You can override with --allow-critical if you *really* intend to kill these.
    "csrss.exe",
    "lsass.exe",
    "services.exe",
    "smss.exe",
    "svchost.exe",
    "system",
    "wininit.exe",
    "winlogon.exe",
}


def utc_ts() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def safe_lower(s: str | None) -> str:
    return (s or "").lower()


def cmdline_text(proc: psutil.Process) -> str:
    try:
        parts = proc.cmdline()
        return " ".join(parts) if parts else ""
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        return ""
    except Exception:
        return ""

def cmdline_parts(proc: psutil.Process) -> list[str]:
    try:
        parts = proc.cmdline()
        return list(parts) if parts else []
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        return []
    except Exception:
        return []


def exe_path(proc: psutil.Process) -> str:
    try:
        return proc.exe() or ""
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        return ""
    except Exception:
        return ""


def parent_info(proc: psutil.Process) -> tuple[int | None, str, str, str, int | None]:
    """
    Returns (ppid, parent_name, parent_exe, parent_cmdline, parent_ppid). If unavailable, ppid may be None.
    """
    try:
        ppid = proc.ppid()
    except Exception:
        return None, "", "", "", None
    try:
        p = psutil.Process(ppid)
        pname = p.name() or ""
        pexe = p.exe() or ""
        try:
            parent_ppid = p.ppid()
        except Exception:
            parent_ppid = None
        try:
            pcmd = " ".join(p.cmdline() or [])
        except Exception:
            pcmd = ""
        return ppid, pname, pexe, pcmd, parent_ppid
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        return ppid, "", "", "", None
    except Exception:
        return ppid, "", "", "", None


def log_line(log_path: str, line: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(log_path)), exist_ok=True)
    with open(log_path, "a", encoding="utf-8", errors="replace") as f:
        f.write(line.rstrip("\n") + "\n")


def write_pid_file(pid_file: str, pid: int) -> None:
    if not pid_file:
        return
    os.makedirs(os.path.dirname(os.path.abspath(pid_file)), exist_ok=True)
    with open(pid_file, "w", encoding="utf-8") as f:
        f.write(str(pid))


def remove_pid_file(pid_file: str) -> None:
    if not pid_file:
        return
    try:
        os.remove(pid_file)
    except Exception:
        pass


def matches(
    cmdline: str,
    parts: list[str],
    match_tokens: list[str],
    *,
    case_sensitive: bool,
    match_mode: str,
) -> bool:
    """
    match_mode:
      - substring: token is a substring of the full command line string
      - exact: full command line string equals token
      - arg: any single argv item equals token
    """
    if match_mode not in {"substring", "exact", "arg"}:
        match_mode = "substring"

    if match_mode == "arg":
        if not parts:
            return False
        if case_sensitive:
            return any(t and any(p == t for p in parts) for t in match_tokens)
        parts_l = [safe_lower(p) for p in parts]
        return any(t and (safe_lower(t) in parts_l) for t in match_tokens)

    if not cmdline:
        return False
    if case_sensitive:
        if match_mode == "exact":
            return any(t and (cmdline == t) for t in match_tokens)
        return any(t and (t in cmdline) for t in match_tokens)

    hay = safe_lower(cmdline)
    if match_mode == "exact":
        return any(t and (hay == safe_lower(t)) for t in match_tokens)
    return any(t and (safe_lower(t) in hay) for t in match_tokens)


def is_critical_name(name: str) -> bool:
    return safe_lower(name).strip() in DEFAULT_CRITICAL_PROCESS_NAMES


def try_terminate(proc: psutil.Process, timeout_s: float) -> tuple[bool, str]:
    """
    Returns (success, detail).
    """
    try:
        proc.terminate()
        try:
            proc.wait(timeout=timeout_s)
            return True, "terminated"
        except psutil.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=timeout_s)
            return True, "killed"
    except psutil.NoSuchProcess:
        return True, "already-exited"
    except psutil.AccessDenied:
        return False, "access-denied"
    except Exception as e:
        return False, f"error:{type(e).__name__}"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Defensive process guard: detect/optionally terminate processes whose command line contains specific tokens."
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Print build/version info and exit.",
    )
    parser.add_argument(
        "--match",
        action="append",
        default=[],
        help="Token/substring to match in command line. Can be provided multiple times.",
    )
    parser.add_argument(
        "--match-mode",
        choices=["substring", "exact", "arg"],
        default="substring",
        help="How to match --match tokens: substring (default), exact, or arg.",
    )
    parser.add_argument(
        "--only-name",
        action="append",
        default=[],
        help="Optional: only act on processes whose name matches one of these (e.g. svchost.exe). Can be provided multiple times.",
    )
    parser.add_argument(
        "--case-sensitive",
        action="store_true",
        help="Use case-sensitive matching (default: case-insensitive).",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=2.0,
        help="Polling interval in seconds (default: 2.0).",
    )
    parser.add_argument(
        "--run-for",
        type=float,
        default=0.0,
        help="Optional: run for N seconds then exit (0 = run until stopped).",
    )
    parser.add_argument(
        "--log",
        default=os.path.join(os.path.dirname(__file__), "process_guard.log"),
        help="Log file path (default: ./process_guard.log).",
    )
    parser.add_argument(
        "--pid-file",
        default="",
        help="Optional: write this process PID to a file while running (useful for stopping a background run).",
    )
    parser.add_argument(
        "--exe-contains",
        action="append",
        default=[],
        help="Optional: require substring(s) in the executable path. Can be provided multiple times.",
    )
    parser.add_argument(
        "--enforce",
        action="store_true",
        help="Actually terminate matching processes. If omitted, runs in dry-run mode.",
    )
    parser.add_argument(
        "--kill-timeout",
        type=float,
        default=3.0,
        help="Seconds to wait after terminate() before kill() (default: 3.0).",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run one scan and exit (useful for testing).",
    )
    parser.add_argument(
        "--include-self",
        action="store_true",
        help="Allow matching/terminating this guard process (default: off).",
    )
    parser.add_argument(
        "--allow-critical",
        action="store_true",
        help="Allow terminating critical Windows process names (DANGEROUS). Default: blocked.",
    )
    args = parser.parse_args()

    if args.version:
        print(f"{BUILD_ID} script={os.path.abspath(__file__)} python={sys.version.split()[0]}")
        return 0

    match_tokens = list(DEFAULT_MATCH_TOKENS)
    match_tokens.extend(args.match or [])
    match_tokens = [t for t in match_tokens if t and t.strip()]

    exe_contains = [t for t in (args.exe_contains or []) if t and t.strip()]
    only_names = [safe_lower(n).strip() for n in (args.only_name or []) if n and n.strip()]

    if not match_tokens:
        print("No match tokens provided.", file=sys.stderr)
        return 2

    stop = False

    def _handle_stop(signum, frame):
        nonlocal stop
        stop = True

    for s in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(s, _handle_stop)
        except Exception:
            pass

    mode = "ENFORCE" if args.enforce else "DRY-RUN"
    header = (
        f"[{utc_ts()}] start build={BUILD_ID} script={os.path.abspath(__file__)} log={os.path.abspath(args.log)} "
        f"mode={mode} interval={args.interval}s case_sensitive={args.case_sensitive} "
        f"tokens={match_tokens} match_mode={args.match_mode} exe_contains={exe_contains} only_name={only_names} allow_critical={args.allow_critical}"
    )
    log_line(args.log, header)
    print(header)

    self_pid = os.getpid()
    write_pid_file(args.pid_file, self_pid)

    started_at = time.time()

    while not stop:
        for proc in psutil.process_iter(attrs=["pid", "name", "username"]):
            pid = proc.info.get("pid")
            if pid is None:
                continue
            if (not args.include_self) and pid == self_pid:
                continue

            name = proc.info.get("name") or ""
            user = proc.info.get("username") or ""
            exe = exe_path(proc)
            ppid, parent_name, parent_exe, parent_cmdline, parent_ppid = parent_info(proc)

            if only_names:
                if safe_lower(name).strip() not in only_names:
                    continue

            parts = cmdline_parts(proc)
            cl = " ".join(parts) if parts else cmdline_text(proc)
            if not matches(cl, parts, match_tokens, case_sensitive=args.case_sensitive, match_mode=args.match_mode):
                continue

            if exe_contains:
                if not matches(exe, [exe], exe_contains, case_sensitive=args.case_sensitive, match_mode="substring"):
                    continue

            critical_blocked = (not args.allow_critical) and is_critical_name(name)

            if critical_blocked:
                line = (
                    f"[{utc_ts()}] match pid={pid} name={name!r} user={user!r} exe={exe!r} "
                    f"ppid={ppid} parent_ppid={parent_ppid} parent_name={parent_name!r} parent_exe={parent_exe!r} parent_cmdline={parent_cmdline!r} "
                    f"action=skip(critical-name) cmdline={cl!r} argv={parts!r}"
                )
            elif args.enforce:
                ok, detail = try_terminate(proc, timeout_s=args.kill_timeout)
                line = (
                    f"[{utc_ts()}] match pid={pid} name={name!r} user={user!r} exe={exe!r} "
                    f"ppid={ppid} parent_ppid={parent_ppid} parent_name={parent_name!r} parent_exe={parent_exe!r} parent_cmdline={parent_cmdline!r} "
                    f"action={detail} ok={ok} cmdline={cl!r} argv={parts!r}"
                )
            else:
                line = (
                    f"[{utc_ts()}] match pid={pid} name={name!r} user={user!r} exe={exe!r} "
                    f"ppid={ppid} parent_ppid={parent_ppid} parent_name={parent_name!r} parent_exe={parent_exe!r} parent_cmdline={parent_cmdline!r} "
                    f"action=none(dry-run) cmdline={cl!r} argv={parts!r}"
                )

            log_line(args.log, line)
            print(line)

        if args.once:
            break
        if args.run_for and (time.time() - started_at) >= args.run_for:
            break
        time.sleep(max(0.2, args.interval))

    footer = f"[{utc_ts()}] stop"
    log_line(args.log, footer)
    print(footer)
    remove_pid_file(args.pid_file)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

