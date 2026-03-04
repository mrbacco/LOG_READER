#!/usr/bin/env python3
"""
mrbacco04@gmail.com
March 2026

Offline syslog reader.

Usage examples:
  python syslog_reader.py -f ./syslog.log
  python syslog_reader.py -f ./syslog.log --contains ssh --level err,warning
  python syslog_reader.py -f ./syslog.log --since "Mar  4 10:00:00"
  python syslog_reader.py -f ./syslog.log --log-level DEBUG
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import logging
import pathlib
import re
import sys
from typing import Iterable

# RFC 3164 style: "Mar  4 10:02:13 host app[123]: message"
RFC3164_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<tag>[^:]+):\s*"
    r"(?P<msg>.*)$"
)

# Keyword-to-level hints used when the raw line does not contain explicit severity metadata.
LEVEL_HINTS = {
    "emerg": ("emerg", "panic", "fatal"),
    "alert": ("alert",),
    "crit": ("crit", "critical"),
    "err": ("err", "error", "failed", "failure"),
    "warning": ("warn", "warning"),
    "notice": ("notice",),
    "info": ("info",),
    "debug": ("debug",),
}

# Shared logger for this module.
LOGGER = logging.getLogger("BAC_LOG.reader")


@dataclasses.dataclass
class SyslogEntry:
    # Original full line from the log.
    raw: str
    # Parsed timestamp (or None if the line did not match known timestamp formats).
    ts: dt.datetime | None
    # Parsed source host.
    host: str | None
    # Parsed application tag, e.g. "sshd[221]".
    tag: str | None
    # Parsed message body.
    msg: str
    # Inferred severity level from message content.
    level: str | None


def configure_logging(log_level: str) -> None:
    # Centralized logging config with BAC_LOG marker so logs stand out in terminal output.
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s [BAC_LOG] [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    LOGGER.debug("Logging configured at level=%s", log_level.upper())


def infer_level(message: str) -> str | None:
    # Fast keyword scan to map free-text lines into a syslog-like severity bucket.
    lower = message.lower()
    for level, hints in LEVEL_HINTS.items():
        if any(h in lower for h in hints):
            return level
    return None


def parse_line(line: str, default_year: int) -> SyslogEntry:
    # Remove only trailing newline so spacing in the raw line remains intact.
    text = line.rstrip("\n")
    match = RFC3164_RE.match(text)
    if not match:
        # Keep non-RFC lines accessible instead of dropping them.
        return SyslogEntry(
            raw=text,
            ts=None,
            host=None,
            tag=None,
            msg=text,
            level=infer_level(text),
        )

    ts_text = match.group("ts")
    parsed_ts = None
    try:
        # Many syslog files omit year, so we inject a caller-supplied default year.
        parsed_ts = dt.datetime.strptime(f"{default_year} {ts_text}", "%Y %b %d %H:%M:%S")
    except ValueError:
        LOGGER.debug("Timestamp parse failed for line: %s", text)
        parsed_ts = None

    msg = match.group("msg")
    return SyslogEntry(
        raw=text,
        ts=parsed_ts,
        host=match.group("host"),
        tag=match.group("tag"),
        msg=msg,
        level=infer_level(msg),
    )


def parse_entries(path: pathlib.Path, encoding: str = "utf-8-sig") -> Iterable[SyslogEntry]:
    # Stream entries one-by-one so large log files do not need to fit in memory.
    year = dt.datetime.now().year
    LOGGER.info("Reading log file: %s (encoding=%s)", path, encoding)
    with path.open("r", encoding=encoding, errors="replace") as handle:
        for line in handle:
            if line.strip():
                yield parse_line(line, year)


def parse_datetime(value: str) -> dt.datetime:
    # Accept both ISO-like and classic syslog datetime formats.
    fmts = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%b %d %H:%M:%S",
        "%b  %d %H:%M:%S",
    ]
    now = dt.datetime.now()
    for fmt in fmts:
        try:
            parsed = dt.datetime.strptime(value, fmt)
            if "%Y" not in fmt:
                parsed = parsed.replace(year=now.year)
            return parsed
        except ValueError:
            continue
    raise argparse.ArgumentTypeError(
        f"Invalid datetime '{value}'. Use 'YYYY-MM-DD HH:MM:SS' or 'Mon DD HH:MM:SS'."
    )


def build_arg_parser() -> argparse.ArgumentParser:
    # All supported CLI filters and runtime options are declared in one place.
    parser = argparse.ArgumentParser(description="Read and filter syslog files offline.")
    parser.add_argument("-f", "--file", required=True, type=pathlib.Path, help="Path to syslog file")
    parser.add_argument("--contains", help="Only lines containing this text (case-insensitive)")
    parser.add_argument(
        "--level",
        help="Comma-separated levels: emerg,alert,crit,err,warning,notice,info,debug",
    )
    parser.add_argument("--since", type=parse_datetime, help="Only include entries at/after this timestamp")
    parser.add_argument("--until", type=parse_datetime, help="Only include entries at/before this timestamp")
    parser.add_argument("--encoding", default="utf-8-sig", help="Input file encoding (default: utf-8-sig)")
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Python logger level for BAC_LOG diagnostics (default: INFO)",
    )
    return parser


def should_keep(
    entry: SyslogEntry,
    contains: str | None,
    allowed_levels: set[str] | None,
    since: dt.datetime | None,
    until: dt.datetime | None,
) -> bool:
    # Text filter.
    if contains and contains.lower() not in entry.raw.lower():
        return False

    # Severity filter.
    if allowed_levels is not None and (entry.level not in allowed_levels):
        return False

    # Start-time boundary filter.
    if since is not None:
        if entry.ts is None or entry.ts < since:
            return False

    # End-time boundary filter.
    if until is not None:
        if entry.ts is None or entry.ts > until:
            return False

    return True


def format_entry(entry: SyslogEntry) -> str:
    # Stable output format for terminal use and redirection to text files.
    ts = entry.ts.isoformat(sep=" ") if entry.ts else "N/A"
    host = entry.host or "N/A"
    tag = entry.tag or "raw"
    level = entry.level or "unknown"
    return f"[{ts}] [{host}] [{tag}] [{level}] {entry.msg}"


def main(argv: list[str] | None = None) -> int:
    # Prevent UnicodeEncodeError on legacy Windows consoles.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")

    parser = build_arg_parser()
    args = parser.parse_args(argv)

    configure_logging(args.log_level)
    LOGGER.info("Starting CLI syslog read")

    if not args.file.exists():
        LOGGER.error("File not found: %s", args.file)
        print(f"Error: file not found: {args.file}", file=sys.stderr)
        return 2

    levels = None
    if args.level:
        levels = {x.strip().lower() for x in args.level.split(",") if x.strip()}
        LOGGER.info("Severity filter active: %s", ",".join(sorted(levels)))

    if args.contains:
        LOGGER.info("Contains filter active: %s", args.contains)
    if args.since:
        LOGGER.info("Since filter active: %s", args.since.isoformat(sep=" "))
    if args.until:
        LOGGER.info("Until filter active: %s", args.until.isoformat(sep=" "))

    matches = 0
    processed = 0
    for entry in parse_entries(args.file, args.encoding):
        processed += 1
        if should_keep(entry, args.contains, levels, args.since, args.until):
            print(format_entry(entry))
            matches += 1

    LOGGER.info("Finished processing lines=%s matches=%s", processed, matches)
    if matches == 0:
        print("No matching entries found.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
