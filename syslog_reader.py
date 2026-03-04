#!/usr/bin/env python3
"""
mrbacco04@gmail.com
March 2026

Offline multi-format log reader.

Supported formats:
  - syslog-rfc3164
  - syslog-rfc5424
  - cef
  - leef
  - access (Apache/Nginx common/combined)
  - json
  - netflow (text exports)
  - ipfix (text exports)
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import json
import logging
import pathlib
import re
import sys
from typing import Callable, Iterable

# RFC 3164 style: "Mar  4 10:02:13 host app[123]: message"
RFC3164_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<tag>[^:]+):\s*"
    r"(?P<msg>.*)$"
)

# RFC 5424 style: "<34>1 2026-03-04T12:00:00Z host app 123 ID47 [meta] msg"
RFC5424_RE = re.compile(
    r"^(?P<pri><\d+>)?(?P<version>\d)\s+"
    r"(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+(?P<proc>\S+)\s+(?P<msgid>\S+)\s+(?P<msg>.*)$"
)

# Common/combined access logs from Apache/Nginx.
ACCESS_LOG_RE = re.compile(
    r"^(?P<src_ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"
    r"\"(?P<request>[^\"]*)\"\s+(?P<status>\d{3})\s+(?P<size>\S+)(?:\s+\"[^\"]*\"\s+\"[^\"]*\")?\s*$"
)

# Simple "src -> dst" flow style from tools/exporters.
FLOW_ARROW_RE = re.compile(
    r"^(?P<ts>[\d\-T:\.Z\+ ]+)\s+"
    r"(?P<src>\d{1,3}(?:\.\d{1,3}){3})(?::(?P<src_port>\d+))?\s*->\s*"
    r"(?P<dst>\d{1,3}(?:\.\d{1,3}){3})(?::(?P<dst_port>\d+))?\s+"
    r"(?P<proto>[A-Za-z0-9]+)(?P<rest>.*)$"
)

# Generic key=value scanner used by flow/CEF/LEEF parsing.
KV_RE = re.compile(r"(?P<key>[A-Za-z0-9_.-]+)=(?P<value>\"[^\"]*\"|\S+)")

LOG_TYPE_CHOICES = (
    "syslog-rfc3164",
    "syslog-rfc5424",
    "cef",
    "leef",
    "access",
    "json",
    "netflow",
    "ipfix",
    "kv",
    "raw",
)

SYSLOG_LEVEL_BY_NUMBER = {
    0: "emerg",
    1: "alert",
    2: "crit",
    3: "err",
    4: "warning",
    5: "notice",
    6: "info",
    7: "debug",
}

# Keyword-to-level hints used when the source line has no explicit severity field.
LEVEL_HINTS = {
    "emerg": ("emerg", "emergency", "panic", "fatal"),
    "alert": ("alert",),
    "crit": ("crit", "critical"),
    "err": ("err", "error", "failed", "failure"),
    "warning": ("warn", "warning"),
    "notice": ("notice",),
    "info": ("info", "informational"),
    "debug": ("debug", "trace"),
}

LOGGER = logging.getLogger("BAC_LOG.reader")


@dataclasses.dataclass
class SyslogEntry:
    # Original line as read from file.
    raw: str
    # Parsed timestamp, if recognized.
    ts: dt.datetime | None
    # Log source host/device.
    host: str | None
    # Service/program/tag name.
    tag: str | None
    # Canonical log type label.
    log_type: str
    # Main line message.
    msg: str
    # Normalized severity.
    level: str | None
    # Optional flow/network fields.
    src_ip: str | None = None
    dst_ip: str | None = None
    protocol: str | None = None
    bytes_count: int | None = None
    packets_count: int | None = None


def configure_logging(log_level: str) -> None:
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s [BAC_LOG] [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    LOGGER.debug("Logging configured at level=%s", log_level.upper())


def _safe_int(value: object) -> int | None:
    if value is None:
        return None
    try:
        text = str(value).strip()
        if text == "":
            return None
        return int(float(text))
    except (TypeError, ValueError):
        return None


def _normalize_protocol(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None

    numeric = _safe_int(text)
    if numeric == 6:
        return "TCP"
    if numeric == 17:
        return "UDP"
    if numeric == 1:
        return "ICMP"
    return text.upper()


def normalize_level(value: object) -> str | None:
    if value is None:
        return None

    text = str(value).strip().lower()
    if text == "":
        return None

    number = _safe_int(text)
    if number is not None and 0 <= number <= 7:
        return SYSLOG_LEVEL_BY_NUMBER[number]

    if text in ("emerg", "emergency", "panic", "fatal"):
        return "emerg"
    if text == "alert":
        return "alert"
    if text in ("crit", "critical"):
        return "crit"
    if text in ("err", "error", "failed", "failure"):
        return "err"
    if text in ("warn", "warning"):
        return "warning"
    if text == "notice":
        return "notice"
    if text in ("info", "informational"):
        return "info"
    if text in ("debug", "trace"):
        return "debug"
    return None


def map_cef_severity(value: object) -> str | None:
    number = _safe_int(value)
    if number is None:
        return normalize_level(value)
    if number >= 9:
        return "crit"
    if number >= 7:
        return "err"
    if number >= 5:
        return "warning"
    if number >= 3:
        return "notice"
    if number >= 1:
        return "info"
    return "debug"


def infer_level(message: str) -> str | None:
    lower = message.lower()
    for level, hints in LEVEL_HINTS.items():
        if any(h in lower for h in hints):
            return level
    return None


def parse_timestamp(value: object, default_year: int) -> dt.datetime | None:
    if value is None:
        return None

    text = str(value).strip().strip('"')
    if text in ("", "-"):
        return None

    # Epoch timestamp support (seconds/milliseconds/microseconds).
    if text.isdigit():
        try:
            epoch = int(text)
            if len(text) >= 16:
                return dt.datetime.fromtimestamp(epoch / 1_000_000)
            if len(text) >= 13:
                return dt.datetime.fromtimestamp(epoch / 1_000)
            return dt.datetime.fromtimestamp(epoch)
        except (OSError, OverflowError, ValueError):
            return None

    iso_text = text.replace("Z", "+00:00")
    try:
        iso_parsed = dt.datetime.fromisoformat(iso_text)
        return iso_parsed.replace(tzinfo=None) if iso_parsed.tzinfo else iso_parsed
    except ValueError:
        pass

    fmts = (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%d/%b/%Y:%H:%M:%S %z",
        "%d/%b/%Y:%H:%M:%S",
    )
    for fmt in fmts:
        try:
            parsed = dt.datetime.strptime(text, fmt)
            if "%Y" not in fmt:
                parsed = parsed.replace(year=default_year)
            return parsed.replace(tzinfo=None) if parsed.tzinfo else parsed
        except ValueError:
            continue

    # Parse RFC3164 timestamp forms without relying on strptime's implicit default year.
    for fmt in ("%b %d %H:%M:%S", "%b  %d %H:%M:%S"):
        try:
            parsed = dt.datetime.strptime(f"{default_year} {text}", f"%Y {fmt}")
            return parsed
        except ValueError:
            continue
    return None


def parse_datetime(value: str) -> dt.datetime:
    parsed = parse_timestamp(value, dt.datetime.now().year)
    if parsed is None:
        raise argparse.ArgumentTypeError(
            f"Invalid datetime '{value}'. Use 'YYYY-MM-DD HH:MM:SS' or 'Mon DD HH:MM:SS'."
        )
    return parsed


def parse_key_values(text: str) -> dict[str, str]:
    data: dict[str, str] = {}
    for match in KV_RE.finditer(text):
        key = match.group("key")
        value = match.group("value").strip().strip('"')
        data[key] = value
    return data


def split_escaped(text: str, sep: str, max_parts: int) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    escaped = False

    for ch in text:
        if escaped:
            current.append(ch)
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if ch == sep and len(parts) < max_parts - 1:
            parts.append("".join(current))
            current = []
            continue
        current.append(ch)

    parts.append("".join(current))
    return parts


def parse_rfc3164_line(text: str, default_year: int) -> SyslogEntry | None:
    match = RFC3164_RE.match(text)
    if not match:
        return None

    ts = parse_timestamp(match.group("ts"), default_year)
    msg = match.group("msg")
    return SyslogEntry(
        raw=text,
        ts=ts,
        host=match.group("host"),
        tag=match.group("tag"),
        log_type="syslog-rfc3164",
        msg=msg,
        level=infer_level(msg),
    )


def parse_rfc5424_line(text: str, default_year: int) -> SyslogEntry | None:
    match = RFC5424_RE.match(text)
    if not match:
        return None

    pri_text = match.group("pri")
    level = None
    if pri_text:
        pri_number = _safe_int(pri_text.strip("<>"))
        if pri_number is not None:
            level = normalize_level(pri_number % 8)

    ts = parse_timestamp(match.group("ts"), default_year)
    app = match.group("app")
    proc = match.group("proc")
    msg = match.group("msg")
    if msg.startswith("- "):
        msg = msg[2:]
    if msg == "-":
        msg = ""

    tag = app if app != "-" else None
    if tag and proc and proc != "-":
        tag = f"{tag}[{proc}]"

    if level is None:
        level = infer_level(msg)

    return SyslogEntry(
        raw=text,
        ts=ts,
        host=None if match.group("host") == "-" else match.group("host"),
        tag=tag,
        log_type="syslog-rfc5424",
        msg=msg,
        level=level,
    )


def _parse_syslog_prefix(prefix: str, default_year: int) -> tuple[dt.datetime | None, str | None]:
    trimmed = prefix.strip()
    if not trimmed:
        return None, None

    prefix_match = re.match(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)$", trimmed)
    if not prefix_match:
        return None, None

    ts = parse_timestamp(prefix_match.group("ts"), default_year)
    host = prefix_match.group("host")
    return ts, host


def parse_cef_line(text: str, default_year: int) -> SyslogEntry | None:
    cef_index = text.find("CEF:")
    if cef_index < 0:
        return None

    prefix = text[:cef_index]
    cef_body = text[cef_index:]
    fields = split_escaped(cef_body, "|", 8)
    if len(fields) < 8 or not fields[0].startswith("CEF:"):
        return None

    ts_prefix, host_prefix = _parse_syslog_prefix(prefix, default_year)
    ext = fields[7]
    ext_kv = parse_key_values(ext.replace("\t", " "))

    ts = (
        parse_timestamp(ext_kv.get("rt"), default_year)
        or parse_timestamp(ext_kv.get("start"), default_year)
        or ts_prefix
    )
    host = host_prefix or ext_kv.get("dhost") or ext_kv.get("deviceHostName")

    msg_name = fields[5].strip() or "CEF event"
    msg = msg_name if not ext else f"{msg_name} | {ext}"
    level = map_cef_severity(fields[6]) or normalize_level(ext_kv.get("sev")) or infer_level(msg)

    return SyslogEntry(
        raw=text,
        ts=ts,
        host=host,
        tag=fields[2].strip() or "cef",
        log_type="cef",
        msg=msg,
        level=level,
        src_ip=ext_kv.get("src") or ext_kv.get("sourceAddress"),
        dst_ip=ext_kv.get("dst") or ext_kv.get("destinationAddress"),
        protocol=_normalize_protocol(ext_kv.get("proto") or ext_kv.get("protocol")),
        bytes_count=_safe_int(ext_kv.get("bytesIn") or ext_kv.get("in") or ext_kv.get("bytes")),
        packets_count=_safe_int(ext_kv.get("cnt") or ext_kv.get("packets")),
    )


def parse_leef_line(text: str, default_year: int) -> SyslogEntry | None:
    leef_index = text.find("LEEF:")
    if leef_index < 0:
        return None

    prefix = text[:leef_index]
    leef_body = text[leef_index:]
    fields = leef_body.split("|", 5)
    if len(fields) < 5 or not fields[0].startswith("LEEF:"):
        return None

    ext = fields[5] if len(fields) > 5 else ""
    ext_kv = parse_key_values(ext.replace("\t", " "))

    ts_prefix, host_prefix = _parse_syslog_prefix(prefix, default_year)
    ts = parse_timestamp(ext_kv.get("devTime"), default_year) or parse_timestamp(ext_kv.get("time"), default_year) or ts_prefix
    host = host_prefix or ext_kv.get("devHost") or ext_kv.get("src")

    event_id = fields[4].strip() if len(fields) >= 5 else "LEEF event"
    msg = event_id if not ext else f"{event_id} | {ext}"
    level = normalize_level(ext_kv.get("sev") or ext_kv.get("severity")) or infer_level(msg)

    return SyslogEntry(
        raw=text,
        ts=ts,
        host=host,
        tag=fields[2].strip() if len(fields) > 2 else "leef",
        log_type="leef",
        msg=msg,
        level=level,
        src_ip=ext_kv.get("src"),
        dst_ip=ext_kv.get("dst"),
        protocol=_normalize_protocol(ext_kv.get("proto")),
        bytes_count=_safe_int(ext_kv.get("bytes")),
        packets_count=_safe_int(ext_kv.get("packets")),
    )


def parse_access_log_line(text: str, default_year: int) -> SyslogEntry | None:
    match = ACCESS_LOG_RE.match(text)
    if not match:
        return None

    status = _safe_int(match.group("status")) or 0
    if status >= 500:
        level = "err"
    elif status >= 400:
        level = "warning"
    else:
        level = "info"

    request = match.group("request")
    size = match.group("size")
    msg = f"{request} status={status} size={size}"

    protocol = None
    request_parts = request.split()
    if len(request_parts) >= 3:
        protocol = request_parts[2]

    return SyslogEntry(
        raw=text,
        ts=parse_timestamp(match.group("ts"), default_year),
        host=None,
        tag="access",
        log_type="access",
        msg=msg,
        level=level,
        src_ip=match.group("src_ip"),
        protocol=protocol,
        bytes_count=_safe_int(size),
    )


def _first_present(data: dict[str, object], keys: tuple[str, ...]) -> object | None:
    for key in keys:
        if key in data:
            return data[key]
    return None


def _flow_type_from_keys(keys: set[str], raw_lower: str) -> str | None:
    ipfix_keys = {
        "sourceipv4address",
        "destinationipv4address",
        "octetdeltacount",
        "packetdeltacount",
        "flowstartmilliseconds",
        "protocolidentifier",
    }
    netflow_keys = {
        "src",
        "dst",
        "srcip",
        "dstip",
        "bytes",
        "packets",
        "in_bytes",
        "out_bytes",
    }

    if keys.intersection(ipfix_keys):
        return "ipfix"
    if "ipfix" in raw_lower:
        return "ipfix"
    if "netflow" in raw_lower or "ipflow" in raw_lower:
        return "netflow"
    if {"src", "dst"}.issubset(keys) or {"srcip", "dstip"}.issubset(keys):
        return "netflow"
    if keys.intersection(netflow_keys) and ("flow" in raw_lower):
        return "netflow"
    return None


def parse_flow_line(text: str, default_year: int) -> SyslogEntry | None:
    lower = text.lower()
    kv = parse_key_values(text)

    if kv:
        key_lookup = {k.lower() for k in kv}
        flow_type = _flow_type_from_keys(key_lookup, lower)
        if flow_type is None and "flow" not in lower:
            return None

        ts = (
            parse_timestamp(kv.get("flowStartMilliseconds"), default_year)
            or parse_timestamp(kv.get("flowStartSeconds"), default_year)
            or parse_timestamp(kv.get("timestamp"), default_year)
            or parse_timestamp(kv.get("time"), default_year)
            or parse_timestamp(kv.get("ts"), default_year)
        )
        src_ip = (
            kv.get("sourceIPv4Address")
            or kv.get("src")
            or kv.get("srcip")
            or kv.get("src_ip")
            or kv.get("client_ip")
        )
        dst_ip = (
            kv.get("destinationIPv4Address")
            or kv.get("dst")
            or kv.get("dstip")
            or kv.get("dst_ip")
            or kv.get("server_ip")
        )
        msg = kv.get("msg") or kv.get("message") or text

        return SyslogEntry(
            raw=text,
            ts=ts,
            host=kv.get("host") or kv.get("device") or kv.get("router"),
            tag="flow",
            log_type=flow_type or "kv",
            msg=str(msg),
            level=normalize_level(kv.get("severity") or kv.get("level")) or infer_level(text),
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=_normalize_protocol(kv.get("protocolIdentifier") or kv.get("proto") or kv.get("protocol")),
            bytes_count=_safe_int(
                kv.get("octetDeltaCount") or kv.get("bytes") or kv.get("in_bytes") or kv.get("out_bytes")
            ),
            packets_count=_safe_int(kv.get("packetDeltaCount") or kv.get("packets")),
        )

    arrow = FLOW_ARROW_RE.match(text)
    if not arrow:
        return None

    rest_kv = parse_key_values(arrow.group("rest"))
    msg = f"{arrow.group('src')} -> {arrow.group('dst')} {arrow.group('proto')} {arrow.group('rest').strip()}".strip()
    return SyslogEntry(
        raw=text,
        ts=parse_timestamp(arrow.group("ts"), default_year),
        host=None,
        tag="flow",
        log_type="netflow",
        msg=msg,
        level=infer_level(text),
        src_ip=arrow.group("src"),
        dst_ip=arrow.group("dst"),
        protocol=_normalize_protocol(arrow.group("proto")),
        bytes_count=_safe_int(rest_kv.get("bytes")),
        packets_count=_safe_int(rest_kv.get("packets")),
    )


def parse_json_line(text: str, default_year: int) -> SyslogEntry | None:
    stripped = text.lstrip()
    if not stripped.startswith("{"):
        return None
    try:
        obj = json.loads(stripped)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None

    ts = parse_timestamp(
        _first_present(obj, ("@timestamp", "timestamp", "time", "ts", "eventTime")),
        default_year,
    )

    host_obj = _first_present(obj, ("host", "hostname", "device", "observer"))
    host = str(host_obj) if host_obj is not None else None

    tag_obj = _first_present(obj, ("app", "service", "program", "logger", "tag"))
    tag = str(tag_obj) if tag_obj is not None else "json"

    msg_obj = _first_present(obj, ("message", "msg", "event", "log"))
    msg = str(msg_obj) if msg_obj is not None else text

    level = normalize_level(_first_present(obj, ("level", "severity", "sev", "logLevel"))) or infer_level(msg)

    lower_keys = {k.lower() for k in obj}
    raw_lower = text.lower()
    explicit_type = _first_present(obj, ("type", "log_type", "format", "eventType"))
    type_text = str(explicit_type).strip().lower() if explicit_type is not None else ""
    if type_text in ("ipflow", "netflow"):
        log_type = "netflow"
    elif type_text in ("ipfix", "cef", "leef", "access", "syslog-rfc3164", "syslog-rfc5424", "json"):
        log_type = type_text
    else:
        log_type = _flow_type_from_keys(lower_keys, raw_lower) or "json"

    src_obj = _first_present(
        obj,
        ("sourceIPv4Address", "src", "srcip", "src_ip", "client_ip"),
    )
    dst_obj = _first_present(
        obj,
        ("destinationIPv4Address", "dst", "dstip", "dst_ip", "server_ip"),
    )

    return SyslogEntry(
        raw=text,
        ts=ts,
        host=host,
        tag=tag,
        log_type=log_type,
        msg=msg,
        level=level,
        src_ip=str(src_obj) if src_obj is not None else None,
        dst_ip=str(dst_obj) if dst_obj is not None else None,
        protocol=_normalize_protocol(_first_present(obj, ("protocolIdentifier", "proto", "protocol"))),
        bytes_count=_safe_int(_first_present(obj, ("octetDeltaCount", "bytes", "in_bytes", "out_bytes"))),
        packets_count=_safe_int(_first_present(obj, ("packetDeltaCount", "packets"))),
    )


LineParser = Callable[[str, int], SyslogEntry | None]


LINE_PARSERS: tuple[LineParser, ...] = (
    parse_json_line,
    parse_rfc5424_line,
    parse_rfc3164_line,
    parse_cef_line,
    parse_leef_line,
    parse_access_log_line,
    parse_flow_line,
)


def parse_line(line: str, default_year: int) -> SyslogEntry:
    # Try specific format parsers in a deterministic order.
    text = line.rstrip("\n")
    for parser in LINE_PARSERS:
        entry = parser(text, default_year)
        if entry is not None:
            return entry

    # Keep non-matching lines accessible instead of dropping them.
    return SyslogEntry(
        raw=text,
        ts=None,
        host=None,
        tag=None,
        log_type="raw",
        msg=text,
        level=infer_level(text),
    )


def parse_entries(path: pathlib.Path, encoding: str = "utf-8-sig") -> Iterable[SyslogEntry]:
    # Stream entries line-by-line for large files.
    year = dt.datetime.now().year
    LOGGER.info("Reading log file: %s (encoding=%s)", path, encoding)
    with path.open("r", encoding=encoding, errors="replace") as handle:
        for line in handle:
            if line.strip():
                yield parse_line(line, year)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Read and filter log files offline.")
    parser.add_argument("-f", "--file", required=True, type=pathlib.Path, help="Path to log file")
    parser.add_argument("--contains", help="Only lines containing this text (case-insensitive)")
    parser.add_argument(
        "--level",
        help="Comma-separated levels: emerg,alert,crit,err,warning,notice,info,debug",
    )
    parser.add_argument(
        "--type",
        help="Comma-separated log types: "
        + ",".join(LOG_TYPE_CHOICES),
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


def parse_filter_values(raw_value: str, valid_values: set[str], label: str) -> set[str]:
    values = {part.strip().lower() for part in raw_value.split(",") if part.strip()}
    invalid = sorted(values - valid_values)
    if invalid:
        valid = ",".join(sorted(valid_values))
        raise argparse.ArgumentTypeError(f"Invalid {label}: {', '.join(invalid)}. Use: {valid}")
    return values


def should_keep(
    entry: SyslogEntry,
    contains: str | None,
    allowed_levels: set[str] | None,
    allowed_types: set[str] | None,
    since: dt.datetime | None,
    until: dt.datetime | None,
) -> bool:
    if contains and contains.lower() not in entry.raw.lower():
        return False

    if allowed_levels is not None and (entry.level not in allowed_levels):
        return False

    if allowed_types is not None and (entry.log_type not in allowed_types):
        return False

    if since is not None:
        if entry.ts is None or entry.ts < since:
            return False

    if until is not None:
        if entry.ts is None or entry.ts > until:
            return False

    return True


def format_entry(entry: SyslogEntry) -> str:
    ts = entry.ts.isoformat(sep=" ") if entry.ts else "N/A"
    host = entry.host or "N/A"
    tag = entry.tag or "raw"
    level = entry.level or "unknown"

    flow_meta = []
    if entry.src_ip:
        flow_meta.append(f"src={entry.src_ip}")
    if entry.dst_ip:
        flow_meta.append(f"dst={entry.dst_ip}")
    if entry.protocol:
        flow_meta.append(f"proto={entry.protocol}")
    if entry.packets_count is not None:
        flow_meta.append(f"packets={entry.packets_count}")
    if entry.bytes_count is not None:
        flow_meta.append(f"bytes={entry.bytes_count}")
    flow_suffix = ""
    if flow_meta:
        flow_suffix = " (" + ", ".join(flow_meta) + ")"

    return f"[{ts}] [{entry.log_type}] [{host}] [{tag}] [{level}] {entry.msg}{flow_suffix}"


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")

    parser = build_arg_parser()
    args = parser.parse_args(argv)
    configure_logging(args.log_level)
    LOGGER.info("Starting CLI log read")

    if not args.file.exists():
        LOGGER.error("File not found: %s", args.file)
        print(f"Error: file not found: {args.file}", file=sys.stderr)
        return 2

    allowed_levels = None
    allowed_types = None
    try:
        if args.level:
            allowed_levels = parse_filter_values(args.level, set(LEVEL_HINTS.keys()), "level(s)")
            LOGGER.info("Severity filter active: %s", ",".join(sorted(allowed_levels)))
        if args.type:
            allowed_types = parse_filter_values(args.type, set(LOG_TYPE_CHOICES), "type(s)")
            LOGGER.info("Type filter active: %s", ",".join(sorted(allowed_types)))
    except argparse.ArgumentTypeError as err:
        print(f"Error: {err}", file=sys.stderr)
        return 2

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
        if should_keep(entry, args.contains, allowed_levels, allowed_types, args.since, args.until):
            print(format_entry(entry))
            matches += 1

    LOGGER.info("Finished processing lines=%s matches=%s", processed, matches)
    if matches == 0:
        print("No matching entries found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
