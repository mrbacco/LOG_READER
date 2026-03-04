#!/usr/bin/env python3
"""
mrbacco04@gmail.com
March 2026

Offline syslog reader.
Mini web UI for offline syslog reading.

Run:
  python syslog_web.py
Open:
  http://127.0.0.1:8000
"""

from __future__ import annotations

import argparse
import datetime as dt
import html
import logging
import pathlib
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

from syslog_reader import LEVEL_HINTS, parse_datetime, parse_line, should_keep

# Root folders used by the tiny template/static system.
BASE_DIR = pathlib.Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

# Protection limits for basic safety on uploads and rendering.
MAX_REQUEST_SIZE = 8 * 1024 * 1024
MAX_ROWS = 2000

# Shared logger for web diagnostics.
LOGGER = logging.getLogger("BAC_LOG.web")


def configure_logging(log_level: str) -> None:
    # Centralized logging format with BAC_LOG marker for easy grep/filtering.
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s [BAC_LOG] [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    LOGGER.debug("Logging configured at level=%s", log_level.upper())


def _first(form: dict[str, list[str]], key: str, default: str = "") -> str:
    # Helper for form fields where only the first value is relevant.
    values = form.get(key)
    if not values:
        return default
    return values[0]


def _load_text(path: pathlib.Path) -> str | None:
    # Small utility for static/template file reads with graceful failure.
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        LOGGER.error("Could not read file: %s", path)
        return None


def _render_template(template_name: str, context: dict[str, str]) -> str:
    # Minimal replacement renderer: {{key}} placeholders are replaced from context.
    template_path = TEMPLATES_DIR / template_name
    template_text = _load_text(template_path)
    if template_text is None:
        return (
            "<!doctype html><html><body><h1>Template Error</h1>"
            f"<p>Could not read template: {html.escape(str(template_path))}</p>"
            "</body></html>"
        )

    rendered = template_text
    for key, value in context.items():
        rendered = rendered.replace(f"{{{{{key}}}}}", value)
    return rendered


def _parse_levels(level_text: str, errors: list[str]) -> set[str] | None:
    # Parse comma-separated level text and validate against known syslog levels.
    text = level_text.strip().lower()
    if not text:
        return None

    chosen = {item.strip() for item in text.split(",") if item.strip()}
    valid = set(LEVEL_HINTS.keys())
    invalid = sorted(chosen - valid)
    if invalid:
        errors.append(
            "Invalid level(s): "
            + ", ".join(invalid)
            + ". Use: "
            + ",".join(sorted(valid))
        )
    return chosen


def _parse_optional_datetime(name: str, value: str, errors: list[str]) -> dt.datetime | None:
    # Parse optional datetime input fields and collect validation errors.
    text = value.strip()
    if not text:
        return None
    try:
        return parse_datetime(text)
    except Exception:
        errors.append(
            f"Invalid {name}: {html.escape(text)}. Use 'YYYY-MM-DD HH:MM:SS' or 'Mon DD HH:MM:SS'."
        )
        return None


def _render_page(
    form_values: dict[str, str] | None = None,
    errors: list[str] | None = None,
    stats: dict[str, int | str | bool] | None = None,
    rows: list[dict[str, str]] | None = None,
) -> bytes:
    # Convert backend state into HTML-safe strings for template rendering.
    form_values = form_values or {}
    errors = errors or []
    stats = stats or {}
    rows = rows or []

    contains = html.escape(form_values.get("contains", ""))
    level = html.escape(form_values.get("level", ""))
    since = html.escape(form_values.get("since", ""))
    until = html.escape(form_values.get("until", ""))
    loaded_file_name = html.escape(form_values.get("loaded_file_name", ""))
    file_status = html.escape(form_values.get("file_status", "No file loaded yet."))
    log_text = html.escape(form_values.get("log_text", ""))

    error_html = ""
    if errors:
        items = "".join(f"<li>{e}</li>" for e in errors)
        error_html = f"<div class='errors'><strong>Validation errors:</strong><ul>{items}</ul></div>"

    stats_html = ""
    if stats:
        level_counts = str(stats.get("level_counts", ""))
        truncated = ""
        if bool(stats.get("truncated")):
            shown = int(stats.get("shown", 0))
            matched = int(stats.get("matched", 0))
            truncated = f"<p class='note'>Showing first {shown:,} matched lines out of {matched:,}.</p>"

        stats_html = (
            "<div class='stats'>"
            f"<p><strong>File:</strong> {html.escape(str(stats.get('file_name', 'uploaded text')))}</p>"
            f"<p><strong>Processed lines:</strong> {int(stats.get('processed', 0)):,}</p>"
            f"<p><strong>Matched lines:</strong> {int(stats.get('matched', 0)):,}</p>"
            f"<p><strong>Level counts:</strong> {html.escape(level_counts)}</p>"
            f"{truncated}"
            "</div>"
        )

    if rows:
        built = []
        for row in rows:
            built.append(
                "<tr>"
                f"<td>{row['timestamp']}</td>"
                f"<td>{row['host']}</td>"
                f"<td>{row['tag']}</td>"
                f"<td>{row['level']}</td>"
                f"<td class='msg'>{row['message']}</td>"
                "</tr>"
            )
        row_html = "".join(built)
    else:
        row_html = "<tr><td colspan='5'>No results yet.</td></tr>"

    context = {
        "contains": contains,
        "level": level,
        "since": since,
        "until": until,
        "loaded_file_name": loaded_file_name,
        "file_status": file_status,
        "log_text": log_text,
        "error_html": error_html,
        "stats_html": stats_html,
        "row_html": row_html,
    }
    return _render_template("index.html", context).encode("utf-8")


class SyslogWebHandler(BaseHTTPRequestHandler):
    server_version = "SyslogReader/1.2"

    def log_message(self, fmt: str, *args: object) -> None:
        # Redirect default HTTP server logs into our Python logger.
        LOGGER.info("%s - %s", self.address_string(), fmt % args)

    def _send_bytes(self, content: bytes, content_type: str, status_code: int = 200) -> None:
        # Shared response writer for HTML/CSS and potential future assets.
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _send_html(self, content: bytes, status_code: int = 200) -> None:
        self._send_bytes(content, "text/html; charset=utf-8", status_code=status_code)

    def _send_css(self, status_code: int = 200) -> None:
        # Serve CSS from a dedicated static path.
        css_path = STATIC_DIR / "styles.css"
        css_text = _load_text(css_path)
        if css_text is None:
            self._send_html(_render_page(errors=[f"Missing CSS file: {css_path}"]), status_code=500)
            return
        self._send_bytes(css_text.encode("utf-8"), "text/css; charset=utf-8", status_code=status_code)

    def do_GET(self) -> None:  # noqa: N802
        route = self.path.split("?", 1)[0]
        LOGGER.debug("GET route=%s", route)
        if route == "/":
            self._send_html(_render_page())
            return
        if route == "/static/styles.css":
            self._send_css()
            return
        self._send_html(_render_page(errors=["Not found."]), status_code=404)

    def do_POST(self) -> None:  # noqa: N802
        route = self.path.split("?", 1)[0]
        LOGGER.debug("POST route=%s", route)
        if route != "/":
            self._send_html(_render_page(errors=["Not found."]), status_code=404)
            return

        # Read and validate request size before parsing.
        content_length = int(self.headers.get("Content-Length", "0") or "0")
        if content_length > MAX_REQUEST_SIZE:
            limit_mb = MAX_REQUEST_SIZE // (1024 * 1024)
            LOGGER.warning("Request rejected: payload too large (%s bytes)", content_length)
            self._send_html(
                _render_page(errors=[f"Request too large. Limit is {limit_mb} MB."]),
                status_code=413,
            )
            return

        # Parse URL-encoded form payload from the browser.
        raw = self.rfile.read(content_length)
        form = parse_qs(raw.decode("utf-8", errors="replace"), keep_blank_values=True)

        form_values = {
            "contains": _first(form, "contains"),
            "level": _first(form, "level"),
            "since": _first(form, "since"),
            "until": _first(form, "until"),
            "loaded_file_name": _first(form, "loaded_file_name"),
            "log_text": _first(form, "log_text"),
            "file_status": _first(form, "loaded_file_name", "No file loaded yet."),
        }

        errors: list[str] = []
        log_text = form_values["log_text"]
        if not log_text.strip():
            errors.append("Load a syslog file first (or paste log text).")

        # Parse and validate filters before scanning lines.
        allowed_levels = _parse_levels(form_values["level"], errors)
        since = _parse_optional_datetime("since", form_values["since"], errors)
        until = _parse_optional_datetime("until", form_values["until"], errors)
        if since and until and since > until:
            errors.append("'since' cannot be later than 'until'.")

        if errors:
            LOGGER.info("Form validation failed with %s error(s)", len(errors))
            self._send_html(_render_page(form_values=form_values, errors=errors), status_code=400)
            return

        processed = 0
        matched = 0
        rows: list[dict[str, str]] = []
        level_counter = Counter()
        default_year = dt.datetime.now().year

        # Parse each non-empty line and apply all filters.
        for line in log_text.splitlines():
            if not line.strip():
                continue
            processed += 1
            entry = parse_line(line, default_year)
            if not should_keep(entry, form_values["contains"], allowed_levels, since, until):
                continue

            matched += 1
            level_counter[entry.level or "unknown"] += 1

            # Keep only the first MAX_ROWS lines in the table for browser performance.
            if len(rows) < MAX_ROWS:
                rows.append(
                    {
                        "timestamp": html.escape(entry.ts.isoformat(sep=" ") if entry.ts else "N/A"),
                        "host": html.escape(entry.host or "N/A"),
                        "tag": html.escape(entry.tag or "raw"),
                        "level": html.escape(entry.level or "unknown"),
                        "message": html.escape(entry.msg),
                    }
                )

        level_counts_text = ", ".join(
            f"{name}={count}" for name, count in sorted(level_counter.items(), key=lambda x: (-x[1], x[0]))
        )
        if not level_counts_text:
            level_counts_text = "none"

        stats = {
            "file_name": form_values["loaded_file_name"] or "pasted text",
            "processed": processed,
            "matched": matched,
            "shown": len(rows),
            "truncated": matched > len(rows),
            "level_counts": level_counts_text,
        }
        LOGGER.info(
            "Analysis complete file=%s processed=%s matched=%s shown=%s",
            stats["file_name"],
            processed,
            matched,
            len(rows),
        )
        self._send_html(_render_page(form_values=form_values, stats=stats, rows=rows))


def parse_args() -> argparse.Namespace:
    # Runtime options for network bind and log verbosity.
    parser = argparse.ArgumentParser(description="Mini web UI for offline syslog reading.")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind (default: 8000)")
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Python logger level for BAC_LOG diagnostics (default: INFO)",
    )
    return parser.parse_args()


def main() -> int:
    # Server bootstrap and graceful shutdown path.
    args = parse_args()
    configure_logging(args.log_level)

    server = ThreadingHTTPServer((args.host, args.port), SyslogWebHandler)
    LOGGER.info("Serving syslog UI on http://%s:%s", args.host, args.port)
    print(f"Serving syslog UI on http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        LOGGER.info("Shutdown requested by keyboard interrupt")
        print("\nShutting down...")
    finally:
        server.server_close()
        LOGGER.info("Server stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
