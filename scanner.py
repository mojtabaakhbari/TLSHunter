"""
scanner.py — Generic TCP + TLS/SNI IP scanner

Reads IPs / CIDRs from CLI args and/or a file, optionally pings them, then
probes TCP:port and (optionally) TLS with a user-supplied SNI. Live Rich UI
shows total / tested / success / fails / errors / elapsed / ETA.

Usage examples
--------------
  python scanner.py 1.2.3.4 10.0.0.0/24 -f hosts.txt --sni example.com -o ok.txt
  python scanner.py -f cidrs.txt --ping --sni vercel.com --match vercel,now.sh
  python scanner.py 142.250.0.0/16 --port 443 --workers 800

  # SNI file: test every IP against every SNI (IPs × SNIs combinations)
  python scanner.py -f hosts.txt --sni-file snis.txt -o results.txt \
      --ips-out matched_ips.txt --snis-out matched_snis.txt
"""

from __future__ import annotations

import argparse
import asyncio
import errno
import ipaddress
import logging
import os
import random
import re
import shutil
import signal
import ssl
import sys
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Deque, Iterable, Iterator

from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.logging import RichHandler
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table
from rich.text import Text

try:
    import resource as _resource

    _HAS_RESOURCE = True
except ImportError:
    _HAS_RESOURCE = False

try:
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID, NameOID

    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False

console = Console()
log = logging.getLogger("scanner")

_DEAD_ERRNOS: frozenset[int] = frozenset(
    e
    for e in (
        getattr(errno, "ECONNREFUSED", None),
        getattr(errno, "EHOSTUNREACH", None),
        getattr(errno, "ENETUNREACH", None),
        getattr(errno, "EHOSTDOWN", None),
        getattr(errno, "ENETDOWN", None),
    )
    if e is not None
)


async def _retry_sleep(attempt: int, base_delay: float) -> None:
    """Sleep `base_delay * 2**attempt` plus up to 50% jitter, capped at 5s.
    Jitter desynchronizes worker retries so we don't re-burst into the same
    upstream rate-limiter window that caused the original loss.
    """
    delay = min(base_delay * (2**attempt), 5.0)
    await asyncio.sleep(delay + random.uniform(0.0, delay * 0.5))

@dataclass
class Stats:
    total: int = 0
    tested: int = 0
    success: int = 0
    fail: int = 0 
    error: int = 0  
    matched: int = 0 
    phase: str = "idle"
    phase_t0: float = 0.0 


_COMMENT_RE = re.compile(r"#.*$")


def _parse_token(tok: str) -> Iterator[str]:
    """Yield IPs from a single token: bare IP, CIDR, or 'a.b.c.d-e.f.g.h' range."""
    tok = tok.strip()
    if not tok:
        return
    if "-" in tok and "/" not in tok:
        lo, hi = (s.strip() for s in tok.split("-", 1))
        a = int(ipaddress.ip_address(lo))
        b = int(ipaddress.ip_address(hi))
        if b < a:
            a, b = b, a
        for n in range(a, b + 1):
            yield str(ipaddress.ip_address(n))
        return
    if "/" in tok:
        net = ipaddress.ip_network(tok, strict=False)
        if net.prefixlen >= net.max_prefixlen - 1:
            for ip in net:
                yield str(ip)
        else:
            for ip in net.hosts():
                yield str(ip)
        return
    yield str(ipaddress.ip_address(tok))


def load_targets(inline: list[str], file_path: str | None) -> list[str]:
    """Collect unique IPs from inline tokens and an optional file. Preserves order."""
    seen: set[str] = set()
    out: list[str] = []

    def feed(tokens: Iterable[str]) -> None:
        for tok in tokens:
            try:
                for ip in _parse_token(tok):
                    if ip not in seen:
                        seen.add(ip)
                        out.append(ip)
            except ValueError as e:
                log.warning("Skipping invalid target %r: %s", tok, e)

    feed(inline)

    if file_path:
        try:
            with open(file_path, "r", encoding="utf-8") as fh:
                for raw in fh:
                    line = _COMMENT_RE.sub("", raw).strip()
                    if not line:
                        continue
                    feed(re.split(r"[\s,]+", line))
        except OSError as e:
            log.error("Cannot read targets file %r: %s", file_path, e)
            sys.exit(2)

    return out

def load_snis(file_path: str) -> list[str]:
    """Load SNI hostnames from a file (one per line; '#' comments allowed).

    Returns a list of unique, non-empty SNI strings preserving file order.
    An empty string token is kept as-is — it means "no-SNI probe".
    """
    seen: set[str] = set()
    out: list[str] = []
    try:
        with open(file_path, "r", encoding="utf-8") as fh:
            for raw in fh:
                line = _COMMENT_RE.sub("", raw).strip()
                if line not in seen:
                    seen.add(line)
                    if line:
                        out.append(line)
    except OSError as e:
        log.error("Cannot read SNI file %r: %s", file_path, e)
        sys.exit(2)
    return out


def raise_fd_limit(needed: int) -> None:
    if not _HAS_RESOURCE:
        return
    soft, hard = _resource.getrlimit(_resource.RLIMIT_NOFILE)
    if soft >= needed:
        return
    try:
        new = min(needed, hard)
        _resource.setrlimit(_resource.RLIMIT_NOFILE, (new, hard))
        log.info("Raised fd soft limit %d → %d", soft, new)
    except (ValueError, OSError):
        log.warning(
            "fd soft limit is %d; need %d. Run: ulimit -n %d",
            soft,
            needed,
            needed,
        )

def make_tls_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def cert_names_from_dict(cert: dict) -> list[str]:
    sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
    if sans:
        return sans
    for rdn in cert.get("subject", []):
        for attr, val in rdn:
            if attr == "commonName":
                return [val]
    return []


def cert_names_from_der(der: bytes) -> list[str]:
    """Extract DNS SANs (+ CN fallback) from a DER cert. Requires cryptography."""
    if not der or not _HAS_CRYPTO:
        return []
    try:
        cert = x509.load_der_x509_certificate(der)
        names: list[str] = []
        try:
            ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            names = list(ext.value.get_values_for_type(x509.DNSName))
        except x509.ExtensionNotFound:
            pass
        if not names:
            try:
                cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                if cn_attrs:
                    names = [cn_attrs[0].value]
            except Exception:
                pass
        return names
    except Exception:
        log.debug("DER parse failed", exc_info=True)
        return []


def matches_keywords(names: list[str], keywords: list[str]) -> bool:
    if not keywords:
        return False
    nl = [n.lower().strip() for n in names]
    return any(kw.lower().strip() in n for n in nl for kw in keywords)


async def cancel_and_wait(*tasks: asyncio.Task) -> None:
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)

def make_progress() -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=None),
        TaskProgressColumn(),
        TextColumn("•"),
        TimeElapsedColumn(),
        TextColumn("ETA"),
        TimeRemainingColumn(),
        console=console,
        expand=True,
    )


def _fmt_dur(s: float) -> str:
    s = int(max(s, 0))
    h, r = divmod(s, 3600)
    m, sec = divmod(r, 60)
    return f"{h:d}:{m:02d}:{sec:02d}" if h else f"{m:d}:{sec:02d}"


def _stats_panel(stats: Stats, phase_totals: dict[str, int]) -> Panel:
    elapsed_phase = (
        max(time.monotonic() - stats.phase_t0, 1e-6) if stats.phase_t0 else 1e-6
    )
    rate = stats.tested / elapsed_phase
    elapsed_total = max(time.monotonic() - _RUN_T0, 0.0) if _RUN_T0 else 0.0
    remaining = max(stats.total - stats.tested, 0)
    eta_s = remaining / rate if rate > 0 else 0.0

    tbl = Table.grid(expand=True, padding=(0, 1))
    tbl.add_column(justify="left", style="dim", no_wrap=True)
    tbl.add_column(justify="right", no_wrap=True)
    tbl.add_row("Phase", Text(stats.phase, style="bold magenta"))
    tbl.add_row("Tested", Text(f"{stats.tested:,}/{stats.total:,}", style="bold"))
    tbl.add_row("Success", Text(f"{stats.success:,}", style="bold green"))
    tbl.add_row("Fail", Text(f"{stats.fail:,}", style="yellow"))
    tbl.add_row("Errors", Text(f"{stats.error:,}", style="red"))
    tbl.add_row("Rate", Text(f"{rate:,.0f} ip/s", style="bold"))
    tbl.add_row("Elapsed", Text(_fmt_dur(elapsed_total)))
    tbl.add_row("ETA", Text(_fmt_dur(eta_s) if eta_s > 0 else "—"))
    tbl.add_row("", "")
    tbl.add_row(Text("Pipeline", style="bold dim"), "")
    tbl.add_row("Loaded", Text(f"{phase_totals.get('loaded', 0):,}", style="bold"))
    if phase_totals.get("snis", 1) > 1:
        tbl.add_row("SNIs", Text(f"{phase_totals.get('snis', 1):,}"))
        tbl.add_row(
            "Combinations",
            Text(
                f"{phase_totals.get('loaded', 0) * phase_totals.get('snis', 1):,}",
                style="bold cyan",
            ),
        )
    if "ping_alive" in phase_totals:
        tbl.add_row("Ping alive", Text(f"{phase_totals['ping_alive']:,}"))
    if "tcp_open" in phase_totals:
        tbl.add_row("TCP open", Text(f"{phase_totals['tcp_open']:,}"))
    if "tls_success" in phase_totals:
        tbl.add_row(
            "TLS success",
            Text(f"{phase_totals['tls_success']:,}", style="bold green"),
        )
    tbl.add_row("Matched", Text(f"{stats.matched:,}", style="bold cyan"))

    return Panel(tbl, title="[bold]Stats", border_style="cyan", padding=(0, 1))


def _successes_panel(successes: Deque[Text], height: int, matched: int) -> Panel:
    inner = max(1, height - 2)
    if successes:
        items = list(successes)[-inner:]
        body = Group(*items)
    else:
        body = Text("(no successes yet)", style="dim")
    return Panel(
        body,
        title=(
            f"[bold green]Successes [dim]({len(successes)} total"
            + (f", [cyan]{matched} matched[/]" if matched else "")
            + ")[/]"
        ),
        border_style="green",
        padding=(0, 1),
    )


def _feed_panel(feed: Deque[Text], height: int) -> Panel:
    inner = max(1, height - 2)
    if feed:
        items = list(feed)[-inner:]
        body = Group(*items)
    else:
        body = Text("(no events yet)", style="dim")
    return Panel(
        body,
        title=f"[bold]Live feed [dim]({len(feed)} events)[/]",
        border_style="magenta",
        padding=(0, 1),
    )


def build_ui(
    stats: Stats,
    progress: Progress,
    feed: Deque[Text],
    successes: Deque[Text],
    phase_totals: dict[str, int],
) -> Layout:
    """Three-column layout: Stats | Successes | Live feed, with Progress at the
    bottom. Sized to the real terminal so Live never scrolls/flickers.
    """
    term_h = console.size.height or 24
    progress_h = 3
    body_h = max(4, term_h - progress_h - 1)

    term_w = console.size.width or 100

    root = Layout()
    root.split_column(
        Layout(name="body", size=body_h),
        Layout(name="progress", size=progress_h),
    )
    if term_w >= 110:
        root["body"].split_row(
            Layout(name="stats", size=28),
            Layout(name="successes", ratio=1, minimum_size=32),
            Layout(name="feed", ratio=1, minimum_size=32),
        )
    else:
        root["body"].split_row(
            Layout(name="left", size=34),
            Layout(name="feed", ratio=1),
        )
        root["left"].split_column(
            Layout(name="stats", size=min(20, body_h // 2 + 4)),
            Layout(name="successes", ratio=1),
        )

    root["stats"].update(_stats_panel(stats, phase_totals))
    root["successes"].update(_successes_panel(successes, body_h, stats.matched))
    root["feed"].update(_feed_panel(feed, body_h))
    root["progress"].update(Panel(progress, border_style="green", padding=(0, 1)))
    return root

_RUN_T0: float = 0.0

def _feed_ok(
    feed: Deque[Text], kind: str, ip: str, extra: str = "", *, matched: bool = False
) -> None:
    prefix = "★ " if matched else "  "
    style = "bold cyan" if matched else "green"
    line = Text.assemble(
        (prefix, style),
        (f"{kind:<4} ", "bold green"),
        ("✓ ", "green"),
        (f"{ip:<15}", style),
        (f"  {extra}" if extra else "", "dim"),
    )
    feed.append(line)


def _feed_fail(feed: Deque[Text], kind: str, ip: str, reason: str = "") -> None:
    line = Text.assemble(
        ("  ", ""),
        (f"{kind:<4} ", "dim"),
        ("✗ ", "yellow"),
        (f"{ip:<15}", "dim"),
        (f"  {reason}" if reason else "", "dim"),
    )
    feed.append(line)


def _feed_err(feed: Deque[Text], kind: str, ip: str, reason: str = "") -> None:
    line = Text.assemble(
        ("  ", ""),
        (f"{kind:<4} ", "red"),
        ("! ", "bold red"),
        (f"{ip:<15}", "red"),
        (f"  {reason}" if reason else "", "dim red"),
    )
    feed.append(line)


def _record_success(
    successes: Deque[Text],
    ip: str,
    sni: str | None,
    names: list[str],
    matched: bool,
) -> None:
    """Push a one-line success entry into the successes panel."""
    sni_disp = sni if sni is not None else "\u2014"
    name_disp = ", ".join(names[:3]) if names else "(no cert names)"
    if len(names) > 3:
        name_disp += f" +{len(names) - 3}"
    line = Text.assemble(
        ("\u2605 " if matched else "\u2022 ", "bold cyan" if matched else "green"),
        (f"{ip:<15}  ", "bold cyan" if matched else "bold green"),
        (f"sni={sni_disp}  ", "dim"),
        (name_disp, "cyan" if matched else "white"),
    )
    successes.append(line)

async def ping_one(ip: str, timeout: float, retries: int = 0) -> bool:
    """ICMP ping using the system 'ping' binary. Returns True if host replied.

    Sends `retries + 1` probes in a single `ping` invocation (so we don't pay
    process-spawn cost per attempt). 'ping' returns 0 if *any* reply arrived,
    which is exactly the recover-from-loss semantics we want.
    """
    count = max(1, retries + 1)
    args = [
        "ping",
        "-c",
        str(count),
        "-W",
        str(int(max(timeout, 1))),
        ip,
        '-b'
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        wait = float(count) + float(timeout) + 1.0
        try:
            rc = await asyncio.wait_for(proc.wait(), timeout=wait)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return False
        return rc == 0
    except (OSError, FileNotFoundError):
        return False


async def ping_phase(
    ips: list[str],
    workers: int,
    timeout: float,
    retries: int,
    stats: Stats,
    progress: Progress,
    feed: Deque[Text],
    alive: list[str],
) -> None:
    """Appends ping-responding IPs to `alive` (caller-owned, so partial results
    survive cancellation)."""
    if not shutil.which("ping"):
        log.warning("'ping' binary not found in PATH — skipping ping phase.")
        alive.extend(ips)
        return

    stats.phase = "ping"
    stats.total = len(ips)
    stats.tested = stats.success = stats.fail = stats.error = 0
    stats.phase_t0 = time.monotonic()
    task = progress.add_task("Pinging", total=len(ips))

    q: asyncio.Queue[str] = asyncio.Queue(maxsize=workers * 4)

    async def worker() -> None:
        while True:
            ip = await q.get()
            try:
                ok = await ping_one(ip, timeout, retries=retries)
                if ok:
                    alive.append(ip)
                    stats.success += 1
                    _feed_ok(feed, "ping", ip)
                else:
                    stats.fail += 1
                    _feed_fail(feed, "ping", ip, "no reply")
            except Exception as e:
                stats.error += 1
                _feed_err(feed, "ping", ip, type(e).__name__)
                log.debug("ping error %s", ip, exc_info=True)
            finally:
                stats.tested += 1
                progress.update(task, advance=1)
                q.task_done()

    workers_t = [asyncio.create_task(worker()) for _ in range(workers)]

    async def producer() -> None:
        for ip in ips:
            await q.put(ip)

    prod = asyncio.create_task(producer())
    try:
        await prod
        await q.join()
    finally:
        await cancel_and_wait(prod, *workers_t)
        progress.remove_task(task)
async def _close_writer(writer: asyncio.StreamWriter | None) -> None:
    """Best-effort close. Swallows Exception (not BaseException) so that
    CancelledError still propagates and shutdown remains responsive."""
    if writer is None:
        return
    try:
        writer.close()
    except Exception:
        pass
    try:
        await writer.wait_closed()
    except Exception:
        pass


async def tcp_probe(
    ip: str,
    port: int,
    timeout: float,
    retries: int = 0,
    retry_delay: float = 0.2,
) -> bool:
    """TCP connect probe with retry on *transient* failures only.

    Returns True if the 3-way handshake ever completes.

    Failure classification:
      * `ConnectionRefusedError` / errnos in `_DEAD_ERRNOS` -> deterministic
        "closed/unreachable". Returns False immediately; retrying cannot
        change the answer and would only waste budget.
      * `asyncio.TimeoutError` and any other `OSError` (e.g. EMFILE,
        ENOBUFS, transient ECONNABORTED) -> transient. Retried up to
        `retries` additional times with exponential backoff + jitter.

    This means lost SYNs / upstream rate-limit drops no longer turn into
    false-negative "closed" reports, while genuinely-dead hosts still
    short-circuit in roughly one timeout window.
    """
    for attempt in range(retries + 1):
        writer: asyncio.StreamWriter | None = None
        transient = False
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout
            )
            return True
        except ConnectionRefusedError:
            return False
        except asyncio.TimeoutError:
            transient = True
        except OSError as e:
            if e.errno in _DEAD_ERRNOS:
                return False
            transient = True
        finally:
            await _close_writer(writer)
        if transient and attempt < retries:
            await _retry_sleep(attempt, retry_delay)
    return False


async def tcp_phase(
    ips: list[str],
    port: int,
    workers: int,
    timeout: float,
    retries: int,
    retry_delay: float,
    stats: Stats,
    progress: Progress,
    feed: Deque[Text],
    alive: list[str],
) -> None:
    """Appends TCP-open IPs to `alive` (caller-owned)."""
    stats.phase = f"tcp:{port}"
    stats.total = len(ips)
    stats.tested = stats.success = stats.fail = stats.error = 0
    stats.phase_t0 = time.monotonic()
    task = progress.add_task(f"TCP :{port}", total=len(ips))

    q: asyncio.Queue[str] = asyncio.Queue(maxsize=workers * 4)

    async def worker() -> None:
        while True:
            ip = await q.get()
            try:
                ok = await tcp_probe(
                    ip, port, timeout, retries=retries, retry_delay=retry_delay
                )
                if ok:
                    alive.append(ip)
                    stats.success += 1
                    _feed_ok(feed, "tcp", ip, f":{port} open")
                else:
                    stats.fail += 1
                    _feed_fail(feed, "tcp", ip, f":{port} closed/timeout")
            except Exception as e:
                stats.error += 1
                _feed_err(feed, "tcp", ip, type(e).__name__)
                log.debug("tcp error %s", ip, exc_info=True)
            finally:
                stats.tested += 1
                progress.update(task, advance=1)
                q.task_done()

    workers_t = [asyncio.create_task(worker()) for _ in range(workers)]

    async def producer() -> None:
        for ip in ips:
            await q.put(ip)

    prod = asyncio.create_task(producer())
    try:
        await prod
        await q.join()
    finally:
        await cancel_and_wait(prod, *workers_t)
        progress.remove_task(task)

async def tls_check(
    ip: str,
    port: int,
    snis: list[str | None],
    ctx: ssl.SSLContext,
    timeout: float,
    retries: int = 0,
    retry_delay: float = 0.2,
) -> dict | None:
    """Try each SNI in order; return on first successful handshake.

    Two-level retry strategy:

      * Inner (per-SNI) retry on *transient* failures only:
        `asyncio.TimeoutError` and non-deterministic `OSError`. These are
        almost always packet loss, conntrack saturation, or the upstream
        path rate-limiting our SYN burst — exactly the cases where one
        more attempt with a small backoff recovers the truth.
        Repeated up to `retries` extra times with backoff + jitter.

      * Outer (across-SNI) fallthrough on *TLS-level* failures:
        `ssl.SSLError` and mid-handshake `ConnectionResetError`. These
        are deterministic for the SNI used, so we move on to the next
        SNI immediately (no inner retry, no backoff).

      * Hard-dead failures (`ConnectionRefusedError`, `EHOSTUNREACH`,
        `ENETUNREACH`, ...) short-circuit the whole function with `None`,
        because no SNI choice and no retry will ever get a handshake.
    """
    for sni in snis:
        tcp_dead = False
        for attempt in range(retries + 1):
            writer: asyncio.StreamWriter | None = None
            transient = False
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port, ssl=ctx, server_hostname=sni),
                    timeout,
                )
                cipher = writer.get_extra_info("cipher")
                ssl_obj = writer.get_extra_info("ssl_object")
                names: list[str] = []
                if ssl_obj is not None:
                    try:
                        der = ssl_obj.getpeercert(binary_form=True)
                    except Exception:
                        der = None
                    if der:
                        names = cert_names_from_der(der)
                if not names:
                    names = cert_names_from_dict(
                        writer.get_extra_info("peercert") or {}
                    )
                return {
                    "ip": ip,
                    "sni": sni,
                    "names": names,
                    "cipher": cipher[0] if cipher else None,
                }
            except ssl.SSLError:
                break
            except ConnectionResetError:
                break
            except ConnectionRefusedError:
                return None
            except asyncio.TimeoutError:
                transient = True
            except OSError as e:
                if e.errno in _DEAD_ERRNOS:
                    return None
                transient = True
            except Exception:
                log.debug("tls unexpected %s sni=%r", ip, sni, exc_info=True)
                return {"_error": True} 
            finally:
                await _close_writer(writer)
            if transient and attempt < retries:
                await _retry_sleep(attempt, retry_delay)
            elif transient:
                tcp_dead = True
        if tcp_dead:
            return None
    return None


async def tls_phase(
    ips: list[str],
    port: int,
    snis: list[str | None],
    workers: int,
    timeout: float,
    retries: int,
    retry_delay: float,
    keywords: list[str],
    stats: Stats,
    progress: Progress,
    feed: Deque[Text],
    successes: Deque[Text],
    out: list[dict],
) -> None:
    """Appends successful TLS results to `out` (caller-owned)."""
    stats.phase = f"tls:{port}"
    stats.total = len(ips)
    stats.tested = stats.success = stats.fail = stats.error = 0
    stats.matched = 0
    stats.phase_t0 = time.monotonic()
    task = progress.add_task(f"TLS :{port}", total=len(ips))

    ctx = make_tls_context()
    q: asyncio.Queue[str] = asyncio.Queue(maxsize=workers * 4)

    async def worker() -> None:
        while True:
            ip = await q.get()
            try:
                res = await tls_check(
                    ip,
                    port,
                    snis,
                    ctx,
                    timeout,
                    retries=retries,
                    retry_delay=retry_delay,
                )
                if res is None:
                    stats.fail += 1
                    _feed_fail(feed, "tls", ip, "no handshake")
                elif res.get("_error"):
                    stats.error += 1
                    _feed_err(feed, "tls", ip, "unexpected")
                else:
                    out.append(res)
                    stats.success += 1
                    is_match = matches_keywords(res["names"], keywords)
                    if is_match:
                        stats.matched += 1
                    res["matched"] = is_match
                    names = ", ".join(res["names"][:2]) or "(no cert names)"
                    sni_disp = res["sni"] if res["sni"] is not None else "—"
                    _feed_ok(
                        feed,
                        "tls",
                        ip,
                        f"sni={sni_disp}  {names}",
                        matched=is_match,
                    )
                    _record_success(successes, ip, res["sni"], res["names"], is_match)
            except Exception as e:
                stats.error += 1
                _feed_err(feed, "tls", ip, type(e).__name__)
                log.debug("tls worker error %s", ip, exc_info=True)
            finally:
                stats.tested += 1
                progress.update(task, advance=1)
                q.task_done()

    workers_t = [asyncio.create_task(worker()) for _ in range(workers)]

    async def producer() -> None:
        for ip in ips:
            await q.put(ip)

    prod = asyncio.create_task(producer())
    try:
        await prod
        await q.join()
    finally:
        await cancel_and_wait(prod, *workers_t)
        progress.remove_task(task)

async def tcp_tls_pipeline(
    ips: list[str],
    port: int,
    snis: list[str | None],
    tcp_workers: int,
    tls_workers: int,
    tcp_timeout: float,
    tls_timeout: float,
    retries: int,
    retry_delay: float,
    keywords: list[str],
    stats: Stats,
    progress: Progress,
    feed: Deque[Text],
    successes: Deque[Text],
    phase_totals: dict[str, int],
    out: list[dict],
) -> None:
    """Fused TCP+TLS phase: as soon as a TCP probe succeeds, the IP is forwarded
    to a TLS worker. TCP and TLS stages run concurrently with independent
    worker pools, so the TLS pool never idles waiting for the TCP sweep to
    finish, and dead IPs short-circuit without paying the (longer) TLS
    timeout.

    Stats accounting:
      - stats.total      = len(ips)                (whole-pipeline denominator)
      - stats.tested     +=1 per IP fully processed (TCP-fail OR TLS-complete)
      - stats.success    = TLS handshake successes
      - stats.fail/error = TCP-level + TLS-level negatives, combined
      - phase_totals["tcp_open"] / ["tls_success"] update live for the UI.
    """
    stats.phase = f"tcp+tls:{port}"
    stats.total = len(ips)
    stats.tested = stats.success = stats.fail = stats.error = 0
    stats.matched = 0
    stats.phase_t0 = time.monotonic()

    tcp_task = progress.add_task(f"TCP :{port}", total=len(ips))
    tls_task = progress.add_task(f"TLS :{port}", total=0)

    ctx = make_tls_context()
    in_q: asyncio.Queue[str] = asyncio.Queue(maxsize=tcp_workers * 4)
    tls_q: asyncio.Queue[str] = asyncio.Queue(maxsize=tls_workers * 4)
    tcp_open_count = 0  

    async def tcp_worker() -> None:
        nonlocal tcp_open_count
        while True:
            ip = await in_q.get()
            try:
                ok = await tcp_probe(
                    ip,
                    port,
                    tcp_timeout,
                    retries=retries,
                    retry_delay=retry_delay,
                )
                if ok:
                    tcp_open_count += 1
                    phase_totals["tcp_open"] = tcp_open_count
                    _feed_ok(feed, "tcp", ip, f":{port} open")
                    progress.update(tls_task, total=tcp_open_count)
                    await tls_q.put(ip)
                else:
                    stats.fail += 1
                    stats.tested += 1
                    _feed_fail(feed, "tcp", ip, f":{port} closed/timeout")
                    progress.update(tcp_task, advance=1)
            except Exception as e:
                stats.error += 1
                stats.tested += 1
                _feed_err(feed, "tcp", ip, type(e).__name__)
                progress.update(tcp_task, advance=1)
                log.debug("tcp error %s", ip, exc_info=True)
            finally:
                in_q.task_done()

    async def tls_worker() -> None:
        while True:
            ip = await tls_q.get()
            try:
                res = await tls_check(
                    ip,
                    port,
                    snis,
                    ctx,
                    tls_timeout,
                    retries=retries,
                    retry_delay=retry_delay,
                )
                if res is None:
                    stats.fail += 1
                    _feed_fail(feed, "tls", ip, "no handshake")
                elif res.get("_error"):
                    stats.error += 1
                    _feed_err(feed, "tls", ip, "unexpected")
                else:
                    out.append(res)
                    stats.success += 1
                    phase_totals["tls_success"] = stats.success
                    is_match = matches_keywords(res["names"], keywords)
                    if is_match:
                        stats.matched += 1
                    res["matched"] = is_match
                    names = ", ".join(res["names"][:2]) or "(no cert names)"
                    sni_disp = res["sni"] if res["sni"] is not None else "\u2014"
                    _feed_ok(
                        feed,
                        "tls",
                        ip,
                        f"sni={sni_disp}  {names}",
                        matched=is_match,
                    )
                    _record_success(successes, ip, res["sni"], res["names"], is_match)
            except Exception as e:
                stats.error += 1
                _feed_err(feed, "tls", ip, type(e).__name__)
                log.debug("tls worker error %s", ip, exc_info=True)
            finally:
                stats.tested += 1
                progress.update(tcp_task, advance=1)
                progress.update(tls_task, advance=1)
                tls_q.task_done()

    tcp_w = [asyncio.create_task(tcp_worker()) for _ in range(tcp_workers)]
    tls_w = [asyncio.create_task(tls_worker()) for _ in range(tls_workers)]

    async def producer() -> None:
        for ip in ips:
            await in_q.put(ip)

    prod = asyncio.create_task(producer())
    try:
        await prod
        await in_q.join()
        await tls_q.join()
    finally:
        await cancel_and_wait(prod, *tcp_w, *tls_w)
        progress.remove_task(tcp_task)
        progress.remove_task(tls_task)

def _ip_sort_key(ip: str) -> tuple[int, int]:
    """Sort IPv4 before IPv6, numerically within each family."""
    try:
        a = ipaddress.ip_address(ip)
        return (a.version, int(a))
    except ValueError:
        return (99, 0)


def _atomic_write(path: str, lines: list[str]) -> None:
    """Write lines to <path>.tmp then atomically rename to <path>."""
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            for line in lines:
                f.write(line)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write_output(
    path: str,
    results: list[dict],
    keywords: list[str],
    matched_only: bool,
    ips_out: str | None = None,
    snis_out: str | None = None,
) -> None:
    """Write the main TSV results file, and optionally separate IPs / SNIs files.

    main output (path)
        TSV with columns: ip, sni, matched, cipher, cert_names
        Atomic write via a .tmp rename.

    ips_out (optional)
        One unique IP per line (sorted numerically) for every successful TLS
        result in the written rows.  No header — ready to feed back into -f.

    snis_out (optional)
        One unique SNI per line (sorted alphabetically) for every successful
        TLS result in the written rows.  No header — ready to feed back into
        --sni-file.
    """
    ts = datetime.now(timezone.utc).isoformat()
    rows = [r for r in results if (r.get("matched") or not matched_only)]
    rows.sort(key=lambda r: _ip_sort_key(r.get("ip", "")))

    lines: list[str] = [
        f"# Generated {ts}\n",
        f"# matched_keywords={','.join(keywords) if keywords else '(none)'}\n",
        f"# rows={len(rows)}\n",
        "# columns: ip<TAB>sni<TAB>matched<TAB>cipher<TAB>cert_names\n",
    ]
    for r in rows:
        lines.append(
            f"{r['ip']}\t{r.get('sni') or ''}\t{int(bool(r.get('matched')))}"
            f"\t{r.get('cipher') or ''}\t{', '.join(r.get('names', []))}\n"
        )
    _atomic_write(path, lines)

    if ips_out:
        seen_ips: list[str] = []
        seen_set: set[str] = set()
        for r in rows:
            ip = r.get("ip", "")
            if ip and ip not in seen_set:
                seen_set.add(ip)
                seen_ips.append(ip)
        seen_ips.sort(key=_ip_sort_key)
        _atomic_write(ips_out, [ip + "\n" for ip in seen_ips])

    if snis_out:
        seen_snis: list[str] = []
        seen_sni_set: set[str] = set()
        for r in rows:
            sni = r.get("sni") or ""
            if sni and sni not in seen_sni_set:
                seen_sni_set.add(sni)
                seen_snis.append(sni)
        seen_snis.sort()
        _atomic_write(snis_out, [sni + "\n" for sni in seen_snis])

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="scanner",
        description="Generic TCP + TLS/SNI scanner for arbitrary IPs and SNIs.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument(
        "targets",
        nargs="*",
        help="IPs, CIDRs, or A-B ranges (e.g. 1.2.3.4, 10.0.0.0/24, 1.1.1.1-1.1.1.50)",
    )
    p.add_argument(
        "-f", "--file", help="File with IPs/CIDRs (one per line; '#' comments allowed)"
    )
    p.add_argument("-o", "--output", default="scan_results.txt", help="Output file")
    p.add_argument(
        "--sni",
        action="append",
        default=[],
        help="SNI to send (repeatable). Use '' for no-SNI probe. "
        "If omitted, defaults to a single no-SNI probe.",
    )
    p.add_argument(
        "--sni-file",
        default=None,
        metavar="FILE",
        help="File of SNI hostnames (one per line; '#' comments allowed). "
        "Combined with any --sni values. Every IP is probed against every SNI "
        "(IPs × SNIs total combinations).",
    )
    p.add_argument(
        "--ips-out",
        default=None,
        metavar="FILE",
        help="Write one unique IP per line (numerically sorted) for every "
        "successful TLS result. Ready to reuse with -f.",
    )
    p.add_argument(
        "--snis-out",
        default=None,
        metavar="FILE",
        help="Write one unique SNI per line (alphabetically sorted) for every "
        "successful TLS result. Ready to reuse with --sni-file.",
    )
    p.add_argument(
        "--match",
        default="",
        help="Comma-separated keywords; cert names containing any are flagged matched.",
    )
    p.add_argument(
        "--matched-only",
        action="store_true",
        help="Write only matched results to --output.",
    )
    p.add_argument("--port", type=int, default=443)
    p.add_argument(
        "--ping",
        action="store_true",
        help="ICMP-ping every target first; only ping-alive IPs continue.",
    )
    p.add_argument(
        "--no-tcp",
        "--no-port-scan",
        dest="no_tcp",
        action="store_true",
        help="Skip standalone TCP probe; go straight to TLS.",
    )
    p.add_argument(
        "--no-tls", action="store_true", help="Skip TLS probe (TCP-only scan)."
    )
    p.add_argument(
        "--no-pipeline",
        action="store_true",
        help="Run TCP and TLS as separate sequential phases instead of the "
        "fused TCP\u2192TLS pipeline (default). Only relevant when both phases "
        "are enabled.",
    )
    p.add_argument("--tcp-timeout", type=float, default=3.0)
    p.add_argument("--tls-timeout", type=float, default=5.0)
    p.add_argument("--ping-timeout", type=float, default=2.0)
    p.add_argument(
        "--retries",
        type=int,
        default=2,
        help="Extra attempts on TRANSIENT failures only "
        "(timeout / EMFILE / transient OSError). Deterministic failures "
        "like ECONNREFUSED / EHOSTUNREACH still short-circuit. "
        "Set 0 to disable retries (faster, more false negatives).",
    )
    p.add_argument(
        "--retry-delay",
        type=float,
        default=0.2,
        help="Base delay (seconds) between retries; doubles each attempt "
        "with up to 50%% jitter, capped at 5s. Jitter desynchronizes workers "
        "so retries don't reproduce the same burst that caused the loss.",
    )
    p.add_argument(
        "--workers", type=int, default=500, help="Concurrency for TCP & ping"
    )
    p.add_argument("--tls-workers", type=int, default=200, help="Concurrency for TLS")
    p.add_argument("--log-file", default="scanner.log")
    p.add_argument("-v", "--verbose", action="count", default=0)
    return p.parse_args(argv)


def setup_logging(log_file: str, verbose: int) -> None:
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    fmt = logging.Formatter(
        "%(asctime)s  %(levelname)-8s  %(name)s: %(message)s", datefmt="%H:%M:%S"
    )
    try:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)
        root.addHandler(fh)
    except OSError as e:
        console.print(
            f"[yellow]Cannot open log {log_file!r}: {e} — file logging disabled[/]"
        )

    rh = RichHandler(
        console=console,
        show_time=True,
        show_path=False,
        markup=True,
        rich_tracebacks=True,
    )
    rh.setLevel(
        logging.WARNING
        if verbose == 0
        else (logging.INFO if verbose == 1 else logging.DEBUG)
    )
    root.addHandler(rh)
    logging.getLogger("asyncio").setLevel(logging.WARNING)


async def amain(args: argparse.Namespace) -> int:
    setup_logging(args.log_file, args.verbose)

    if not args.targets and not args.file:
        console.print("[red]No targets provided.[/] Pass IPs/CIDRs or use -f FILE.")
        return 2

    console.rule("[bold cyan]TLS/SNI Scanner")
    ips = load_targets(args.targets, args.file)
    if not ips:
        console.print("[red]No valid targets parsed.[/]")
        return 2
    console.print(f"Loaded [bold]{len(ips):,}[/] unique target IPs.")

    if args.no_tcp and args.no_tls and not args.ping:
        console.print(
            "[red]Nothing to do:[/] --no-tcp and --no-tls set, and --ping not enabled."
        )
        return 2

    raise_fd_limit(max(args.workers, args.tls_workers) * 6 + 64)

    snis: list[str | None] = []
    for s in args.sni:
        snis.append(None if s == "" else s)

    if args.sni_file:
        file_snis = load_snis(args.sni_file)
        console.print(f"Loaded [bold]{len(file_snis):,}[/] SNIs from [dim]{args.sni_file}[/].")
        for s in file_snis:
            candidate: str | None = None if s == "" else s
            if candidate not in snis:
                snis.append(candidate)

    if not snis:
        snis = [None]

    if len(snis) > 1:
        console.print(
            f"Testing [bold]{len(ips):,}[/] IPs × [bold]{len(snis):,}[/] SNIs "
            f"= [bold cyan]{len(ips) * len(snis):,}[/] combinations."
        )

    keywords = [k.strip().lower() for k in args.match.split(",") if k.strip()]
    if keywords and not _HAS_CRYPTO:
        console.print(
            "[yellow]Warning:[/] 'cryptography' not installed \u2014 cert names will be "
            "empty and --match will never trigger. Run: pip install cryptography"
        )

    if args.ping and not shutil.which("ping"):
        console.print(
            "[yellow]Warning:[/] 'ping' binary not found in PATH \u2014 --ping will be skipped."
        )
        args.ping = False
    total_combinations = len(ips) * len(snis)
    stats = Stats(total=total_combinations)
    feed: Deque[Text] = deque(maxlen=500)
    successes: Deque[Text] = deque(maxlen=1000)
    global _RUN_T0
    _RUN_T0 = time.monotonic()
    progress = make_progress()

    phase_totals: dict[str, int] = {"loaded": len(ips), "snis": len(snis)}

    def _phase_marker(label: str, n: int) -> None:
        feed.append(
            Text.assemble(
                ("\u2500\u2500 ", "blue"),
                (label, "bold blue"),
                (f"  \u2192  {n:,} forwarded \u2500\u2500", "blue"),
            )
        )

    pool: list[str] = ips
    final_results: list[dict] = []
    rc = 0

    main_task = asyncio.current_task()
    loop = asyncio.get_running_loop()
    interrupt_count = 0

    def _signal_handler(signame: str) -> None:
        nonlocal interrupt_count
        interrupt_count += 1
        if interrupt_count == 1:
            console.print(
                f"\n[yellow]Got {signame} \u2014 shutting down gracefully. "
                f"Press Ctrl-C again to force-quit.[/]"
            )
            if main_task is not None and not main_task.done():
                main_task.cancel()
        else:
            console.print(f"\n[red]Got second {signame} \u2014 force quit.[/]")
            os._exit(130)

    installed_signals: list[int] = []
    for sig, name in ((signal.SIGINT, "SIGINT"), (signal.SIGTERM, "SIGTERM")):
        try:
            loop.add_signal_handler(sig, _signal_handler, name)
            installed_signals.append(sig)
        except (NotImplementedError, RuntimeError):
            pass

    console_handlers = [
        h for h in logging.getLogger().handlers if isinstance(h, RichHandler)
    ]
    saved_levels = [(h, h.level) for h in console_handlers]
    for h in console_handlers:
        h.setLevel(logging.CRITICAL + 1)  

    try:
        with Live(
            build_ui(stats, progress, feed, successes, phase_totals),
            console=console,
            refresh_per_second=10,
            transient=False,
            screen=False,
        ) as live:

            async def ticker() -> None:
                while True:
                    await asyncio.sleep(0.1)
                    live.update(
                        build_ui(stats, progress, feed, successes, phase_totals)
                    )

            tick = asyncio.create_task(ticker())
            try:
                if args.ping:
                    ping_alive: list[str] = []
                    try:
                        await ping_phase(
                            pool,
                            args.workers,
                            args.ping_timeout,
                            args.retries,
                            stats,
                            progress,
                            feed,
                            ping_alive,
                        )
                    finally:
                        pool = ping_alive
                        phase_totals["ping_alive"] = len(pool)
                        _phase_marker("ping done", len(pool))

                use_pipeline = (
                    pool
                    and not args.no_tcp
                    and not args.no_tls
                    and not args.no_pipeline
                )

                if use_pipeline:
                    try:
                        await tcp_tls_pipeline(
                            pool,
                            args.port,
                            snis,
                            args.workers,
                            args.tls_workers,
                            args.tcp_timeout,
                            args.tls_timeout,
                            args.retries,
                            args.retry_delay,
                            keywords,
                            stats,
                            progress,
                            feed,
                            successes,
                            phase_totals,
                            final_results,
                        )
                    finally:
                        phase_totals["tcp_open"] = phase_totals.get("tcp_open", 0)
                        phase_totals["tls_success"] = len(final_results)
                        phase_totals["matched"] = stats.matched
                        _phase_marker(f"tcp+tls:{args.port} done", len(final_results))
                else:
                    if pool and not args.no_tcp:
                        tcp_alive: list[str] = []
                        try:
                            await tcp_phase(
                                pool,
                                args.port,
                                args.workers,
                                args.tcp_timeout,
                                args.retries,
                                args.retry_delay,
                                stats,
                                progress,
                                feed,
                                tcp_alive,
                            )
                        finally:
                            pool = tcp_alive
                            phase_totals["tcp_open"] = len(pool)
                            _phase_marker(f"tcp:{args.port} done", len(pool))

                    if pool and not args.no_tls:
                        try:
                            await tls_phase(
                                pool,
                                args.port,
                                snis,
                                args.tls_workers,
                                args.tls_timeout,
                                args.retries,
                                args.retry_delay,
                                keywords,
                                stats,
                                progress,
                                feed,
                                successes,
                                final_results,
                            )
                        finally:
                            phase_totals["tls_success"] = len(final_results)
                            phase_totals["matched"] = stats.matched
                            _phase_marker(f"tls:{args.port} done", len(final_results))
            except (KeyboardInterrupt, asyncio.CancelledError):
                rc = 130
            finally:
                await cancel_and_wait(tick)
                live.update(build_ui(stats, progress, feed, successes, phase_totals))
    finally:
        for h, lvl in saved_levels:
            h.setLevel(lvl)
        for sig in installed_signals:
            try:
                loop.remove_signal_handler(sig)
            except (NotImplementedError, RuntimeError):
                pass

    if rc == 130:
        console.print("[yellow]Scan interrupted \u2014 saving partial results.[/]")

    try:
        if final_results:
            write_output(args.output, final_results, keywords, args.matched_only,
                         ips_out=args.ips_out, snis_out=args.snis_out)
        else:
            res = [
                {"ip": ip, "sni": None, "names": [], "cipher": None, "matched": False}
                for ip in pool
            ]
            write_output(args.output, res, keywords, matched_only=False)
        console.print(f"[green]\u2713[/] Saved \u2192 [bold]{args.output}[/]")
        if args.ips_out and final_results:
            console.print(f"[green]\u2713[/] IPs  \u2192 [bold]{args.ips_out}[/]")
        if args.snis_out and final_results:
            console.print(f"[green]\u2713[/] SNIs \u2192 [bold]{args.snis_out}[/]")
    except OSError as e:
        console.print(f"[red]Failed to write {args.output}: {e}[/]")
        rc = rc or 1

    return rc


def main() -> None:
    args = parse_args()
    try:
        sys.exit(asyncio.run(amain(args)))
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
