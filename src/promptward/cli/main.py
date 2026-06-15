"""pw — Promptward CLI"""

import json
import sys

import typer
from rich import box
from rich.console import Console
from rich.table import Table

from ..common.config import get_settings
from ..common.storage import Store

app = typer.Typer(
    name="pw",
    help="Promptward — monitor, log, and inspect Claude interactions.",
    add_completion=False,
)
console = Console()


# ── proxy ──────────────────────────────────────────────────────────────────────

@app.command()
def proxy(
    host: str = typer.Option(None, help="Override listen host"),
    port: int = typer.Option(None, help="Override listen port"),
) -> None:
    """Start the transparent API proxy (intercepts VS Code / SDK calls)."""
    from ..agent.forwarder import run as _run_proxy

    settings = get_settings()
    if host:
        settings.proxy_host = host  # type: ignore[assignment]
    if port:
        settings.proxy_port = port  # type: ignore[assignment]

    console.print(
        f"[bold green]Promptward proxy[/] → [cyan]http://{settings.proxy_host}:{settings.proxy_port}[/]"
        f"  upstream: [dim]{settings.upstream_base_url}[/]"
    )
    console.print(
        "Run this in your terminal session [bold](do NOT add to .bashrc)[/]:\n"
        f"  [yellow]export ANTHROPIC_BASE_URL=http://{settings.proxy_host}:{settings.proxy_port}[/]\n"
    )
    _run_proxy()


# ── enroll / service ─────────────────────────────────────────────────────────

@app.command()
def enroll(
    server: str = typer.Option(..., help="Collector base URL, e.g. https://pw.corp"),
    token: str = typer.Option(..., help="Org enroll token (from the server admin)"),
    device_name: str = typer.Option(None, help="Friendly device name (default: hostname)"),
    install_service: bool = typer.Option(True, help="Install OS service + fail-open wrapper"),
) -> None:
    """Enroll this agent with a central Promptward collector and install its service."""
    from ..agent.enroll import enroll as _enroll
    from ..agent import service as _svc

    info = _enroll(server, token, device_name)
    console.print(
        f"[green]Enrolled[/] device=[cyan]{info['device_name']}[/] "
        f"id=[dim]{info['agent_id']}[/] → {info['server']}"
    )
    if install_service:
        res = _svc.install()
        console.print(f"  Service : [dim]{res['unit'] or '(manual: run `pw proxy`)'}[/]")
        console.print(f"  Wrapper : [dim]{res['wrapper']}[/] (use `claude-tracked` instead of `claude`)")
        console.print(f"  Next    : [yellow]{res['hint']}[/]")


service_app = typer.Typer(help="Manage the agent OS service + fail-open wrapper.")
app.add_typer(service_app, name="service")


@service_app.command("install")
def service_install() -> None:
    """Install the OS service unit and the fail-open `claude-tracked` wrapper."""
    from ..agent import service as _svc

    res = _svc.install()
    console.print(f"  OS      : {res['os']}")
    console.print(f"  Service : [dim]{res['unit'] or '(unsupported — run `pw proxy`)'}[/]")
    console.print(f"  Wrapper : [dim]{res['wrapper']}[/]")
    console.print(f"  Next    : [yellow]{res['hint']}[/]")


@service_app.command("wrapper")
def service_wrapper() -> None:
    """Install only the fail-open `claude-tracked` wrapper."""
    from ..agent import service as _svc

    path = _svc.install_wrapper()
    console.print(f"Wrote [dim]{path}[/] — run [cyan]claude-tracked[/] in place of `claude`.")


# ── server (central) ───────────────────────────────────────────────────────────

@app.command()
def server() -> None:
    """Run the central collector + dashboard (org deployment)."""
    from ..server.app import run as _run_server
    from ..server.server_store import ServerStore

    settings = get_settings()
    token = ServerStore(settings).ensure_enroll_token()
    if token:
        console.print(f"[bold]Org enroll token (save this):[/] [cyan]{token}[/]")
        console.print("  Give it to employees: [dim]pw enroll --server <url> --token <token>[/]\n")
    _run_server()


@app.command("org-token")
def org_token(rotate: bool = typer.Option(False, "--rotate", help="Rotate (invalidates the old token)")) -> None:
    """Show (create) or rotate the org enroll token."""
    from ..server.server_store import ServerStore

    store = ServerStore(get_settings())
    if rotate:
        console.print(f"New enroll token: [cyan]{store.rotate_enroll_token()}[/]")
    else:
        token = store.ensure_enroll_token()
        console.print(
            f"Enroll token: [cyan]{token}[/]" if token
            else "[yellow]Enroll token already exists[/] — use --rotate to replace it."
        )


@app.command()
def evidence(
    out: str = typer.Option(None, "-o", "--out", help="Write to this file (default: stdout)"),
    fmt: str = typer.Option("json", "--format", help="Output format: json | html"),
    period_days: int = typer.Option(30, help="Reporting window in days (metadata only)"),
    verify: str = typer.Option(None, "--verify", help="Verify an existing pack file instead of generating"),
) -> None:
    """Generate (or verify) a signed compliance evidence pack for auditors.

    `--format html` renders a print-to-PDF document; `--format json` emits the
    signed, machine-verifiable pack.
    """
    from datetime import datetime, timezone
    from ..server import evidence as _ev
    from ..server import evidence_report as _report

    settings = get_settings()

    if verify:
        with open(verify) as f:
            signed = json.load(f)
        ok, reason = _ev.verify_pack(signed, settings)
        style = "green" if ok else "red"
        console.print(f"[bold {style}]{'VERIFIED' if ok else 'INVALID'}[/] — {reason}")
        sys.exit(0 if ok else 1)

    now = datetime.now(timezone.utc).isoformat()
    pack = _ev.build_pack(settings, period_days=period_days, generated_at=now, actor="cli")
    signed = _ev.sign_pack(pack, settings)
    blob = _report.render_html(signed) if fmt == "html" else json.dumps(signed, indent=2)

    if out:
        with open(out, "w") as f:
            f.write(blob)
        p = signed["pack"]["posture"]
        console.print(
            f"[green]Wrote {fmt} evidence pack[/] → [cyan]{out}[/]\n"
            f"  Controls: [green]{p['pass']} pass[/] · [yellow]{p['partial']} partial[/] · "
            f"[red]{p['gap']} gap[/]   sha256=[dim]{signed['manifest']['pack_sha256'][:16]}…[/]"
        )
    else:
        print(blob)


@app.command()
def agents() -> None:
    """List enrolled agents (central server)."""
    from ..server.server_store import ServerStore

    rows = ServerStore(get_settings()).list_agents()
    table = Table(box=box.SIMPLE_HEAVY)
    for col in ("agent_id", "device", "os", "status", "last_seen"):
        table.add_column(col)
    for r in rows:
        table.add_row(r["agent_id"], r.get("device_name") or "—", r.get("os") or "—",
                      r["status"], (r.get("last_seen") or "—")[:19])
    console.print(table)


# ── cli wrap ───────────────────────────────────────────────────────────────────

@app.command("ask")
def ask(prompt: list[str] = typer.Argument(..., help="Prompt to send to Claude CLI")) -> None:
    """Wrap the `claude` CLI — logs the interaction then prints the response."""
    from ..agent.cli_wrapper import run as _run_cli

    full_prompt = " ".join(prompt)
    sys.exit(_run_cli(full_prompt))


# ── logs ───────────────────────────────────────────────────────────────────────

@app.command("logs")
def logs(
    limit: int = typer.Option(20, "-n", help="Number of recent entries to show"),
    json_out: bool = typer.Option(False, "--json", help="Output raw JSON"),
) -> None:
    """Show recent logged interactions."""
    settings = get_settings()
    store = Store(settings)
    rows = store.list_recent(limit)

    if json_out:
        print(json.dumps(rows, indent=2, default=str))
        return

    table = Table(box=box.SIMPLE_HEAVY, show_lines=True)
    table.add_column("#", style="dim", width=4)
    table.add_column("Time", style="cyan", width=22)
    table.add_column("Src", width=6)
    table.add_column("Model", width=20)
    table.add_column("Prompt", max_width=55)
    table.add_column("Response", max_width=55)
    table.add_column("↑tok", justify="right", width=6)
    table.add_column("↓tok", justify="right", width=6)

    for r in reversed(rows):
        prompt_preview = (r["prompt"] or "")[:120].replace("\n", " ")
        resp_preview = (r["response"] or "")[:120].replace("\n", " ")
        table.add_row(
            str(r["id"]),
            r["ts"][:19],
            r["source"],
            r["model"] or "—",
            prompt_preview,
            resp_preview,
            str(r["tokens_in"] or "—"),
            str(r["tokens_out"] or "—"),
        )

    console.print(table)


# ── stats ──────────────────────────────────────────────────────────────────────

@app.command()
def stats() -> None:
    """Show usage statistics."""
    settings = get_settings()
    store = Store(settings)
    s = store.stats()

    console.print("\n[bold]Promptward — Stats[/]")
    console.print(f"  Total interactions : [cyan]{s['total_interactions']}[/]")
    console.print(f"  Devices            : [cyan]{s['total_devices']}[/]")
    console.print(f"  Tokens in          : [yellow]{s['total_tokens_in']:,}[/]")
    console.print(f"  Tokens out         : [yellow]{s['total_tokens_out']:,}[/]")
    console.print(
        f"  Alerts             : "
        f"[red]{s['alerts_high']} high[/] · "
        f"[yellow]{s['alerts_medium']} med[/] · "
        f"[blue]{s['alerts_low']} low[/]"
    )
    console.print(f"  DB path            : [dim]{settings.db_path}[/]\n")


# ── prune ──────────────────────────────────────────────────────────────────────

@app.command()
def prune(
    days: int = typer.Option(None, help="Delete interactions older than N days (default: PW_RETENTION_DAYS)"),
) -> None:
    """Delete interactions past the retention window."""
    from ..server.prune import prune_once

    removed = prune_once(days)
    console.print(f"Pruned [cyan]{removed}[/] interaction(s).")


# ── config ─────────────────────────────────────────────────────────────────────

@app.command("config")
def show_config() -> None:
    """Print current configuration."""
    settings = get_settings()
    console.print_json(settings.model_dump_json(indent=2))


# ── dashboard ──────────────────────────────────────────────────────────────────

@app.command()
def dashboard(
    port: int = typer.Option(None, help="Dashboard listen port (default from config)"),
    host: str = typer.Option(None, help="Bind host. Use 0.0.0.0 to expose (token required)"),
    no_browser: bool = typer.Option(False, "--no-browser", help="Don't open browser automatically"),
) -> None:
    """Open the web dashboard to view activity, stats, and interactions."""
    from ..server.dashboard import run as _run_dashboard

    _run_dashboard(port=port, host=host, open_browser=not no_browser)


if __name__ == "__main__":
    app()
