#!/usr/bin/env python3
"""hostveil — presentation demo TUI."""

import time
from datetime import datetime

from rich import box
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TaskProgressColumn, TextColumn
from rich.table import Table
from rich.text import Text

# ── Mock data ──────────────────────────────────────────────────────────────────

SERVICES = [
    ("Vaultwarden", "vaultwarden/server:1.30.1"),
    ("Immich",      "ghcr.io/immich-app/immich-server:v2.1.0"),
    ("Jellyfin",    "jellyfin/jellyfin:10.8.13"),
    ("Gitea",       "gitea:latest"),
    ("Nginx",       "nginx"),
]

SCAN_CHECKS = [
    "Reading docker-compose.yml",
    "Checking sensitive data exposure",
    "Auditing container permissions",
    "Scanning external exposure",
    "Checking image update status",
    "Generating security report",
]

SCAN_RESULTS = [
    ("Vaultwarden", "CRITICAL", 1),
    ("Immich",      "CRITICAL", 1),
    ("Jellyfin",    "HIGH",     1),
    ("Gitea",       "MEDIUM",   1),
    ("Nginx",       "LOW",      1),
]

SCORES = {
    "overall":  58,
    "sensitive": 42,
    "perms":    55,
    "exposure": 71,
    "updates":  65,
}

QUICKFIXES = [
    ("SAFE",   "Bind Jellyfin port 8096 → 127.0.0.1"),
    ("SAFE",   "Pin gitea:latest → gitea/gitea:1.21"),
    ("GUIDED", "Remove privileged:true (Vaultwarden)"),
    ("GUIDED", "Move Immich DB password to secret"),
]

# ── Helpers ────────────────────────────────────────────────────────────────────

SEV_COLOR = {
    "CRITICAL": "red",
    "HIGH":     "dark_orange",
    "MEDIUM":   "yellow",
    "LOW":      "green",
}


def score_color(n: int) -> str:
    return "red" if n < 50 else ("yellow" if n < 75 else "green")


def score_bar(n: int, width: int = 16) -> Text:
    filled = round(n / 100 * width)
    t = Text()
    t.append("█" * filled, style=score_color(n))
    t.append("░" * (width - filled), style="bright_black")
    return t


# ── Panels ─────────────────────────────────────────────────────────────────────

def panel_server() -> Panel:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="cyan", min_width=9)
    grid.add_column(style="white")

    load_bar = Text()
    load_bar.append("0.42  ", style="white")
    load_bar.append("████", style="green")
    load_bar.append("░░░░░░░░░░", style="bright_black")

    grid.add_row("Host",    "home-server")
    grid.add_row("IP",      "192.168.1.100")
    grid.add_row("Docker",  "24.0.7")
    grid.add_row("Uptime",  "14d 3h 22m")
    grid.add_row("Load",    load_bar)
    grid.add_row("", "")
    grid.add_row(
        Text("Services", style="bold cyan"),
        Text("5 running", style="green"),
    )
    for name, image in SERVICES:
        row = Text()
        row.append("● ", style="green")
        row.append(f"{name:<14}", style="white")
        row.append(image, style="bright_black")
        grid.add_row("", row)

    return Panel(
        grid,
        title="[bold cyan]◈ Server Status[/bold cyan]",
        border_style="cyan",
        box=box.ROUNDED,
    )


def panel_scan() -> Panel:
    grid = Table.grid(padding=(0, 1))
    grid.add_column(min_width=2)
    grid.add_column(min_width=13)
    grid.add_column(min_width=12)
    grid.add_column()

    for service, sev, count in SCAN_RESULTS:
        color = SEV_COLOR[sev]
        grid.add_row(
            Text("✓", style="bold green"),
            Text(service, style="white"),
            Text(f"[{sev}]", style=f"bold {color}"),
            Text(f"{count} finding", style="bright_black"),
        )

    summary = Text()
    summary.append("\n  Total: 5 findings  ", style="white")
    summary.append("2 CRITICAL  ", style="bold red")
    summary.append("1 HIGH  ", style="bold dark_orange")
    summary.append("1 MEDIUM  ", style="bold yellow")
    summary.append("1 LOW", style="bold green")

    return Panel(
        Group(grid, summary),
        title="[bold cyan]◈ Scan Results[/bold cyan]",
        border_style="cyan",
        box=box.ROUNDED,
    )


def panel_scores() -> Panel:
    grid = Table.grid(padding=(0, 1))
    grid.add_column(min_width=16, style="white")
    grid.add_column(min_width=4)
    grid.add_column()

    s = SCORES
    grid.add_row(
        Text("Overall", style=f"bold {score_color(s['overall'])}"),
        Text(str(s["overall"]), style=f"bold {score_color(s['overall'])}"),
        score_bar(s["overall"], 18),
    )
    grid.add_row("", "", "")

    for label, key in [
        ("Sensitive Data",  "sensitive"),
        ("Permissions",     "perms"),
        ("Ext. Exposure",   "exposure"),
        ("Updates",         "updates"),
    ]:
        v = s[key]
        grid.add_row(
            Text(label),
            Text(str(v), style=score_color(v)),
            score_bar(v),
        )

    return Panel(
        grid,
        title="[bold cyan]◈ Security Scores[/bold cyan]",
        border_style="cyan",
        box=box.ROUNDED,
    )


def panel_fixes() -> Panel:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(min_width=10)
    grid.add_column()

    for fix_type, desc in QUICKFIXES:
        if fix_type == "SAFE":
            badge = Text(" SAFE ", style="bold black on green")
        else:
            badge = Text(" GUIDED ", style="bold black on yellow")
        grid.add_row(badge, Text(desc, style="white"))
        grid.add_row("", "")

    return Panel(
        grid,
        title="[bold cyan]◈ Quick Fixes[/bold cyan]",
        border_style="cyan",
        box=box.ROUNDED,
    )


# ── Layout ─────────────────────────────────────────────────────────────────────

def make_header() -> Panel:
    t = Text(justify="center")
    t.append(" hostveil ", style="bold cyan")
    t.append("v0.1", style="cyan")
    t.append("  ·  ", style="bright_black")
    t.append("Docker Compose Security Dashboard", style="white")
    t.append("  ·  ", style="bright_black")
    t.append(datetime.now().strftime("%Y-%m-%d  %H:%M:%S"), style="bright_black")
    return Panel(t, border_style="bright_black", box=box.HORIZONTALS)


def make_footer() -> Text:
    t = Text(justify="left")
    t.append("  ")
    t.append("[q]", style="bold cyan")
    t.append(" quit   ", style="bright_black")
    t.append("[↵]", style="bold cyan")
    t.append(" apply safe fixes   ", style="bright_black")
    t.append("[?]", style="bold cyan")
    t.append(" help", style="bright_black")
    return t


def build_layout() -> Layout:
    root = Layout()
    root.split_column(
        Layout(name="header", size=3),
        Layout(name="main"),
        Layout(name="footer", size=1),
    )
    root["main"].split_row(
        Layout(name="left"),
        Layout(name="right"),
    )
    root["left"].split_column(
        Layout(name="server"),
        Layout(name="scores"),
    )
    root["right"].split_column(
        Layout(name="scan"),
        Layout(name="fixes"),
    )
    root["footer"].update(make_footer())
    return root


def refresh(root: Layout) -> None:
    root["header"].update(make_header())
    root["server"].update(panel_server())
    root["scan"].update(panel_scan())
    root["scores"].update(panel_scores())
    root["fixes"].update(panel_fixes())


# ── Scan animation ──────────────────────────────────────────────────────────────

def run_scan(console: Console) -> None:
    console.clear()
    console.print()
    console.print(
        "  [bold cyan]hostveil[/bold cyan]"
        "  [bright_black]─  Docker Compose Security Scanner[/bright_black]"
    )
    console.print()

    with Progress(
        TextColumn("  [cyan]{task.description:<36}[/cyan]"),
        BarColumn(bar_width=36, complete_style="cyan", finished_style="bright_cyan"),
        TaskProgressColumn(),
        console=console,
    ) as prog:
        task = prog.add_task("Scanning...", total=len(SCAN_CHECKS))
        for check in SCAN_CHECKS:
            time.sleep(0.38)
            prog.console.print(f"  [bold green]✓[/bold green]  [white]{check}[/white]")
            prog.advance(task)

    console.print()
    console.print(
        "  [bold green]Scan complete.[/bold green]"
        "  [bright_black]Launching dashboard...[/bright_black]"
    )
    time.sleep(0.7)


# ── Entry point ─────────────────────────────────────────────────────────────────

def main() -> None:
    console = Console()
    run_scan(console)
    console.clear()

    root = build_layout()
    refresh(root)

    with Live(root, console=console, screen=True, refresh_per_second=1):
        try:
            while True:
                root["header"].update(make_header())
                time.sleep(1)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
