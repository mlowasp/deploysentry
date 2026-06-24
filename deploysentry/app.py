from __future__ import annotations
import asyncio
import os
import tempfile
from pathlib import Path
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Header, Footer, Input, Button, DataTable, RichLog, Static, Label, TextArea
from textual.binding import Binding
from deploysentry.models import ScanConfig, ScanResult
from deploysentry.scanner.scan_controller import ScanController
from deploysentry.reports.writer import write_reports
from deploysentry.theme import CYBERPUNK_CSS
from deploysentry.utils.validation import normalize_domain, DomainValidationError
from deploysentry.network.tor import tor_proxy_reachable
from deploysentry.network.pro_verification import verify_api_key, redact_api_key



class ProxyListModal(ModalScreen[str | None]):
    """Modal for pasting a proxy list without showing credentials elsewhere."""

    CSS = """
    ProxyListModal {
        align: center middle;
    }

    #proxy-modal {
        width: 96;
        height: 31;
        border: heavy #39fff3;
        background: #090d18;
        padding: 1 2;
    }

    #proxy-title {
        color: #39fff3;
        text-style: bold;
        height: 1;
        margin-bottom: 1;
    }

    #proxy-help {
        color: #d8fff8;
        height: 5;
        margin-bottom: 1;
    }

    #proxy-textarea {
        height: 15;
        border: tall #ff3df2;
        background: #03050a;
        color: #d8fff8;
        margin-bottom: 1;
    }

    #proxy-modal-buttons {
        layout: horizontal;
        height: 3;
    }

    #proxy-save,
    #proxy-disable,
    #proxy-cancel {
        height: 3;
        min-height: 3;
        margin-right: 1;
    }
    """

    BINDINGS = [
        Binding('escape', 'cancel', 'Cancel'),
        Binding('ctrl+s', 'save', 'Save'),
    ]

    def __init__(self, initial_text: str = ''):
        super().__init__()
        self.initial_text = initial_text

    def compose(self) -> ComposeResult:
        with Container(id='proxy-modal'):
            yield Label('DEPLOYSENTRY // Proxy List', id='proxy-title')
            yield Static(
                'Paste one proxy per line. Supported: http://, https://, socks4://, socks5://. '
                'Use Shift+Insert to paste inside this terminal modal; mouse/right-click paste may be intercepted by your terminal. '
                'Credentials are accepted but never printed in logs or reports. Blank lines and # comments are ignored.',
                id='proxy-help',
            )
            yield TextArea(text=self.initial_text, id='proxy-textarea')
            with Horizontal(id='proxy-modal-buttons'):
                yield Button('Save + Enable Proxies', id='proxy-save', variant='primary')
                yield Button('Disable Proxies', id='proxy-disable')
                yield Button('Cancel', id='proxy-cancel')

    def on_mount(self) -> None:
        self.call_after_refresh(lambda: self.query_one('#proxy-textarea', TextArea).focus())

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == 'proxy-save':
            await self.action_save()
        elif event.button.id == 'proxy-disable':
            self.dismiss('')
        elif event.button.id == 'proxy-cancel':
            self.dismiss(None)

    async def action_save(self) -> None:
        text = self.query_one('#proxy-textarea', TextArea).text
        self.dismiss(text)

    async def action_cancel(self) -> None:
        self.dismiss(None)


class ApiKeyModal(ModalScreen[str | None]):
    """Modal for entering a Pro Verification API key without displaying it."""

    CSS = """
    ApiKeyModal {
        align: center middle;
    }

    #api-modal {
        width: 86;
        height: 14;
        border: heavy #55ff99;
        background: #090d18;
        padding: 1 2;
    }

    #api-title {
        color: #55ff99;
        text-style: bold;
        height: 1;
        margin-bottom: 1;
    }

    #api-help {
        color: #d8fff8;
        height: 3;
        margin-bottom: 1;
    }

    #api-key-input {
        height: 3;
        border: tall #55ff99;
        background: #03050a;
        color: #d8fff8;
        margin-bottom: 1;
    }

    #api-modal-buttons {
        layout: horizontal;
        height: 3;
    }

    #api-save,
    #api-disable,
    #api-cancel {
        height: 3;
        min-height: 3;
        margin-right: 1;
    }
    """

    BINDINGS = [
        Binding('escape', 'cancel', 'Cancel'),
        Binding('ctrl+s', 'save', 'Save'),
    ]

    def compose(self) -> ComposeResult:
        with Container(id='api-modal'):
            yield Label('DEPLOYSENTRY // Pro Verification API Key', id='api-title')
            yield Static(
                'Enter your API key, or leave blank to use DEPLOYSENTRY_API_KEY from the environment. '
                'The key is verified with api.deploysentry.com and is never printed.',
                id='api-help',
            )
            yield Input(placeholder='API key or blank for DEPLOYSENTRY_API_KEY', id='api-key-input', password=True)
            with Horizontal(id='api-modal-buttons'):
                yield Button('Verify + Enable Pro', id='api-save', variant='primary')
                yield Button('Disable Pro', id='api-disable')
                yield Button('Cancel', id='api-cancel')

    def on_mount(self) -> None:
        self.call_after_refresh(lambda: self.query_one('#api-key-input', Input).focus())

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == 'api-save':
            await self.action_save()
        elif event.button.id == 'api-disable':
            self.dismiss('')
        elif event.button.id == 'api-cancel':
            self.dismiss(None)

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == 'api-key-input':
            await self.action_save()

    async def action_save(self) -> None:
        self.dismiss(self.query_one('#api-key-input', Input).value.strip())

    async def action_cancel(self) -> None:
        self.dismiss(None)

class DeploySentryApp(App):
    TITLE = 'DeploySentry'
    SUB_TITLE = 'Deployment Exposure Monitor'
    CSS = CYBERPUNK_CSS
    # Input-safe shortcuts only. Plain single-letter shortcuts can intercept typing
    # in Textual Input widgets depending on Textual/terminal versions.
    BINDINGS = [
        Binding('ctrl+q', 'quit', 'Quit'),
        Binding('ctrl+s', 'start_scan', 'Start scan'),
        Binding('ctrl+x', 'stop_scan', 'Stop scan'),
        Binding('ctrl+l', 'clear_log', 'Clear log'),
        Binding('ctrl+r', 'generate_report', 'Report'),
        Binding('ctrl+t', 'toggle_tor', 'Tor'),
        Binding('ctrl+y', 'toggle_proxies', 'Proxies'),
        Binding('ctrl+p', 'toggle_pro', 'Pro'),
    ]

    def __init__(self, domain: str | None = None):
        super().__init__()
        self.initial_domain = domain or ''
        self.controller: ScanController | None = None
        self.scan_task: asyncio.Task | None = None
        self.last_result: ScanResult | None = None
        self.tor_enabled = False
        self.proxies_enabled = False
        self.proxy_list_text = ''
        self.proxy_temp_file: str | None = None
        self.tor_status = 'Disabled'
        self.pro_enabled = False
        self.api_key: str | None = None
        self.asset_rows: dict[str, object] = {}
        self.finding_asset_rows: set[str] = set()
        self.spinner_index = 0
        self.scan_in_progress = False
        self.spinner_frames = ['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏']

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id='top'):
            yield Label('DEPLOYSENTRY // Deployment Exposure Monitor', id='title')
            with Horizontal(id='target-row'):
                yield Label('Target:', id='target-label')
                yield Input(value=self.initial_domain, placeholder='example.com', id='domain')
                yield Button('Start Scan', id='start', variant='primary')
                yield Button('Stop Scan', id='stop')
                yield Button('Export Report', id='report')
            with Horizontal(id='network-row'):
                yield Label('Network:', id='network-label')
                yield Button('Enable Proxies', id='toggle-proxies')
                yield Button('Enable Tor', id='toggle-tor')
                yield Button('Enable Pro', id='toggle-pro')
                yield Static('Shortcuts: Ctrl+Y Proxies | Ctrl+T Tor | Ctrl+P Pro | Ctrl+S Scan | Ctrl+X Stop | Ctrl+R Report', id='shortcut-help')
        with Horizontal():
            with Vertical():
                yield Label('Assets / Subdomains', classes='panel-title')
                yield DataTable(id='assets')
            with Vertical():
                yield Label('Findings', classes='panel-title')
                yield DataTable(id='findings')
        yield Static('', id='status')
        yield Label('Live Log', classes='panel-title')
        yield RichLog(id='log', highlight=True, markup=True)
        yield Footer()

    def on_mount(self) -> None:
        assets = self.query_one('#assets', DataTable)
        assets.cursor_type = 'row'
        assets.zebra_stripes = True
        assets.fixed_columns = 1
        assets.add_column('Asset', key='asset', width=32)
        assets.add_column('A Records', key='a', width=36)
        assets.add_column('AAAA Records', key='aaaa', width=46)
        assets.add_column('CNAME Records', key='cname', width=44)
        findings = self.query_one('#findings', DataTable)
        findings.cursor_type = 'row'
        findings.zebra_stripes = True
        findings.add_column('Severity', key='severity', width=12)
        findings.add_column('Title', key='title', width=36)
        findings.add_column('Asset', key='asset', width=38)
        findings.add_column('Path / Details', key='path', width=54)
        findings.add_column('URL', key='url', width=64)
        self.refresh_network_status()
        self.log_line('[bold cyan]DeploySentry is intended for authorized defensive scanning only.[/bold cyan]')
        self.log_line('Only scan domains you own or have permission to test.')
        self.log_line('[dim]Type a domain in the Target field, press Enter or Ctrl+S to scan. Ctrl+Y opens proxies; Ctrl+T tests/enables Tor; Ctrl+P toggles Pro Verification Mode.[/dim]')
        self.set_interval(0.12, self._tick_spinner)
        self.call_after_refresh(self._focus_domain_input)

    def _focus_domain_input(self) -> None:
        domain_input = self.query_one('#domain', Input)
        domain_input.focus()
        try:
            domain_input.cursor_position = len(domain_input.value)
        except Exception:
            pass

    def log_line(self, msg: str) -> None:
        self.query_one('#log', RichLog).write(msg)

    def refresh_network_status(self) -> None:
        proxy_status = 'Enabled' if self.proxies_enabled else 'Disabled'
        pro_status = 'Enabled' if self.pro_enabled else 'Disabled'
        if self.tor_enabled:
            mode = 'Tor'
        elif self.proxies_enabled:
            mode = 'Proxies'
        elif self.pro_enabled:
            mode = 'Pro Verification'
        else:
            mode = 'Direct'
        loaded = self._proxy_line_count()
        self.query_one('#status', Static).update(
            f'Network Mode: {mode} | Proxies: {proxy_status} ({loaded} configured) | '
            f'Tor Status: {self.tor_status} | Pro Status: {pro_status}'
        )
        self.query_one('#toggle-proxies', Button).label = 'Disable Proxies' if self.proxies_enabled else 'Enable Proxies'
        self.query_one('#toggle-tor', Button).label = 'Disable Tor' if self.tor_enabled else 'Enable Tor'
        self.query_one('#toggle-pro', Button).label = 'Disable Pro' if self.pro_enabled else 'Enable Pro'
        self._refresh_start_button()

    def _proxy_line_count(self) -> int:
        return len([ln for ln in self.proxy_list_text.splitlines() if ln.strip() and not ln.strip().startswith('#')])

    def _refresh_start_button(self) -> None:
        button = self.query_one('#start', Button)
        if self.scan_in_progress:
            frame = self.spinner_frames[self.spinner_index % len(self.spinner_frames)]
            button.label = f'{frame} Scanning...'
            button.disabled = True
        else:
            button.label = 'Start Scan'
            button.disabled = False

    def _tick_spinner(self) -> None:
        if not self.scan_in_progress:
            return
        self.spinner_index = (self.spinner_index + 1) % len(self.spinner_frames)
        self._refresh_start_button()

    def _format_records(self, value: str, max_len: int = 90) -> str:
        if not value:
            return '—'
        return value if len(value) <= max_len else value[:max_len - 1] + '…'

    def _add_asset_info_finding(self, host: str, title: str = 'Asset discovered', details: str = 'queued for DNS/HTTP scan') -> None:
        key = f'{title}:{host}:{details}'
        if key in self.finding_asset_rows:
            return
        self.finding_asset_rows.add(key)
        try:
            self.query_one('#findings', DataTable).add_row('INFO', title, host, details or '—', '', key=f'asset-info-{len(self.finding_asset_rows)}')
        except Exception:
            # A UI-only info row should never break the scanner.
            pass

    def _add_or_update_asset(self, host: str, a: str = '', aaaa: str = '', cname: str = '') -> None:
        if not (a or aaaa or cname):
            return
        a = self._format_records(a, 80)
        aaaa = self._format_records(aaaa, 100)
        cname = self._format_records(cname, 100)
        table = self.query_one('#assets', DataTable)
        if host not in self.asset_rows:
            self.asset_rows[host] = table.add_row(host, a, aaaa, cname, key=host)
            return
        try:
            table.update_cell(host, 'a', a)
            table.update_cell(host, 'aaaa', aaaa)
            table.update_cell(host, 'cname', cname)
        except Exception:
            # Older Textual versions can be picky about row/column keys. Rebuilding
            # the table keeps the UI correct without crashing a scan.
            self._rebuild_assets_table(host, a, aaaa, cname)

    def _rebuild_assets_table(self, changed_host: str, a: str, aaaa: str, cname: str) -> None:
        table = self.query_one('#assets', DataTable)
        current: dict[str, tuple[str, str, str]] = {}
        for host in self.asset_rows:
            current[host] = ('', '', '')
        current[changed_host] = (a, aaaa, cname)
        table.clear()
        self.asset_rows.clear()
        for host, values in current.items():
            self.asset_rows[host] = table.add_row(host, values[0], values[1], values[2], key=host)

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == 'domain':
            await self.action_start_scan()

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == 'start':
            await self.action_start_scan()
        elif event.button.id == 'stop':
            await self.action_stop_scan()
        elif event.button.id == 'report':
            await self.action_generate_report()
        elif event.button.id == 'toggle-proxies':
            await self.action_toggle_proxies()
        elif event.button.id == 'toggle-tor':
            await self.action_toggle_tor()
        elif event.button.id == 'toggle-pro':
            await self.action_toggle_pro()

    async def action_toggle_tor(self) -> None:
        if self.scan_task and not self.scan_task.done():
            self.log_line('[yellow]Network mode cannot be changed while a scan is running.[/yellow]')
            return
        if self.tor_enabled:
            self.tor_enabled = False
            self.tor_status = 'Disabled'
            self.log_line('[cyan]Tor mode disabled.[/cyan]')
            self.refresh_network_status()
            return
        if self.proxies_enabled:
            self.log_line('[red]Tor and custom proxies are mutually exclusive in the MVP. Disable proxies first.[/red]')
            return
        self.tor_status = 'Checking'
        self.refresh_network_status()
        self.log_line('[yellow]Checking local Tor SOCKS proxy at socks5://127.0.0.1:9050...[/yellow]')
        ok, err = await asyncio.to_thread(tor_proxy_reachable, 'socks5://127.0.0.1:9050', 2.0)
        if not ok:
            self.tor_enabled = False
            self.tor_status = 'Unavailable'
            self.log_line(f'[red]Tor is unavailable on 127.0.0.1:9050: {err}[/red]')
            self.log_line('[dim]Start Tor locally first, then press Ctrl+T again. DeploySentry will not install or start Tor automatically.[/dim]')
            self.refresh_network_status()
            return
        self.tor_enabled = True
        self.tor_status = 'Connected'
        self.log_line('[green]Tor mode enabled through socks5://127.0.0.1:9050. Use only for authorized defensive verification.[/green]')
        self.refresh_network_status()

    async def action_toggle_proxies(self) -> None:
        if self.scan_task and not self.scan_task.done():
            self.log_line('[yellow]Network mode cannot be changed while a scan is running.[/yellow]')
            return
        if self.tor_enabled:
            self.log_line('[red]Tor and custom proxies are mutually exclusive in the MVP. Disable Tor first.[/red]')
            return

        # Do not use push_screen_wait() here. Recent Textual versions require
        # wait_for_dismiss=True to be called from a worker, otherwise button
        # handlers crash with NoActiveWorker. Callback-style push_screen works
        # from normal UI event handlers and receives the modal dismiss value.
        self.push_screen(
            ProxyListModal(self.proxy_list_text),
            callback=self._handle_proxy_modal_result,
        )

    def _handle_proxy_modal_result(self, result: str | None) -> None:
        if result is None:
            return

        self.proxy_list_text = result.strip()
        self.proxies_enabled = bool(self.proxy_list_text)

        if self.proxies_enabled:
            self.log_line(
                f'[cyan]Proxy mode enabled. {self._proxy_line_count()} proxy entries configured. '
                'Credentials will be redacted.[/cyan]'
            )
        else:
            self.log_line('[cyan]Proxy mode disabled.[/cyan]')

        self.refresh_network_status()

    async def action_toggle_pro(self) -> None:
        if self.scan_task and not self.scan_task.done():
            self.log_line('[yellow]Network mode cannot be changed while a scan is running.[/yellow]')
            return
        if self.pro_enabled:
            self.pro_enabled = False
            self.api_key = None
            self.log_line('[cyan]Pro Verification Mode disabled.[/cyan]')
            self.refresh_network_status()
            return

        self.push_screen(ApiKeyModal(), callback=self._handle_api_key_modal_result)

    def _handle_api_key_modal_result(self, result: str | None) -> None:
        if result is None:
            return
        if result == '':
            env_key = os.getenv('DEPLOYSENTRY_API_KEY')
            if not env_key:
                self.pro_enabled = False
                self.api_key = None
                self.log_line('[cyan]Pro Verification Mode disabled. No API key was provided and DEPLOYSENTRY_API_KEY is not set.[/cyan]')
                self.refresh_network_status()
                return
            key = env_key
        else:
            key = result

        self.run_worker(self._verify_and_enable_pro(key), exclusive=False)

    async def _verify_and_enable_pro(self, key: str) -> None:
        self.log_line(f'[magenta]Verifying Pro API key {redact_api_key(key)}...[/magenta]')
        ok, err = await verify_api_key(key)
        if not ok:
            self.pro_enabled = False
            self.api_key = None
            self.log_line(f'[red]{err or "Pro API key verification failed."}[/red]')
            self.refresh_network_status()
            return
        self.api_key = key
        self.pro_enabled = True
        self.log_line('[green]Pro Verification Mode enabled. API key verified.[/green]')
        self.refresh_network_status()

    async def action_start_scan(self) -> None:
        if self.scan_task and not self.scan_task.done():
            self.log_line('[yellow]A scan is already running.[/yellow]')
            return
        raw = self.query_one('#domain', Input).value
        try:
            domain = normalize_domain(raw)
        except DomainValidationError as exc:
            self.log_line(f'[red]Invalid domain: {exc}[/red]')
            return
        if self.tor_enabled and self.proxies_enabled:
            self.log_line('[red]Tor and custom proxies are mutually exclusive in the MVP. Disable one and scan again.[/red]')
            return
        assets = self.query_one('#assets', DataTable)
        findings = self.query_one('#findings', DataTable)
        assets.clear()
        findings.clear()
        self.asset_rows.clear()
        self.finding_asset_rows.clear()
        proxy_file = self._write_runtime_proxy_file() if self.proxies_enabled else None
        cfg = ScanConfig(
            domain=domain,
            tor=self.tor_enabled,
            pro=self.pro_enabled,
            api_key=self.api_key,
            proxy_file=proxy_file,
            proxy_mode='rotate' if proxy_file else 'off',
        )
        self.controller = ScanController(cfg, self.handle_event)
        self.scan_in_progress = True
        self.spinner_index = 0
        self._refresh_start_button()
        self.scan_task = asyncio.create_task(self._run_scan())

    def _write_runtime_proxy_file(self) -> str | None:
        if not self.proxy_list_text.strip():
            return None
        fd, path = tempfile.mkstemp(prefix='deploysentry-proxies-', suffix='.txt')
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            fh.write(self.proxy_list_text.strip() + '\n')
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        self.proxy_temp_file = path
        return path

    def _cleanup_runtime_proxy_file(self) -> None:
        if not self.proxy_temp_file:
            return
        try:
            Path(self.proxy_temp_file).unlink(missing_ok=True)
        except OSError:
            pass
        self.proxy_temp_file = None

    async def _run_scan(self) -> None:
        try:
            if self.controller is None:
                return
            self.last_result = await self.controller.run()
        except asyncio.CancelledError:
            # Hard stop: cancellation should propagate into DNS/HTTP tasks and
            # close any in-flight httpx clients via their async context managers.
            self.log_line('[bold yellow]Scan stopped hard. Active requests were cancelled.[/bold yellow]')
            raise
        except Exception as exc:
            self.log_line(f'[red]Scan failed: {exc}[/red]')
        finally:
            self.scan_in_progress = False
            self._refresh_start_button()
            self._cleanup_runtime_proxy_file()

    async def action_stop_scan(self) -> None:
        stopped = False
        if self.controller:
            self.controller.stop()
            stopped = True

        if self.scan_task and not self.scan_task.done():
            # Hard cancel the top-level scan task. asyncio.gather will cancel
            # child DNS/probe/path-scan tasks created by the controller.
            self.scan_task.cancel()
            self.scan_in_progress = False
            self._refresh_start_button()
            self.log_line('[bold yellow]Hard stop requested. Cancelling active scan task now...[/bold yellow]')
            return

        if stopped:
            self.scan_in_progress = False
            self._refresh_start_button()
            self.log_line('[yellow]Stop requested, but no active scan task was running.[/yellow]')
        else:
            self.log_line('[dim]No scan is currently running.[/dim]')

    async def action_clear_log(self) -> None:
        self.query_one('#log', RichLog).clear()

    async def action_generate_report(self) -> None:
        if not self.last_result:
            self.log_line('[yellow]No completed scan result to export yet.[/yellow]')
            return
        paths = write_reports(self.last_result, 'deploysentry-reports', 'all')
        for p in paths:
            self.log_line(f'[green]Report written:[/green] {p}')

    async def handle_event(self, event: dict) -> None:
        typ = event.get('type')
        if typ == 'scan_started':
            self.log_line(f"[cyan]Starting scan for {event['domain']}[/cyan]")
        elif typ == 'subdomain_found':
            source = event.get('source', 'discovery')
            # Keep unverified candidates out of the Assets/Findings tables.
            # They will be displayed only if DNS returns at least one A, AAAA, or CNAME record.
            self.log_line(f"Found candidate subdomain: {event['host']} ({source})")
        elif typ == 'dns_resolved':
            rec = event['record']
            a = ', '.join(rec.a)
            aaaa = ', '.join(rec.aaaa)
            cname = ', '.join(rec.cname)
            has_dns_records = bool(a or aaaa or cname)
            if has_dns_records:
                self._add_or_update_asset(rec.host, a, aaaa, cname)
            if rec.resolved and has_dns_records:
                detail_parts = []
                if a:
                    detail_parts.append(f'A: {self._format_records(a, 80)}')
                if aaaa:
                    detail_parts.append(f'AAAA: {self._format_records(aaaa, 80)}')
                if cname:
                    detail_parts.append(f'CNAME: {self._format_records(cname, 80)}')
                self._add_asset_info_finding(rec.host, 'DNS resolved', ' | '.join(detail_parts) or 'resolved')
                self.log_line(f"[green]Resolved {rec.host}[/green] A={a or '-'} AAAA={aaaa or '-'} CNAME={cname or '-'}")
            else:
                self.log_line(f"[dim]Unresolved {rec.host}: {rec.error or 'no records'}[/dim]")
        elif typ == 'service_found':
            svc = event['service']
            self._add_asset_info_finding(svc.host, 'Live service discovered', f'{svc.status_code} {svc.url}')
            self.log_line(f"[magenta]Live service[/magenta] {svc.url} [{svc.status_code}] {svc.title or ''}")
        elif typ == 'path_checked':
            self.log_line(f"Checked {event['url']} -> {event.get('status')}")
        elif typ == 'scan_log':
            self.log_line(f"[dim]{event.get('message', '')}[/dim]")
        elif typ == 'technology_detected':
            tech = event['technology']
            if tech.confidence < 0.55:
                return
            confidence_pct = int(round(tech.confidence * 100))
            version = getattr(tech, 'version', None)
            details = f"{tech.category} | confidence: {confidence_pct}%"
            if version:
                details += f" | version: {version}"
            if tech.evidence:
                details += f" | {self._format_records(', '.join(tech.evidence), 90)}"
            title = f"Tech: {tech.name}" + (f" {version}" if version else '')
            self.query_one('#findings', DataTable).add_row('INFO', title, tech.asset, details, tech.url)
            self.log_line(f"[green]Technology detected[/green] {tech.name}{f' {version}' if version else ''} on {tech.url} ({confidence_pct}%)")
        elif typ == 'shodan_info_found':
            shodan = event['shodan']
            ip = event.get('ip', shodan.ip)
            asset = event.get('asset', '—')
            ports = ', '.join(str(port.port) for port in shodan.ports[:16])
            if len(shodan.ports) > 16:
                ports += ', …'
            org_bits = [shodan.organization, shodan.asn, shodan.country]
            org_text = ' / '.join(bit for bit in org_bits if bit)
            details = f"{ip}"
            if ports:
                details += f" ports: {ports}"
            if org_text:
                details += f" | {org_text}"
            self.query_one('#findings', DataTable).add_row('INFO', 'Shodan passive data', asset, details, shodan.url)
            self.log_line(f"[cyan]Shodan passive data for {ip}: {len(shodan.ports)} ports found[/cyan]")
        elif typ == 'finding_found':
            f = event['finding']
            self.query_one('#findings', DataTable).add_row(f.severity.upper(), f.title, f.asset, f.path, f.url)
            self.log_line(f"[bold red]Finding:[/bold red] {f.severity.upper()} {f.url}")
        elif typ == 'scan_error':
            self.log_line(f"[red]{event['message']}[/red]")
        elif typ == 'scan_finished':
            r = event['result']
            self.last_result = r
            self.query_one('#status', Static).update(
                f"Network Mode: {r.network.network_mode} | Proxy Health: {r.network.proxies_loaded} loaded / "
                f"{r.network.proxies_healthy} healthy / {r.network.proxies_failed} failed | "
                f"Tor Status: {'Connected' if r.network.tor_enabled else self.tor_status} | "
                f"Pro Status: {'Enabled' if r.network.pro_enabled else 'Disabled'}"
            )
            self.log_line(f"[bold green]Scan finished.[/bold green] {len(r.findings)} findings, {len(r.services)} live services.")
