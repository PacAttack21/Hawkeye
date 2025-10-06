#!/usr/bin/env python3
# HAWKEYE — Automatic Subdomain & Directory Fuzzer
# v1.3 — 4-phase pipeline (quick→quick+ext→full→full+ext), subdomain priority,
#        link discovery, auth-aware, stacked TUI, clean artifacts.

import argparse, asyncio, dataclasses, hashlib, json, os, queue, re, shlex, signal, subprocess, sys, time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ======== Rich (UI) ========
try:
    from rich.console import Console, Group
    from rich.progress import (
        Progress, BarColumn, TimeElapsedColumn, TimeRemainingColumn,
        SpinnerColumn, TextColumn, MofNCompleteColumn, TaskProgressColumn
    )
    from rich.table import Table
    from rich.panel import Panel
    from rich.columns import Columns
    from rich.align import Align
    from rich.live import Live
    from rich.text import Text
except Exception:
    Console = Progress = Live = Panel = Columns = Align = Text = Group = None  # fallback

try:
    from bs4 import BeautifulSoup
except Exception:
    BeautifulSoup = None

try:
    import yaml
except Exception:
    yaml = None

try:
    from pyppeteer import launch as pyppeteer_launch
except Exception:
    pyppeteer_launch = None

# ---------- Constants ----------
DEFAULT_CODES = "200,201,202,204,301,302,307,401,403"
ENQUEUE_CODES = {200, 201, 202, 204, 301, 302, 307, 401, 403}
DIR_LIKE_RE  = re.compile(r"/[^./]+/?$")  # "/admin" or "/admin/"
RUN_ID_FMT   = "%Y%m%dT%H%M%SZ"

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")  # strip terminal colors
HIT_RE  = re.compile(r"^\s*(?P<path>[^\s\[]+)\s*\[Status:\s*(?P<code>\d+)", re.I)
PROG_RE = re.compile(r"::\s*Progress:\s*\[(?P<done>\d+)\/(?P<total>\d+)\]")

TECH_REGEX = {
    "WordPress": re.compile(r"wp-content|/wp-admin|/wp-login\.php", re.I),
    "jQuery": re.compile(r"jquery[-\.]((\d+\.){1,3}\d+)\.js", re.I),
}
SECRET_REGEX = {
    "AWS_AccessKeyID": re.compile(r"AKIA[0-9A-Z]{16}"),
    "JWT": re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
}
COMMENT_OPEN = "<!--"
EXT_RE  = re.compile(r"\.([a-z0-9]{1,5})(?:[^\w]|$)", re.I)

ABS_URL_RE  = re.compile(r"https?://[A-Za-z0-9\.\-:_/?#%+=@~,;]+", re.I)
HREF_SRC_RE = re.compile(r"""\b(?:href|src)\s*=\s*['"]([^'"]+)['"]""", re.I)

ROOT_DOMAIN_RE = re.compile(r"([A-Za-z0-9-]+)\.([A-Za-z0-9-]+\.[A-Za-z]{2,})$")  # crude, good enough for triage

# ---------- Models ----------
@dataclass
class Seed:
    seedId: int
    url: str
    source: str  # "cli" | "xml" | "link"
    host: str
    port: int
    scheme: str

@dataclass
class FindingMeta:
    server: Optional[str] = None
    x_powered_by: Optional[str] = None
    tech: Optional[List[str]] = None
    secrets: Optional[List[Dict[str, str]]] = None
    comments_found: Optional[int] = None

@dataclass
class Finding:
    id: int
    parentSeedId: int
    url: str
    status: int
    length: int
    headers_path: str
    body_path: str
    screenshot_path: Optional[str]
    meta: FindingMeta
    branch_depth: int

@dataclass
class FindingsJson:
    run_id: str
    elapsed_sec: int
    config: Dict[str, Any]
    seeds: List[Seed]
    findings: List[Finding]

# ---------- Utils ----------
def now_utc_run_id() -> str:
    return datetime.now(timezone.utc).strftime(RUN_ID_FMT)

def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

def sha1_hex(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8", "ignore")).hexdigest()

def normalize_url(scheme: str, host: str, port: Optional[int], path: str) -> str:
    hostport = host if (port in [None, 80, 443]) or \
               (scheme == "http" and port == 80) or \
               (scheme == "https" and port == 443) else f"{host}:{port}"
    if not path.startswith("/"):
        path = "/" + path
    return f"{scheme}://{hostport}{path}"

def is_dir_like(path: str) -> bool:
    return bool(DIR_LIKE_RE.search(path.rstrip()))

def redactor(val: str) -> str:
    return (val[:6] + "…redacted…" + val[-4:]) if len(val) > 10 else "***redacted***"

def read_file_text(path: Path) -> str:
    try: return path.read_text(errors="replace")
    except Exception: return ""

def parse_headers_for_meta(headers_text: str) -> Tuple[Optional[str], Optional[str]]:
    server = xpb = None
    for line in headers_text.splitlines():
        low = line.lower()
        if low.startswith("server:"):
            server = line.split(":", 1)[1].strip()
        if low.startswith("x-powered-by:"):
            xpb = line.split(":", 1)[1].strip()
    return server, xpb

def extract_meta_from_body(body_text: str) -> Tuple[List[str], List[Dict[str, str]], int, List[str]]:
    comments = body_text.count(COMMENT_OPEN)
    tech = []
    for name, rx in TECH_REGEX.items():
        if rx.search(body_text):
            if name == "jQuery":
                m = re.search(TECH_REGEX["jQuery"], body_text)
                ver = m.group(1) if m and m.groups() else None
                tech.append(f"jQuery {ver}" if ver else "jQuery")
            else:
                tech.append(name)
    secrets = []
    for sname, rx in SECRET_REGEX.items():
        for m in rx.finditer(body_text):
            secrets.append({"type": sname, "match": redactor(m.group(0))})
    exts = [m.group(1).lower() for m in EXT_RE.finditer(body_text)]
    return sorted(set(tech)), secrets, comments, sorted(set(exts))

def guess_scheme(port: int, prefer_https: bool) -> str:
    if port == 443: return "https"
    if port == 80:  return "https" if prefer_https else "http"
    return "https" if prefer_https else "http"

def count_lines(path: Path) -> int:
    """Count the number of lines in *path* efficiently.

    The previous implementation iterated line-by-line in Python which is
    noticeably slower for large wordlists.  Reading in larger binary chunks
    lets us count newlines using highly optimised C code while keeping memory
    usage low.
    """
    try:
        with path.open("rb") as f:
            count = 0
            ends_with_newline = True
            had_bytes = False
            while True:
                chunk = f.read(1 << 15)  # 32 KiB chunks balance I/O and memory
                if not chunk:
                    break
                had_bytes = True
                ends_with_newline = chunk.endswith(b"\n")
                count += chunk.count(b"\n")
            if had_bytes and not ends_with_newline:
                count += 1
            return count
    except Exception:
        return 0

def slugify(s: str, maxlen: int = 80) -> str:
    s = s.strip()
    s = re.sub(r"[^\w.\-~/]", "_", s)
    s = s.replace("//", "/")
    return (s[:maxlen] if len(s) > maxlen else s) or "root"

def url_parts(url: str) -> Tuple[str, int, str]:
    m = re.match(r"^(https?)://([^/:]+)(?::(\d+))?(/.*)?$", url, re.I)
    if not m: return ("unknown", 0, "/")
    scheme, host, port, path = m.group(1), m.group(2), m.group(3), m.group(4) or "/"
    port = int(port) if port else (443 if scheme == "https" else 80)
    return host, port, path

def detect_default_wordlist() -> Path:
    candidates = [
        "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/opt/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt",
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
    ]
    for p in candidates:
        if Path(p).exists():
            return Path(p)
    # tiny fallback
    fallback = Path(__file__).with_name("hawkeye-mini.txt")
    if not fallback.exists():
        fallback.write_text("admin\nlogin\nimages\nimg\ncss\njs\napi\nuploads\n", encoding="utf-8")
    return fallback

def crop_wordlist(src: Path, dst: Path, max_lines: int) -> int:
    if max_lines <= 0:
        dst.write_bytes(b"")
        return 0

    written = 0
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        for line in fin:
            fout.write(line)
            written += 1
            if written >= max_lines:
                break
    return written

def root_domain_of(host: str) -> Optional[str]:
    # naive: keeps last two labels (domain.tld); good enough for CTF/HTB style
    m = ROOT_DOMAIN_RE.search(host)
    return m.group(0) if m else None

# ---------- Nmap XML (minimal) ----------
def read_nmap_xml_files(paths: List[Path]) -> List[Tuple[str, int, str]]:
    results = []
    rx_addr = re.compile(r'<address[^>]*addr="([^"]+)"')
    rx_hostn = re.compile(r'<hostname[^>]*name="([^"]+)"')
    for p in paths:
        try:
            txt = read_file_text(p)
        except Exception:
            continue
        addr = None
        ma = rx_addr.search(txt)
        if ma: addr = ma.group(1)
        mh = rx_hostn.search(txt)
        host = mh.group(1) if mh else addr
        if not host: continue
        for chunk in re.findall(r'(<port.*?</port>)', txt, re.S | re.I):
            mp = re.search(r'portid="(\d+)"', chunk)
            ms = re.search(r'<service[^>]*name="([^"]+)"[^>]*?(tunnel="ssl")?[^>]*/?>', chunk, re.I)
            if not mp: continue
            port = int(mp.group(1))
            scheme = "https" if (ms and (ms.group(2) or "https" in (ms.group(1) or "").lower())) else "http"
            results.append((host, port, scheme))
    return results

# ---------- Core ----------
class Hawkeye:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.console = Console() if Console else None
        self.run_id = now_utc_run_id()
        self.root = Path(args.results_root).resolve() / self.run_id
        self.paths = {
            "headers": self.root / "headers",
            "bodies":  self.root / "bodies",
            "shots":   self.root / "shots",
            "ffuf":    self.root / "ffuf",
            "raw":     self.root / "raw",
            "lists":   self.root / "lists",
        }
        for p in self.paths.values(): ensure_dir(p)
        ensure_dir(self.root)

        self.summary_txt = self.root / "SUMMARY.txt"
        self.findings_json_path = self.root / "findings.json"
        self.urls_txt = self.root / "urls.txt"
        self.live_jsonl = self.root / "live.ndjson"

        self.urls_file = open(self.urls_txt, "a", encoding="utf-8")
        self.live_file = open(self.live_jsonl, "a", encoding="utf-8")

        self.index_json = self.root / "index.json"
        self.index_csv  = self.root / "index.csv"
        self._index_rows: List[Dict[str, Any]] = []

        self.start_ts = time.time()
        self.start_human = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")
        self.id_counter = 0
        self.findings: List[Finding] = []
        self.seeds: List[Seed] = []
        self.seed_keys: set = set()  # (scheme,host,port)
        self.visited: set = set()
        self.stop_requested = False

        # Wordlists / stages
        self.full_wordlist  = Path(args.dirs_wordlist).resolve() if args.dirs_wordlist else detect_default_wordlist()
        self.quick_wordlist = self.paths["lists"] / "quick.txt"
        self.quick_lines    = args.quick_lines

        self.full_wordlist_lines = count_lines(self.full_wordlist)
        target_quick_lines = min(self.quick_lines, self.full_wordlist_lines)

        current_quick_lines = count_lines(self.quick_wordlist) if self.quick_wordlist.exists() else None
        if current_quick_lines != target_quick_lines:
            current_quick_lines = crop_wordlist(self.full_wordlist, self.quick_wordlist, target_quick_lines)

        if current_quick_lines is None:
            current_quick_lines = target_quick_lines
        self.quick_wordlist_lines = current_quick_lines

        # progress counters
        self.words_done_global = 0
        self.words_total_global = 0
        self.task_total = 0
        self.task_completed = 0

        # extension learning
        self.ext_by_host: Dict[str, set] = {}
        self.default_exts = set(e.strip(".") for e in (args.exts.split(",") if args.exts else []))

        # HTTP headers/auth
        self.headers: List[str] = []
        if args.header: self.headers += args.header
        if args.cookie: self.headers.append(f"Cookie: {args.cookie}")
        if args.auth_file:
            try:
                for ln in Path(args.auth_file).read_text().splitlines():
                    ln = ln.strip()
                    if ln and ":" in ln:
                        self.headers.append(ln)
            except Exception:
                pass
        self.basic_auth = args.auth

        # UI state
        self.jobs_progress = self.words_progress = None
        self.jobs_task = self.words_task = None
        self.live = None
        self.job_views: List[Dict[str, Any]] = []

        signal.signal(signal.SIGINT, self._handle_sigint)

    # ---- lifecycle helpers ----
    def _handle_sigint(self, *_):
        self.stop_requested = True
        self._log_event("SIGNAL", {"signal": "SIGINT"})
        self._print("[!] Interrupt received, finishing current tasks…")

    def _print(self, msg: str):
        if self.console: self.console.print(msg)
        else: print(msg)

    def _ev(self, event: str, payload: Dict[str, Any]):
        o = {"ts": datetime.utcnow().isoformat() + "Z", "event": event}; o.update(payload);  return json.dumps(o, ensure_ascii=False)

    def _log_event(self, event: str, payload: Dict[str, Any]):
        self.live_file.write(self._ev(event, payload) + "\n"); self.live_file.flush()

    def _next_id(self) -> int:
        self.id_counter += 1; return self.id_counter

    def close(self):
        for f in (self.urls_file, self.live_file):
            try: f.close()
            except Exception: pass

    # ---- deps ----
    @staticmethod
    def _which(cmd: str) -> Optional[str]:
        for p in os.environ.get("PATH", "").split(os.pathsep):
            candidate = Path(p) / cmd
            if candidate.exists() and os.access(candidate, os.X_OK):
                return str(candidate)
        return None

    def check_deps(self):
        miss = [x for x in ["ffuf", "curl"] if not self._which(x)]
        if miss:
            self._print(f"[x] Missing required tools: {', '.join(miss)}")
            sys.exit(1)
        if self.args.screenshot_engine != "none":
            if self.args.screenshot_engine == "pyppeteer":
                if pyppeteer_launch is None:
                    self._print("[!] Screenshot engine 'pyppeteer' unavailable (module missing). Continuing without screenshots.")
                    self.args.screenshot_engine = "none"
            else:
                lookup = self.args.screenshot_engine if self.args.screenshot_engine != "eyewitness" else "EyeWitness"
                ok = self._which(lookup)
                if not ok:
                    self._print(f"[!] Screenshot engine '{self.args.screenshot_engine}' not found. Continuing without screenshots.")
                    self.args.screenshot_engine = "none"

    # ---- seeds ----
    def _add_seed_if_new(self, scheme: str, host: str, port: int, source: str) -> Optional[Seed]:
        key = (scheme, host, port)
        if key in self.seed_keys: return None
        seed_id = len(self.seeds) + 1
        url = normalize_url(scheme, host, port, "/")
        s = Seed(seed_id, url, source, host, port, scheme)
        self.seeds.append(s); self.seed_keys.add(key)
        self.urls_file.write(url + "\n"); self.urls_file.flush()
        self._print(f"[+] New seed: {url}  (source: {source})")
        self._log_event("SEED_ADDED", {"url": url, "source": source})
        return s

    def build_initial_seeds(self) -> List[Seed]:
        seeds: List[Seed] = []
        targets = []
        if self.args.target: targets.append(self.args.target.strip())
        if self.args.targets: targets.extend([t.strip() for t in self.args.targets])

        if not targets and self.args.nmap_xml:
            paths = [Path(p) for p in self.args.nmap_xml]
            for host, port, scheme in read_nmap_xml_files(paths):
                s = self._add_seed_if_new(scheme, host, port, "xml")
                if s: seeds.append(s)
        else:
            if not targets:
                target = input("Target/root domain (e.g., example.com): ").strip()
                if not target:
                    self._print("No target provided. Exiting."); sys.exit(2)
                targets = [target]
            ports = [int(p.strip()) for p in (self.args.ports or "80").split(",") if p.strip()]
            for host in targets:
                for port in ports:
                    scheme = guess_scheme(port, self.args.prefer_https)
                    s = self._add_seed_if_new(scheme, host, port, "cli")
                    if s: seeds.append(s)
        return seeds

    # ---- UI ----
    def _render_header(self, phase_name: str) -> Panel:
        title = Text(f"HAWKEYE — Subdomain & Directory Fuzzer  [{phase_name}]", style="bold cyan")
        info  = Text(f"run_id: {self.run_id}   started: {self.start_human}", style="dim")
        return Panel(Align.center(Text.assemble(title, "\n", info)), border_style="cyan", padding=(1,2))

    def _setup_progress(self, phase_name: str):
        if not (Progress and self.console and Live):
            self._print("[i] Basic UI (install 'rich' for full TUI)."); return
        self.jobs_progress = Progress(
            SpinnerColumn(), TextColumn("[bold blue]Jobs[/]"), BarColumn(),
            MofNCompleteColumn(), TimeElapsedColumn(), TimeRemainingColumn(), expand=True
        )
        self.words_progress = Progress(
            TextColumn("[bold green]Words[/]"),
            TaskProgressColumn(show_speed=True), BarColumn(),
            TextColumn("{task.completed:,}/{task.total:,}"),
            TimeElapsedColumn(), TimeRemainingColumn(), expand=True
        )
        self.jobs_task  = self.jobs_progress.add_task("jobs", total=0)
        self.words_task = self.words_progress.add_task("words", total=0)
        self.live = Live(refresh_per_second=10, console=self.console); self.live.start()
        self._live_render(phase_name)

    def _render_job_panel(self, view: Dict[str, Any]) -> Panel:
        title = view["title"]; n, t = view["words"]; sub = f"{n:,}/{t:,} words  —  hits: {len(view['hits'])}" if t else f"hits: {len(view['hits'])}"
        table = Table.grid(padding=0); table.add_column(justify="left", no_wrap=False, ratio=1)
        if view["hits"]:
            last = view["hits"][-14:]
            lines = [f"[green]{u}[/] [dim](status {s})[/]" for u,s in last]
            table.add_row("\n".join(lines))
        else:
            table.add_row("[dim]— no hits yet —[/dim]")
        style = "magenta" if view.get("running", False) else "grey50"
        return Panel(table, title=f"[bold]{'Current' if view.get('running', False) else 'Done'}[/]: {title}", subtitle=sub, border_style=style, padding=(1,2))

    def _live_render(self, phase_name: str):
        if not (Live and self.console): return
        header = self._render_header(phase_name)
        bars   = Columns([self.jobs_progress, self.words_progress], expand=True)
        panels = [self._render_job_panel(v) for v in self.job_views]
        content = Group(header, bars, *panels) if Group else Columns([header, bars] + panels, expand=True)
        self.live.update(Panel(content, border_style="blue"))

    def _advance_progress(self, phase_name: str):
        if self.jobs_progress and self.words_progress:
            self.jobs_progress.update(self.jobs_task,  completed=self.task_completed, total=max(self.task_total, 1))
            self.words_progress.update(self.words_task, completed=self.words_done_global, total=max(self.words_total_global, 1))
            self._live_render(phase_name)

    def _teardown_progress(self):
        try:
            if self.live: self.live.stop()
        except Exception: pass

    # ---- run (4-phase, with subdomain priority) ----
    def run(self):
        self.check_deps()
        self.build_initial_seeds()

        phases = [
            ("quick",          self.quick_wordlist, False),
            ("quick + ext",    self.quick_wordlist, True),
            ("full",           self.full_wordlist,  False),
            ("full + ext",     self.full_wordlist,  True),
        ]

        for phase_name, wordlist, use_ext in phases:
            if self.stop_requested: break

            # Each phase: keep scanning until no NEW seeds (subdomains) are added.
            scanned_seed_keys = set()
            while True and not self.stop_requested:
                # Any unscanned seeds for this phase?
                pending = [s for s in self.seeds if (s.scheme, s.host, s.port) not in scanned_seed_keys]
                if not pending:
                    break

                self._phase_scan(phase_name, wordlist, use_ext, pending)
                # Mark scanned
                for s in pending:
                    scanned_seed_keys.add((s.scheme, s.host, s.port))

        self._write_index_files(); self._write_findings_json(); self._write_summary()
        self._print_done()

    def _phase_scan(self, phase_name: str, wordlist: Path, use_ext: bool, seeds_batch: List[Seed]):
        # reset counters & UI
        self.words_done_global = 0
        self.words_total_global = 0
        self.task_total = 0
        self.task_completed = 0
        self.job_views.clear()
        self.visited.clear()

        if wordlist == self.quick_wordlist:
            dirs_wl_lines = self.quick_wordlist_lines
        elif wordlist == self.full_wordlist:
            dirs_wl_lines = self.full_wordlist_lines
        else:
            dirs_wl_lines = count_lines(wordlist)
        baseline_sizes: Dict[str,int] = {}

        # capture roots to learn baseline sizes + ext hints
        for s in seeds_batch:
            rid = self._capture_and_parse(s.seedId, s.url, depth=0)
            if rid:
                body_file = next((p for p in self.paths["bodies"].glob(f"{rid}__*.html")), None)
                if body_file:
                    baseline_sizes[s.url] = body_file.stat().st_size

        # queue bases
        q: "queue.Queue[Tuple[int,str,int]]" = queue.Queue()
        bases = []
        for s in seeds_batch:
            base = s.url.rstrip("/")
            q.put((s.seedId, base, 0))
            bases.append(base)
        self.task_total = q.qsize()
        self.words_total_global = self.task_total * dirs_wl_lines

        self._setup_progress(phase_name)

        while not q.empty() and not self.stop_requested:
            parentSeedId, base_url, depth = q.get()
            try:
                job_view = {"title": f"[seed {parentSeedId}] {base_url}", "hits": [], "words": (0, dirs_wl_lines), "running": True, "base": base_url}
                self.job_views.append(job_view); self._advance_progress(phase_name)

                hits = self._ffuf_dirs(parentSeedId, base_url, depth, job_view, wordlist, use_ext, fs_size=baseline_sizes.get(base_url+"/", 0))

                for path, status_code in hits:
                    if (not path) or (" " in path) or ("#" in path) or path.startswith("#"):
                        continue
                    url = base_url.rstrip("/") + "/" + path.lstrip("/")
                    self._capture_and_parse(parentSeedId, url, depth)

                    try_path = "/" + path.strip("/")
                    if depth < self.args.max_depth and status_code in ENQUEUE_CODES and is_dir_like(try_path):
                        host = self._url_host(base_url)
                        vid = sha1_hex(f"{host}{try_path}{depth+1}__{phase_name}")
                        if vid not in self.visited:
                            self.visited.add(vid)
                            new_base = base_url.rstrip("/") + (try_path if try_path.endswith("/") else try_path + "/")
                            q.put((parentSeedId, new_base.rstrip("/"), depth + 1))
                            self.task_total += 1; self.words_total_global += dirs_wl_lines; self._advance_progress(phase_name)
            finally:
                job_view["running"] = False; self.task_completed += 1; self._advance_progress(phase_name)
                q.task_done()

        self._teardown_progress()

    # ---- ffuf helpers ----
    @staticmethod
    def _url_host(base_url: str) -> str:
        m = re.match(r"^[a-z]+://([^/]+)", base_url, re.I)
        return m.group(1) if m else base_url

    def _ffuf_dirs(self, parentSeedId: int, base_url: str, depth: int, job_view: Dict[str, Any],
                   wordlist: Path, use_ext: bool, fs_size: int = 0) -> List[Tuple[str,int]]:
        target_url = base_url.rstrip("/") + "/FUZZ"
        host, port, _ = url_parts(base_url)
        short = f"dirs-{parentSeedId}-{host}-{port}-d{depth}-p{self.run_id[-6:]}"  # short, readable
        out_json = self.paths["ffuf"] / f"{short}.json"
        out_log  = self.paths["ffuf"] / f"{short}.log"

        cmd = [
            "ffuf",
            "-w", str(wordlist),
            "-u", target_url,
            "-mc", self.args.codes,
            "-t", str(self.args.threads),
            "-rate", str(self.args.rate),
            "-timeout", str(self.args.ffuf_timeout),
            "-of", "json",
            "-o", str(out_json),
            "-ic",
        ]
        for h in self.headers: cmd += ["-H", h]
        if self.basic_auth:   cmd += ["-maxtime-job", "0"]  # let curl do auth; ffuf still runs normally
        if fs_size > 0:       cmd += ["-fs", str(fs_size)]
        if use_ext:
            exts = set(self.default_exts)
            exts.update(self.ext_by_host.get(host, set()))
            if exts:
                cmd += ["-e", ",".join("." + e for e in sorted(exts))]

        self._log_event("FFUF_START", {"cmd": " ".join(shlex.quote(c) for c in cmd), "seed": parentSeedId, "base": base_url})

        hits: List[Tuple[str,int]] = []
        seen_hit = set()
        prog_current, prog_total = 0, 0  # will be updated from ffuf stream
        job_view["words"] = (0, 0)

        with open(out_log, "w", encoding="utf-8") as logf:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            try:
                for raw in proc.stdout:  # type: ignore
                    line = ANSI_RE.sub("", raw).replace("\r", "")
                    logf.write(line)

                    mprog = PROG_RE.search(line)
                    if mprog:
                        new_cur = int(mprog.group("done")); new_tot = int(mprog.group("total"))
                        # keep totals in sync with ffuf (extensions inflate total, first seen here)
                        if new_tot != prog_total:
                            # adjust global total by delta
                            self.words_total_global += (new_tot - prog_total)
                            prog_total = new_tot
                        if new_cur > prog_current:
                            self.words_done_global += (new_cur - prog_current)
                            prog_current = new_cur
                        job_view["words"] = (prog_current, prog_total)
                        self._advance_progress(phase_name="")  # title updated in outer loop
                        continue

                    mhit = HIT_RE.search(line)
                    if mhit:
                        seg = mhit.group("path").strip()
                        status = int(mhit.group("code"))
                        if not seg or "#" in seg or " " in seg:
                            continue
                        if seg not in seen_hit:
                            seen_hit.add(seg)
                            hits.append((seg, status))
                            full_url = base_url.rstrip("/") + "/" + seg.lstrip("/")
                            job_view["hits"].append((full_url, status))
                            self._print(f"[hit] {full_url} (status {status})")
                            self._advance_progress(phase_name="")
            finally:
                proc.wait()

        hits += [h for h in self._parse_ffuf_hits(out_json) if h not in hits]
        self._log_event("FFUF_HITS", {"count": len(hits), "type": "dirs", "seed": parentSeedId})
        return hits

    def _parse_ffuf_hits(self, out_json: Path) -> List[Tuple[str,int]]:
        try:
            data = json.loads(out_json.read_text())
        except Exception:
            return []
        hits = []
        for r in data.get("results", []):
            status = int(r.get("status", 0))
            path = (r.get("input") or {}).get("FUZZ", "")
            if not path:
                url = r.get("url") or ""
                path = url.rsplit("/", 1)[-1] if "/" in url else url
            if not path or " " in path or "#" in path or path.startswith("#"):
                continue
            hits.append((path.strip(), status))
        return hits

    # ---- capture/parse + link discovery ----
    def _add_index_row(self, *, id:int, url:str, status:int, headers_path:str, body_path:str, raw_path:str, screenshot_path:Optional[str], depth:int):
        host, port, path = url_parts(url)
        self._index_rows.append({
            "id": id, "url": url, "host": host, "port": port, "path": path, "status": status,
            "headers": headers_path, "body": body_path, "raw": raw_path, "screenshot": screenshot_path, "depth": depth,
        })

    def _extract_links(self, base_url: str, body_text: str):
        host, port, base_path = url_parts(base_url)
        rd = root_domain_of(host) or host

        abs_urls = set()
        rel_paths = set()
        exts = set()

        if BeautifulSoup:
            try:
                soup = BeautifulSoup(body_text, "lxml")
            except Exception:
                soup = BeautifulSoup(body_text, "html.parser")
            for tag in soup.find_all(src=True):
                rel_paths.add(str(tag.get("src")))
            for tag in soup.find_all(href=True):
                rel_paths.add(str(tag.get("href")))
            txt = body_text
        else:
            txt = body_text
            for m in HREF_SRC_RE.finditer(txt):
                rel_paths.add(m.group(1))

        for m in ABS_URL_RE.finditer(txt):
            abs_urls.add(m.group(0))

        # Learn extensions from obvious filenames
        for m in EXT_RE.finditer(txt):
            exts.add(m.group(1).lower())

        # Normalize
        cleaned_rel = set()
        for p in rel_paths:
            if not p or p.startswith("#"): continue
            if p.startswith("http://") or p.startswith("https://"):
                abs_urls.add(p); continue
            if p.startswith("//"):  # protocol-relative
                abs_urls.add(("https:" if base_url.startswith("https") else "http:") + p); continue
            if not p.startswith("/"):
                # relative to current base path
                base_dir = base_path if base_path.endswith("/") else base_path.rsplit("/",1)[0] + "/"
                p = base_dir + p
            cleaned_rel.add(p)

        # Enqueue: rel paths on same host (dir-like)
        for rp in cleaned_rel:
            if is_dir_like(rp):
                vid = sha1_hex(f"{host}{rp}{'ld'}")
                if vid not in self.visited:
                    self.visited.add(vid)
                    new_base = normalize_url("http" if port==80 else "https", host, port, rp if rp.endswith("/") else rp + "/")
                    self._print(f"[link] enqueue base: {new_base}")
                    # immediate enqueue happens in caller by returning these paths
                    yield ("dir_base", new_base)

        # Subdomains on same root -> new seeds (port 80, http)
        for url in abs_urls:
            try:
                m = re.match(r"^(https?)://([^/:]+)", url, re.I)
                if not m: continue
                scheme = m.group(1).lower(); h = m.group(2).lower()
                if h == host or rd not in h:  # only subdomains of same root
                    continue
                s = self._add_seed_if_new("http", h, 80, "link")
                if s:
                    self._print(f"[subdomain] {s.url}")
            except Exception:
                pass

        if exts:
            self.ext_by_host.setdefault(host, set()).update(exts)

    def _capture_and_parse(self, parentSeedId: int, url: str, depth: int) -> Optional[int]:
        if self.stop_requested: return None
        rid = self._next_id()
        host, port, path = url_parts(url)
        path_slug = slugify(path if path != "/" else "root")
        base_slug = f"{host}-{port}-{path_slug}"

        headers_path = self.paths["headers"] / f"{rid}__{base_slug}.txt"
        body_path    = self.paths["bodies"]  / f"{rid}__{base_slug}.html"
        raw_file     = self.paths["raw"]     / f"{rid}__{base_slug}.http"
        shot_path    = self.paths["shots"]   / f"{rid}__{base_slug}.png"

        curl_cmd = ["curl","-sS","--max-time",str(self.args.curl_timeout),"-i","-L","-k"]
        for h in self.headers: curl_cmd += ["-H", h]
        if self.basic_auth:   curl_cmd += ["-u", self.basic_auth]
        curl_cmd += [url]

        self._log_event("CAPTURE_START", {"url": url, "id": rid})
        rc, status_code, length, body_bytes = self._curl_and_split(curl_cmd, raw_file, headers_path, body_path)
        if rc != 0:
            self._log_event("CAPTURE_ERROR", {"url": url, "id": rid, "rc": rc});  return None

        body_text = body_bytes.decode(errors="ignore") if body_bytes else ""
        if body_text:
            # learn extensions and discover links
            tech, secrets, comments_count, more_exts = extract_meta_from_body(body_text)
            if more_exts:
                self.ext_by_host.setdefault(host, set()).update(more_exts)
            # return discovered dir-bases to be queued by caller
            for kind, value in self._extract_links(url, body_text):
                # Just inform; actual queueing for dir-bases happens in _phase_scan via ffuf hits + branch.
                pass
        else:
            tech, secrets, comments_count, more_exts = ([], [], 0, [])

        screenshot_path = None
        if self.args.screenshot_engine != "none":
            if self._screenshot(url, shot_path):
                screenshot_path = f"shots/{shot_path.name}"

        headers_text = read_file_text(headers_path)
        server, xpb = parse_headers_for_meta(headers_text)

        finding = Finding(
            id=rid, parentSeedId=parentSeedId, url=url, status=status_code, length=length,
            headers_path=f"headers/{headers_path.name}", body_path=f"bodies/{body_path.name}",
            screenshot_path=screenshot_path,
            meta=FindingMeta(server=server, x_powered_by=xpb, tech=tech or None, secrets=secrets or None, comments_found=comments_count),
            branch_depth=depth,
        )
        self.findings.append(finding)
        self._add_index_row(
            id=rid, url=url, status=status_code,
            headers_path=f"headers/{headers_path.name}", body_path=f"bodies/{body_path.name}", raw_path=f"raw/{raw_file.name}",
            screenshot_path=screenshot_path, depth=depth,
        )
        self._log_event("PARSE_DONE", {"url": url, "id": rid, "status": status_code})
        return rid

    def _curl_and_split(self, cmd: List[str], raw_file: Path, headers_path: Path, body_path: Path) -> Tuple[int,int,int,bytes]:
        try:
            with open(raw_file, "wb") as f:
                p = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE)
            if p.returncode != 0: return p.returncode, 0, 0, b""
            raw = raw_file.read_bytes()
            parts = raw.split(b"\r\n\r\n");  parts = parts if len(parts)>=2 else raw.split(b"\n\n")
            if len(parts) < 2:
                headers_path.write_bytes(raw); body_path.write_bytes(b"");  return 0,0,0, b""
            header_bytes = parts[-2]; body_bytes = parts[-1]
            headers_path.write_bytes(header_bytes); body_path.write_bytes(body_bytes)
            status_code = 0
            for line in header_bytes.splitlines():
                if line.startswith(b"HTTP/"):
                    try: status_code = int(line.split()[1])
                    except Exception: pass
            return 0, status_code, len(body_bytes), body_bytes
        except Exception:
            return 1, 0, 0, b""

    def _screenshot(self, url: str, out_path: Path) -> bool:
        eng = self.args.screenshot_engine
        if eng == "gowitness":
            cmd = [
                "gowitness",
                "single",
                "--url",
                url,
                "--timeout",
                str(self.args.screenshot_timeout),
                "--disable-logging",
                "--screenshot-path",
                str(self.paths["shots"]),
            ]
            try:
                subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
                pngs = sorted(self.paths["shots"].glob("*.png"), key=lambda p: p.stat().st_mtime, reverse=True)
                if pngs:
                    out_path.write_bytes(pngs[0].read_bytes())
                    return True
            except Exception:
                return False
            return False

        if eng == "pyppeteer":
            return self._screenshot_pyppeteer(url, out_path)

        return False

    def _screenshot_pyppeteer(self, url: str, out_path: Path) -> bool:
        if pyppeteer_launch is None:
            return False

        async def _capture() -> bool:
            browser = await pyppeteer_launch(headless=True, args=["--no-sandbox", "--disable-gpu"])
            try:
                page = await browser.newPage()
                await page.setViewport({"width": 1920, "height": 1080})
                try:
                    await page.goto(url, timeout=self.args.screenshot_timeout * 1000, waitUntil="networkidle2")
                except Exception:
                    await page.goto(url, timeout=self.args.screenshot_timeout * 1000, waitUntil="load")
                await page.screenshot(path=str(out_path), fullPage=True)
                return True
            finally:
                await browser.close()

        try:
            try:
                running_loop = asyncio.get_running_loop()
            except RuntimeError:
                running_loop = None

            if running_loop is not None:
                new_loop = asyncio.new_event_loop()
                try:
                    return new_loop.run_until_complete(_capture())
                finally:
                    new_loop.close()
            else:
                return asyncio.run(_capture())
        except Exception:
            return False

    # ---- outputs ----
    def _write_index_files(self):
        try:
            import csv
            headers = ["id","url","host","port","path","status","headers","body","raw","screenshot","depth"]
            with open(self.index_csv, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=headers); w.writeheader()
                for r in self._index_rows: w.writerow(r)
            self.index_json.write_text(json.dumps(self._index_rows, indent=2))
        except Exception: pass

    def _write_findings_json(self):
        elapsed = int(time.time() - self.start_ts)
        cfg = {
            "rate": self.args.rate, "threads": self.args.threads, "max_depth": self.args.max_depth,
            "quick_lines": self.args.quick_lines, "pipeline": ["quick","quick+ext","full","full+ext"],
            "quick_wordlist": str(self.quick_wordlist), "full_wordlist": str(self.full_wordlist),
            "screenshot_engine": self.args.screenshot_engine,
            "exts_default": sorted(self.default_exts),
        }
        payload = FindingsJson(run_id=self.run_id, elapsed_sec=elapsed, config=cfg, seeds=self.seeds, findings=self.findings)
        def default(o): return asdict(o) if dataclasses.is_dataclass(o) else o
        self.findings_json_path.write_text(json.dumps(payload, default=default, indent=2))

    def _write_summary(self):
        elapsed = int(time.time() - self.start_ts)
        lines = [
            f"HAWKEYE v1.3 Summary — run_id={self.run_id}",
            f"Elapsed: {elapsed}s",
            f"Seeds: {len(self.seeds)}",
            f"Findings: {len(self.findings)}",
            f"quick_wordlist: {self.quick_wordlist} (lines: {self.quick_wordlist_lines})",
            f"full_wordlist : {self.full_wordlist} (lines: {self.full_wordlist_lines})",
            f"Results root: {self.root}",
        ]
        self.summary_txt.write_text("\n".join(lines) + "\n")

    def _print_done(self):
        elapsed = int(time.time() - self.start_ts)
        self._print(f"[✓] Done in {elapsed}s — seeds: {len(self.seeds)} | results: {len(self.findings)}")
        self._print(f"[+] Summary : {self.summary_txt}")
        self._print(f"[+] Findings: {self.findings_json_path}")
        self._print(f"[+] Index   : {self.index_csv} (and {self.index_json})")

# ---------- CLI ----------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="hawkeye", description="SecLists-powered subdomain + directory discovery with branching, capture & screenshots.")
    # Modes / inputs
    p.add_argument("--mode", choices=["interactive","xml"], default=None)
    p.add_argument("--nmap-xml", nargs="*", default=[])
    p.add_argument("--target", help="root domain or host")
    p.add_argument("--targets", nargs="*", default=[])
    # Easy defaults: HTTP only, port 80
    p.add_argument("--ports", default="80")
    p.add_argument("--prefer-https", action="store_true")
    # Wordlist / Pipeline
    p.add_argument("--dirs-wordlist", default=None, help="Full wordlist (defaults auto-detected).")
    p.add_argument("--quick-lines", type=int, default=10000, help="Lines used in quick stages.")
    # Scan controls (fast defaults)
    p.add_argument("--max-depth", type=int, default=2)
    p.add_argument("--threads", type=int, default=80)
    p.add_argument("--rate", type=int, default=300)
    p.add_argument("--codes", default=DEFAULT_CODES)
    p.add_argument("--ffuf-timeout", dest="ffuf_timeout", type=int, default=7)
    # Capture / screenshots
    p.add_argument("--screenshot-engine", choices=["gowitness","aquatone","eyewitness","pyppeteer","none"], default="none")
    p.add_argument("--screenshot-timeout", type=int, default=15)
    p.add_argument("--curl-timeout", type=int, default=15)
    # Auth / headers
    p.add_argument("--cookie", help="Cookie string, e.g. 'sid=abc; a=1'")
    p.add_argument("--auth", help="HTTP basic auth user:pass")
    p.add_argument("--header", action="append", help="Extra header, e.g. 'Authorization: Bearer …' (repeatable)")
    p.add_argument("--auth-file", help="File with headers, one per line (e.g., Cookie:, Authorization:)")
    # Extension defaults (only used in ext phases; learning adds more)
    p.add_argument("--exts", help="Comma list of default extensions to try in ext phases (e.g., php,html,txt).")
    # Output
    p.add_argument("--results-root", default="./results")
    p.add_argument("--workers", type=int, default=6)
    p.add_argument("--resume", default=None)
    # Optional YAML (CLI wins)
    p.add_argument("--config", help="YAML config to merge (CLI overrides)")
    return p

def apply_yaml_overrides(args: argparse.Namespace) -> argparse.Namespace:
    if not args.config: return args
    if not yaml:
        print("[!] pyyaml not installed but --config provided.", file=sys.stderr); sys.exit(2)
    cfg = yaml.safe_load(Path(args.config).read_text())

    if args.mode is None: args.mode = cfg.get("mode", None)
    if not args.nmap_xml: args.nmap_xml = cfg.get("nmap_xml", [])
    if not args.target and not args.targets:
        tgs = cfg.get("targets", []);  args.targets = tgs or args.targets
    if args.ports == "80" and cfg.get("ports"): args.ports = ",".join(str(p) for p in cfg["ports"])
    if not args.prefer_https and cfg.get("prefer_https"): args.prefer_https = True

    wl = cfg.get("wordlists", {})
    if not args.dirs_wordlist and wl.get("dirs"): args.dirs_wordlist = wl["dirs"]
    if "quick_lines" in cfg and args.quick_lines == 10000: args.quick_lines = int(cfg["quick_lines"])

    sc = cfg.get("scan", {})
    for k in ["max_depth","threads","rate","codes"]:
        if k in sc: setattr(args, k if k!="max_depth" else "max_depth", sc[k])

    cap = cfg.get("capture", {})
    if "curl_timeout" in cap and args.curl_timeout == 15: args.curl_timeout = cap["curl_timeout"]
    if "screenshot_engine" in cap and args.screenshot_engine == "none": args.screenshot_engine = cap["screenshot_engine"]
    if "screenshot_timeout" in cap and args.screenshot_timeout == 15: args.screenshot_timeout = cap["screenshot_timeout"]

    out = cfg.get("output", {})
    if "results_root" in out and args.results_root == "./results": args.results_root = out["results_root"]
    if "workers" in out and args.workers == 6: args.workers = out["workers"]
    if "resume_db" in out and args.resume is None: args.resume = out["resume_db"]
    return args

# ---------- Entry ----------
def main():
    parser = build_parser()
    args = parser.parse_args()
    args = apply_yaml_overrides(args)

    hk = Hawkeye(args)
    try:
        hk.run()
    except Exception:
        try: hk._teardown_progress()
        except Exception: pass
        raise
    finally:
        hk.close()

if __name__ == "__main__":
    main()
