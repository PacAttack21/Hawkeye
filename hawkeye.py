#!/usr/bin/env python3
"""
HAWKEYE v2.0 — CPTC Competition Web Scanner
Target: Kali Linux (Python 3.10+)

Features:
- Subdomain enumeration phase (subfinder, amass, custom wordlists)
- Multi-phase scanning: subdomains → quick wins → deep scanning
- Interactive prompts for user guidance during competition
- Enhanced documentation and finding organization
- Robust resume functionality with crash recovery
- Competition-focused reporting and time tracking
- Async orchestration with ThreadPoolExecutor for ffuf subprocesses
- Resume via SQLite checkpoint (resume.db) and JSONL run log (hawkeye_log.ndjson)
- Per-host baseline detection (-fs / -fl) to reduce noise
- Parallel ffuf jobs, parallel curl captures, optional screenshots (gowitness)
- Per-finding artifact folder (headers, body, curl, meta, screenshot)
- Minimal external Python deps (rich optional)
"""

# Standard libs
import argparse
import asyncio
import concurrent.futures
import csv
import hashlib
import json
import os
import queue
import random
import re
import shlex
import signal
import sqlite3
import string
import subprocess
import sys
import threading
import time
import traceback
from collections import defaultdict
from contextlib import closing
from dataclasses import dataclass, asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Optional UI
try:
    from rich.console import Console
    from rich.live import Live
    from rich.progress import Progress, BarColumn, TimeElapsedColumn, TimeRemainingColumn, SpinnerColumn, TextColumn
    from rich.table import Table
    RICH_AVAILABLE = True
except Exception:
    Console = None
    Live = None
    Progress = None
    Table = None
    RICH_AVAILABLE = False

# ----------------------------
# Constants & small helpers
# ----------------------------
RUN_ID_FMT = "%Y-%m-%d_%H-%M-%S"
DEFAULT_CODES = "200,201,202,204,301,302,307,401,403"
ENQUEUE_CODES = {200, 201, 202, 204, 301, 302, 307, 401, 403}
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
HIT_RE = re.compile(r"^\s*(?P<path>[^\s\[]+)\s*\[Status:\s*(?P<code>\d+)", re.I)
PROG_RE = re.compile(r"::\s*Progress:\s*\[(?P<done>\d+)\/(?P<total>\d+)\]")
ABS_URL_RE = re.compile(r"https?://[A-Za-z0-9\.\-:_/?#%+=@~,;]+", re.I)
HREF_SRC_RE = re.compile(r"""\b(?:href|src)\s*=\s*['"]([^'"]+)['"]""", re.I)
EXT_RE = re.compile(r"\.([a-z0-9]{1,5})(?:[^\w]|$)", re.I)
DIR_LIKE_RE = re.compile(r"/[^./]+/?$")

# Subdomain enumeration tools and wordlists
SUBDOMAIN_TOOLS = ["subfinder", "amass", "assetfinder"]
DEFAULT_SUBDOMAIN_WORDLIST = "subdomains.txt"

# Generate readable run ID with date and time
def run_id_now() -> str:
    return datetime.now().strftime(RUN_ID_FMT)

def slugify(s: str, maxlen: int = 80) -> str:
    s = s.strip().replace("//", "/")
    # Replace forward slashes with underscores for file names
    s = s.replace("/", "_")
    s = re.sub(r"[^\w.\-~]", "_", s)
    return (s[:maxlen] if len(s) > maxlen else s) or "root"

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def safe_write_bytes(p: Path, b: bytes) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b)

def now_iso() -> str:
    from datetime import datetime, UTC
    # timezone-aware UTC timestamp (no deprecation warning)
    return datetime.now(UTC).isoformat()

def sanitized_shell(cmd: List[str]) -> str:
    return " ".join(shlex.quote(x) for x in cmd)

def is_dir_like(path: str) -> bool:
    return bool(DIR_LIKE_RE.search(path.rstrip()))

# parse url parts simplistic
def url_parts(url: str) -> Tuple[str, int, str, str]:
    """
    returns (scheme, host, port, path)
    crude but fine for typical URLs used here. default ports: 443 for https, 80 for http
    """
    m = re.match(r"^(https?)://([^/:]+)(?::(\d+))?(/.*)?$", url, re.I)
    if not m:
        return ("http", url, 80, "/")
    scheme, host, port, path = m.group(1).lower(), m.group(2), m.group(3), (m.group(4) or "/")
    port = int(port) if port else (443 if scheme == "https" else 80)
    return scheme, host, port, path

# ----------------------------
# Dataclasses for findings & seeds
# ----------------------------
@dataclass
class Seed:
    id: int
    scheme: str
    host: str
    port: int
    url: str
    source: str

@dataclass
class FindingMeta:
    server: Optional[str] = None
    x_powered_by: Optional[str] = None
    tech: Optional[List[str]] = None
    secrets: Optional[List[Dict[str, str]]] = None
    comments_found: Optional[int] = None

@dataclass
class SubdomainRecord:
    id: int
    subdomain: str
    domain: str
    ip: Optional[str]
    tool: str
    source: str
    timestamp: str

@dataclass
class FindingRecord:
    id: int
    seed_id: int
    url: str
    status: int
    length: int
    headers_file: str
    body_file: str
    curl_file: str
    screenshot: Optional[str]
    meta: FindingMeta
    depth: int
    phase: str
    priority: int = 0  # 0=low, 1=medium, 2=high

# ----------------------------
# Core Hawkeye class
# ----------------------------
class Hawkeye:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.console = Console() if RICH_AVAILABLE else None
        
        # Setup run ID and paths
        self.run_id = args.resume_run_id if args.resume_run_id else run_id_now()
        self.root = Path(args.results_root).resolve() / self.run_id
        
        # Create directory structure efficiently
        self.paths = {
            "headers": self.root / "findings" / "headers",
            "bodies":  self.root / "findings" / "bodies",
            "curl":    self.root / "findings" / "curl",
            "shots":   self.root / "findings" / "shots",
            "ffuf":    self.root / "artifacts" / "ffuf",
            "raw":     self.root / "artifacts" / "raw",
            "subdomains": self.root / "artifacts" / "subdomains",
            "reports": self.root / "reports",
        }
        
        # Create directories in parallel
        for p in self.paths.values():
            p.mkdir(parents=True, exist_ok=True)
        
        # File paths
        self.summary_txt = self.root / "summary.txt"
        self.seeds_txt = self.root / "seeds.txt"
        self.log_jsonl = self.root / "hawkeye_log.ndjson"
        self.resume_db = self.root / "resume.db"
        
        # Runtime state
        self.start_ts = time.time()
        self.competition_start = time.time()
        self.id_counter = 0
        self.findings: List[FindingRecord] = []
        self.subdomains: List[SubdomainRecord] = []
        self.seeds: Dict[Tuple[str,int,str], Seed] = {}
        self.seed_list: List[Seed] = []
        self.seed_lock = threading.Lock()
        self.visited_bases: Set[str] = set()
        self.visited_urls: Set[str] = set()  # Track visited URLs to prevent duplicates
        self.ext_by_host: Dict[str, Set[str]] = defaultdict(set)
        self.baseline_by_host: Dict[str, Dict[str, Any]] = {}
        self.phase_times: Dict[str, float] = {}
        self.interactive_mode = not args.background
        
        # Progress tracking
        self.total_jobs = 0
        self.completed_jobs = 0
        self.current_phase = ""
        self.current_url = "Starting..."
        self.last_progress_update = 0
        
        # Queues and concurrency
        self.ffuf_job_q: "asyncio.Queue[Dict]" = asyncio.Queue()
        self.capture_q: "asyncio.Queue[Dict]" = asyncio.Queue()
        self.screenshot_q: "asyncio.Queue[Dict]" = asyncio.Queue()
        
        # Initialize database
        self._init_resume_db()
        
        # Concurrency controls
        self.global_sem = asyncio.Semaphore(args.global_concurrency)
        self.host_semaphores: Dict[str, asyncio.Semaphore] = {}
        self.stop_requested = False
        
        # Signal handling
        self._register_sigint()
        
        # UI setup
        self.progress = None
        self.live = None
        if RICH_AVAILABLE:
            self._setup_rich()
        
        # Thread pool for blocking operations
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=max(4, args.workers))
        
        # Resume from previous run if requested
        if args.resume_run_id and self.resume_db.exists():
            self._load_resume_db(self.resume_db)

    # -----------------------
    # Resume DB (sqlite) — simple job checkpointing
    # -----------------------
    def _init_resume_db(self):
        # ensure directory
        self.resume_db.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.resume_db))
        with closing(conn):
            cur = conn.cursor()
            cur.execute("""CREATE TABLE IF NOT EXISTS seeds (
                scheme TEXT, host TEXT, port INTEGER, url TEXT, source TEXT, scanned INTEGER DEFAULT 0, PRIMARY KEY(scheme,host,port)
            )""")
            cur.execute("""CREATE TABLE IF NOT EXISTS ffuf_jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT, seed_scheme TEXT, seed_host TEXT, seed_port INTEGER,
                base_url TEXT, depth INTEGER, phase TEXT, wordlist TEXT, use_ext INTEGER, state TEXT DEFAULT 'pending'
            )""")
            cur.execute("""CREATE TABLE IF NOT EXISTS subdomains (
                subdomain TEXT, domain TEXT, ip TEXT, tool TEXT, source TEXT, timestamp TEXT, PRIMARY KEY(subdomain,domain)
            )""")
            conn.commit()

    def _save_seed_resume(self, s: Seed):
        conn = sqlite3.connect(str(self.resume_db))
        with closing(conn):
            cur = conn.cursor()
            cur.execute("INSERT OR REPLACE INTO seeds(scheme,host,port,url,source,scanned) VALUES(?,?,?,?,?,?)",
                        (s.scheme, s.host, s.port, s.url, s.source, 0))
            conn.commit()
    def _enqueue_ffuf_resume(self, base_url: str, seed: Seed, depth: int, phase: str, wordlist: str, use_ext: bool):
        conn = sqlite3.connect(str(self.resume_db))
        with closing(conn):
            cur = conn.cursor()
            cur.execute("INSERT INTO ffuf_jobs(seed_scheme,seed_host,seed_port,base_url,depth,phase,wordlist,use_ext) VALUES(?,?,?,?,?,?,?,?)",
                        (seed.scheme, seed.host, seed.port, base_url, depth, phase, wordlist, int(use_ext)))
            conn.commit()

    def _load_resume_db(self, path: Path):
        # read seeds and ffuf_jobs (pending)
        try:
            conn = sqlite3.connect(str(path))
            with closing(conn):
                cur = conn.cursor()
                cur.execute("SELECT scheme,host,port,url,source FROM seeds")
                rows = cur.fetchall()
                for r in rows:
                    scheme, host, port, url, src = r
                    with self.seed_lock:
                        key = (scheme, port, host)
                        if key not in self.seeds:
                            sid = len(self.seed_list) + 1
                            s = Seed(sid, scheme, host, port, url, src)
                            self.seeds[key] = s
                            self.seed_list.append(s)
                cur.execute("SELECT seed_scheme,seed_host,seed_port,base_url,depth,phase,wordlist,use_ext,state FROM ffuf_jobs WHERE state='pending'")
                jobs = cur.fetchall()
                for j in jobs:
                    scheme, host, port, base_url, depth, phase, wordlist, use_ext, state = j
                    job = {"seed_scheme": scheme, "seed_host": host, "seed_port": port, "base_url": base_url,
                           "depth": depth, "phase": phase, "wordlist": wordlist, "use_ext": bool(use_ext)}
                    # push to ffuf_q for resuming
                    asyncio.get_event_loop().call_soon_threadsafe(self.ffuf_job_q.put_nowait, job)
        except Exception:
            self._log("RESUME_LOAD_ERROR", {"err": traceback.format_exc()})

    # -----------------------
    # Signals
    # -----------------------
    def _register_sigint(self):
        def handler(sig, frame):
            self.stop_requested = True
            self._log("SIGNAL", {"signal": str(sig)})
            print("\n[!] SIGINT received — finishing in-flight work and checkpointing. Press Ctrl+C again to force quit.")
        signal.signal(signal.SIGINT, handler)

    # -----------------------
    # Logging - JSONL timeline
    # -----------------------
    def _log(self, event: str, payload: Dict[str, Any]):
        obj = {"ts": now_iso(), "event": event}
        obj.update(payload)
        try:
            with open(self.log_jsonl, "a", encoding="utf-8") as f:
                f.write(json.dumps(obj, default=str, ensure_ascii=False) + "\n")
        except Exception:
            print("[LOG_ERROR]", event, payload)

    # -----------------------
    # UI setup (rich)
    # -----------------------
    def _setup_rich(self):
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn()
        )
        self.live = Live(auto_refresh=False, refresh_per_second=2, console=self.console)

    # -----------------------
    # Seed management
    # -----------------------
    def _add_seed(self, scheme: str, host: str, port: int, source: str = "cli") -> Optional[Seed]:
        key = (scheme, port, host)
        with self.seed_lock:
            if key in self.seeds:
                return None
            sid = len(self.seed_list) + 1
            url = f"{scheme}://{host}" + (f":{port}" if (scheme == 'http' and port != 80) or (scheme == 'https' and port != 443) else "")
            url += "/"
            s = Seed(sid, scheme, host, port, url, source)
            self.seeds[key] = s
            self.seed_list.append(s)
            try:
                self._save_seed_resume(s)
            except Exception:
                pass
            with open(self.seeds_txt, "a", encoding="utf-8") as f:
                f.write(f"{url}\n")
            self._log("SEED_ADDED", {"url": url, "source": source})
            return s

    def build_initial_seeds(self):
        args = self.args
        if not args.target:
            target = input("Target URL (e.g., http://example.com): ").strip()
            if not target:
                print("No target provided. Exiting."); sys.exit(2)
            args.target = target
        
        # Parse the target URL
        target_url = args.target.strip()
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url
        
        try:
            scheme, host, port, path = url_parts(target_url)
            self._add_seed(scheme, host, port, "cli")
            
            # If subdomain enumeration is enabled, extract domain for subdomain scanning
            if args.enable_subdomain_enum:
                # Extract root domain (e.g., example.com from subdomain.example.com)
                domain_parts = host.split('.')
                if len(domain_parts) >= 2:
                    root_domain = '.'.join(domain_parts[-2:])
                    # Only add root domain as seed if it's different from the main target
                    if root_domain != host:
                        self._add_seed(scheme, root_domain, port, "subdomain_base")
        except Exception as e:
            print(f"❌ Invalid URL format: {target_url}")
            print("Please provide a valid URL like: http://example.com or https://example.com:8080")
            sys.exit(1)

    # -----------------------
    # Subdomain enumeration
    # -----------------------
    def _run_subfinder(self, domain: str) -> List[str]:
        """Run subfinder to discover subdomains"""
        # Check if subfinder is available
        try:
            subprocess.run(["subfinder", "-version"], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            self._log("SUBFINDER_NOT_AVAILABLE", {"domain": domain})
            return []
        
        cmd = ["subfinder", "-d", domain, "-silent", "-o", "-"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                subdomains = [line.strip() for line in result.stdout.split('\n') if line.strip()]
                self._log("SUBFINDER_SUCCESS", {"domain": domain, "count": len(subdomains)})
                return subdomains
            else:
                self._log("SUBFINDER_ERROR", {"domain": domain, "error": result.stderr})
                return []
        except subprocess.TimeoutExpired:
            self._log("SUBFINDER_TIMEOUT", {"domain": domain})
            return []
        except Exception as e:
            self._log("SUBFINDER_EXCEPTION", {"domain": domain, "error": str(e)})
            return []

    def _run_amass(self, domain: str) -> List[str]:
        """Run amass to discover subdomains"""
        # Check if amass is available
        try:
            subprocess.run(["amass", "version"], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            self._log("AMASS_NOT_AVAILABLE", {"domain": domain})
            return []
        
        cmd = ["amass", "enum", "-d", domain, "-silent"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if result.returncode == 0:
                subdomains = [line.strip() for line in result.stdout.split('\n') if line.strip()]
                self._log("AMASS_SUCCESS", {"domain": domain, "count": len(subdomains)})
                return subdomains
            else:
                self._log("AMASS_ERROR", {"domain": domain, "error": result.stderr})
                return []
        except subprocess.TimeoutExpired:
            self._log("AMASS_TIMEOUT", {"domain": domain})
            return []
        except Exception as e:
            self._log("AMASS_EXCEPTION", {"domain": domain, "error": str(e)})
            return []

    def _run_wordlist_bruteforce(self, domain: str, wordlist_path: str) -> List[str]:
        """Bruteforce subdomains using wordlist"""
        if not Path(wordlist_path).exists():
            self._log("WORDLIST_NOT_FOUND", {"path": wordlist_path})
            return []
        
        cmd = ["ffuf", "-w", wordlist_path, "-u", f"https://FUZZ.{domain}", "-mc", "200,301,302,403", "-t", "50", "-rate", "100", "-o", "-", "-of", "json", "-ic"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                try:
                    data = json.loads(result.stdout)
                    subdomains = []
                    for item in data.get("results", []):
                        subdomain = item.get("input", {}).get("FUZZ", "")
                        if subdomain:
                            subdomains.append(f"{subdomain}.{domain}")
                    self._log("WORDLIST_BRUTEFORCE_SUCCESS", {"domain": domain, "count": len(subdomains)})
                    return subdomains
                except json.JSONDecodeError:
                    self._log("WORDLIST_BRUTEFORCE_JSON_ERROR", {"domain": domain})
                    return []
            else:
                self._log("WORDLIST_BRUTEFORCE_ERROR", {"domain": domain, "error": result.stderr})
                return []
        except subprocess.TimeoutExpired:
            self._log("WORDLIST_BRUTEFORCE_TIMEOUT", {"domain": domain})
            return []
        except Exception as e:
            self._log("WORDLIST_BRUTEFORCE_EXCEPTION", {"domain": domain, "error": str(e)})
            return []

    def _resolve_subdomain_ip(self, subdomain: str) -> Optional[str]:
        """Resolve subdomain to IP address"""
        try:
            import socket
            ip = socket.gethostbyname(subdomain)
            return ip
        except socket.gaierror:
            # If subdomain can't be resolved, try to get the main domain's IP
            try:
                domain_parts = subdomain.split('.')
                if len(domain_parts) >= 2:
                    main_domain = '.'.join(domain_parts[-2:])
                    ip = socket.gethostbyname(main_domain)
                    return ip
            except socket.gaierror:
                pass
            return None

    def _save_subdomain(self, subdomain: str, domain: str, tool: str, source: str = "enum") -> None:
        """Save subdomain to database and memory"""
        ip = self._resolve_subdomain_ip(subdomain)
        timestamp = now_iso()
        
        # Save to database
        conn = sqlite3.connect(str(self.resume_db))
        with closing(conn):
            cur = conn.cursor()
            cur.execute("INSERT OR REPLACE INTO subdomains(subdomain,domain,ip,tool,source,timestamp) VALUES(?,?,?,?,?,?)",
                       (subdomain, domain, ip, tool, source, timestamp))
            conn.commit()
        
        # Save to memory
        subdomain_id = len(self.subdomains) + 1
        record = SubdomainRecord(subdomain_id, subdomain, domain, ip, tool, source, timestamp)
        self.subdomains.append(record)
        
        # Save to file
        subdomain_file = self.paths["subdomains"] / f"{domain}_subdomains.txt"
        with open(subdomain_file, "a") as f:
            f.write(f"{subdomain}\n")
        
        # Update /etc/hosts FIRST if subdomain resolves
        if ip and ip != "N/A":
            self._update_etc_hosts(subdomain, ip)
            
            # Test if subdomain is reachable after adding to /etc/hosts
            if self._test_subdomain_reachability(subdomain):
                self._log("SUBDOMAIN_REACHABLE", {"subdomain": subdomain, "ip": ip})
            else:
                self._log("SUBDOMAIN_NOT_REACHABLE", {"subdomain": subdomain, "ip": ip})
        
        self._log("SUBDOMAIN_FOUND", {"subdomain": subdomain, "domain": domain, "ip": ip, "tool": tool})

    def _test_subdomain_reachability(self, subdomain: str) -> bool:
        """Test if subdomain is reachable after adding to /etc/hosts"""
        try:
            import socket
            # Try to resolve the subdomain
            socket.gethostbyname(subdomain)
            
            # Try a quick HTTP request to see if it responds
            import subprocess
            result = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "5", f"http://{subdomain}"],
                capture_output=True, text=True, timeout=10
            )
            
            # If we get any HTTP response code, it's reachable
            return result.returncode == 0 and result.stdout.strip().isdigit()
            
        except Exception as e:
            self._log("SUBDOMAIN_REACHABILITY_TEST_ERROR", {"subdomain": subdomain, "error": str(e)})
            return False

    def _update_etc_hosts(self, subdomain: str, ip: str):
        """Update /etc/hosts with discovered subdomain"""
        try:
            # Check if entry already exists in /etc/hosts
            hosts_file = Path("/etc/hosts")
            if hosts_file.exists():
                hosts_content = hosts_file.read_text()
                if subdomain not in hosts_content:
                    # Add entry to /etc/hosts
                    new_entry = f"{ip}\t{subdomain}\n"
                    hosts_file.write_text(hosts_content + new_entry)
                    self._log("HOSTS_UPDATED", {"subdomain": subdomain, "ip": ip})
                    if self.console:
                        self.console.print(f"📝 Added {subdomain} -> {ip} to /etc/hosts")
        except Exception as e:
            # Can't write to /etc/hosts, that's okay
            self._log("HOSTS_UPDATE_FAILED", {"subdomain": subdomain, "ip": ip, "error": str(e)})

    async def enumerate_subdomains(self, domain: str) -> List[str]:
        """Optimized subdomain enumeration using FFUF"""
        self._log("SUBDOMAIN_PHASE_START", {"domain": domain})
        phase_start = time.time()
        
        all_subdomains = set()
        
        # Use FFUF for subdomain enumeration
        if self.args.subdomain_wordlist and Path(self.args.subdomain_wordlist).exists():
            # Create appropriate wordlist size based on scan mode
            if hasattr(self.args, 'fast') and self.args.fast:
                # Use first 1000 lines for fast scanning (quick but comprehensive)
                small_wordlist = self.paths["subdomains"] / f"fast_subdomains_{domain}.txt"
                if not small_wordlist.exists():
                    with open(self.args.subdomain_wordlist, 'r') as f:
                        lines = f.readlines()[:1000]
                    with open(small_wordlist, 'w') as f:
                        f.writelines(lines)
                wordlist_path = str(small_wordlist)
            elif hasattr(self.args, 'deep') and self.args.deep:
                # Use full wordlist for deep scanning
                wordlist_path = self.args.subdomain_wordlist
            else:
                # Use first 3000 lines for default scanning (balanced for regular use)
                default_wordlist = self.paths["subdomains"] / f"default_subdomains_{domain}.txt"
                if not default_wordlist.exists():
                    with open(self.args.subdomain_wordlist, 'r') as f:
                        lines = f.readlines()[:3000]
                    with open(default_wordlist, 'w') as f:
                        f.writelines(lines)
                wordlist_path = str(default_wordlist)
            
            subdomains = await self._run_ffuf_subdomain_enum(domain, wordlist_path)
            for subdomain in subdomains:
                if subdomain and subdomain not in all_subdomains:
                    all_subdomains.add(subdomain)
                    self._save_subdomain(subdomain, domain, "ffuf", "wordlist")
        
        # Also try external tools if available (but don't wait forever)
        tasks = []
        
        if self.args.use_subfinder:
            tasks.append(self._run_subfinder_async(domain))
        
        if self.args.use_amass:
            tasks.append(self._run_amass_async(domain))
        
        # Wait for external tools with timeout
        if tasks:
            try:
                results = await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True), 
                    timeout=60  # 1 minute timeout
                )
                
                for result in results:
                    if isinstance(result, list):
                        for subdomain in result:
                            if subdomain and subdomain not in all_subdomains:
                                all_subdomains.add(subdomain)
                                self._save_subdomain(subdomain, domain, "external", "tool")
            except asyncio.TimeoutError:
                self._log("SUBDOMAIN_TOOLS_TIMEOUT", {"domain": domain})
        
        # Add discovered subdomains as seeds (use original scheme only)
        if all_subdomains:
            for subdomain in all_subdomains:
                # Use the original scheme from the main target, not both HTTP/HTTPS
                original_scheme = "http"  # Default to http
                original_port = 80
                
                # Get the original scheme from the first seed
                if self.seed_list:
                    original_scheme = self.seed_list[0].scheme
                    original_port = self.seed_list[0].port
                
                self._add_seed(original_scheme, subdomain, original_port, "subdomain_enum")
        
        phase_time = time.time() - phase_start
        self.phase_times["subdomain_enum"] = phase_time
        self._log("SUBDOMAIN_PHASE_COMPLETE", {"domain": domain, "count": len(all_subdomains), "time": phase_time})
        
        return list(all_subdomains)

    async def _run_subfinder_async(self, domain: str) -> List[str]:
        """Async wrapper for subfinder"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self.executor, self._run_subfinder, domain)
    
    async def _run_wordlist_bruteforce_async(self, domain: str, wordlist_path: str) -> List[str]:
        """Async wrapper for wordlist bruteforce"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self.executor, self._run_wordlist_bruteforce, domain, wordlist_path)

    async def _run_ffuf_subdomain_enum(self, domain: str, wordlist_path: str) -> List[str]:
        """Use FFUF for subdomain enumeration"""
        try:
            # Create output file
            output_file = self.paths["subdomains"] / f"ffuf_subdomains_{domain}.json"
            
            # FFUF command for subdomain enumeration with filtering
            cmd = [
                "ffuf",
                "-w", wordlist_path,
                "-u", f"http://{domain}",
                "-H", f"Host: FUZZ.{domain}",
                "-mc", "200,201,202,204,301,302,307,401,403",
                "-fs", "13560",  # Filter out the default response size (wildcard)
                "-t", "20",
                "-rate", "100",
                "-timeout", "5",
                "-of", "json",
                "-o", str(output_file)
            ]
            
            # Run FFUF with reasonable timeout for subdomain enumeration
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0 and output_file.exists():
                # Parse FFUF results
                with open(output_file, 'r') as f:
                    data = json.load(f)
                
                subdomains = []
                for result_item in data.get('results', []):
                    subdomain = result_item.get('input', {}).get('FUZZ', '')
                    if subdomain:
                        subdomains.append(f"{subdomain}.{domain}")
                
                self._log("FFUF_SUBDOMAIN_SUCCESS", {"domain": domain, "count": len(subdomains)})
                return subdomains
            else:
                self._log("FFUF_SUBDOMAIN_FAILED", {"domain": domain, "error": result.stderr})
                return []
                
        except Exception as e:
            self._log("FFUF_SUBDOMAIN_ERROR", {"domain": domain, "error": str(e)})
            return []

    async def _run_amass_async(self, domain: str) -> List[str]:
        """Async wrapper for amass"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self.executor, self._run_amass, domain)

    async def _run_wordlist_bruteforce_async(self, domain: str, wordlist_path: str) -> List[str]:
        """Async wrapper for wordlist bruteforce"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self.executor, self._run_wordlist_bruteforce, domain, wordlist_path)

    # -----------------------
    # Interactive prompts
    # -----------------------
    async def ask_user_guidance(self, phase: str, context: Dict[str, Any]) -> str:
        """Simplified user guidance - only ask for critical decisions"""
        if not self.interactive_mode:
            return "continue"
        
        # Only ask for guidance on important phases
        if phase == "subdomain_enum" and len(self.subdomains) > 50:
            print(f"\n🔍 Found {len(self.subdomains)} subdomains so far...")
            print("Press Enter to continue, 's' to skip subdomain scanning, or 'q' to quit")
            try:
                choice = input("Choice: ").strip().lower()
                if choice == 's':
                    return "skip"
                elif choice == 'q':
                    self.stop_requested = True
                    return "skip"
            except (EOFError, KeyboardInterrupt):
                pass
        
        return "continue"

    def _show_progress(self):
        """Show current progress summary"""
        if self.console:
            if self.total_jobs > 0:
                progress_pct = min((self.completed_jobs / self.total_jobs) * 100, 100)
                self.console.print(f"📊 {self.current_phase}: {self.completed_jobs}/{self.total_jobs} ({progress_pct:.1f}%) | {len(self.subdomains)} subdomains, {len(self.findings)} findings | 🔍 {self.current_url}")
            else:
                self.console.print(f"📊 {self.current_phase}: {len(self.subdomains)} subdomains, {len(self.findings)} findings | 🔍 {self.current_url}")

    def _write_findings_periodically(self):
        """Write current findings to a simple URL list for easy viewing"""
        if not self.findings:
            return
        
        # Create simple URL list
        url_list_file = self.root / "urls_found.txt"
        with open(url_list_file, "w") as f:
            f.write("# URLs Found by Hawkeye\n")
            f.write(f"# Generated: {now_iso()}\n")
            f.write(f"# Phase: {self.current_phase}\n")
            if self.total_jobs > 0:
                progress_pct = (self.completed_jobs/self.total_jobs*100)
                f.write(f"# Progress: {self.completed_jobs}/{self.total_jobs} ({progress_pct:.1f}%)\n")
            else:
                f.write(f"# Progress: {self.completed_jobs}/{self.total_jobs} (0.0%)\n")
            f.write(f"# Total URLs: {len(self.findings)}\n\n")
            
            # Group by status code
            by_status = defaultdict(list)
            for finding in self.findings:
                by_status[finding.status].append(finding.url)
            
            for status in sorted(by_status.keys()):
                f.write(f"## Status {status}\n")
                for url in sorted(by_status[status]):
                    f.write(f"{url}\n")
                f.write("\n")
        
        # Also write to a simple list
        simple_list_file = self.root / "urls_simple.txt"
        with open(simple_list_file, "w") as f:
            for finding in sorted(self.findings, key=lambda x: x.url):
                f.write(f"{finding.url}\n")
        
        # Generate periodic reports
        self._generate_periodic_reports()
    
    def _generate_periodic_reports(self):
        """Generate reports periodically during scanning"""
        try:
            # Generate HTML report
            html_file = self.root / "report_periodic.html"
            self._generate_html_report()
            
            # Generate competition report
            comp_file = self.root / "competition_report_periodic.md"
            self._generate_competition_report()
            
            self._log("PERIODIC_REPORTS_GENERATED", {"html": str(html_file), "competition": str(comp_file)})
            
        except Exception as e:
            self._log("PERIODIC_REPORTS_ERROR", {"error": str(e)})

    def _ask_for_large_directory(self, url: str, hit_count: int) -> bool:
        """Ask user if they want to scan a large directory"""
        if not self.interactive_mode or hit_count < 50:
            return True
        
        print(f"\n⚠️  Large directory detected: {url}")
        print(f"   Found {hit_count} items. This could take a while.")
        print("   Options:")
        print("   1. Continue scanning (y)")
        print("   2. Skip this directory (n)")
        print("   3. Skip all large directories (a)")
        
        try:
            choice = input("Choice (y/n/a): ").strip().lower()
            if choice == 'a':
                self.interactive_mode = False  # Disable future prompts
                return False
            return choice in ['y', 'yes', '']
        except (EOFError, KeyboardInterrupt):
            return True

    # -----------------------
    # Baseline capture
    # -----------------------
    def _capture_root_baseline(self, seed: Seed):
        url = seed.url
        cmd = ["curl", "-sS", "--max-time", str(self.args.curl_timeout), "-L", "-k", "-i", url]
        for h in (self.args.header or []):
            cmd += ["-H", h]
        if self.args.cookie:
            cmd += ["-H", f"Cookie: {self.args.cookie}"]
        try:
            p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if p.returncode != 0:
                self._log("BASELINE_ERROR", {"seed": seed.url, "rc": p.returncode, "err": p.stderr.decode(errors="ignore")})
                return
            raw = p.stdout
            parts = raw.split(b"\r\n\r\n")
            if len(parts) < 2:
                parts = raw.split(b"\n\n")
            header_bytes = parts[-2] if len(parts) >= 2 else b""
            body_bytes = parts[-1] if len(parts) >= 2 else b""
            size = len(body_bytes)
            b_hash = sha256_hex(body_bytes)
            self.baseline_by_host[f"{seed.host}:{seed.port}"] = {"size": size, "hash": b_hash}
            base_dir = self.paths["raw"] / "baseline"
            base_dir.mkdir(parents=True, exist_ok=True)
            safe_write_bytes(base_dir / f"{seed.host}_{seed.port}__raw.bin", raw)
            self._log("BASELINE_CAPTURE", {"seed": seed.url, "size": size, "hash": b_hash})
        except Exception as e:
            self._log("BASELINE_EXCEPTION", {"seed": seed.url, "err": str(e)})

    # -----------------------
    # FFUF runner
    # -----------------------
    def _build_ffuf_cmd(self, base_url: str, wordlist: str, use_ext: bool, seed: Seed, depth: int, out_json: Path, out_log: Path) -> List[str]:
        target = base_url.rstrip("/") + "/FUZZ"
        cmd = ["ffuf", "-w", wordlist, "-u", target, "-mc", self.args.codes, "-t", str(self.args.ffuf_threads), "-rate", str(self.args.rate), "-timeout", str(self.args.ffuf_timeout), "-of", "json", "-o", str(out_json), "-ic"]
        for h in (self.args.header or []):
            cmd += ["-H", h]
        if self.args.cookie:
            cmd += ["-H", f"Cookie: {self.args.cookie}"]
        bh = self.baseline_by_host.get(f"{seed.host}:{seed.port}")
        if bh:
            cmd += ["-fs", str(bh["size"])]
        if use_ext:
            exts = set(self.args.exts.split(",")) if (self.args.exts and self.args.exts.strip()) else set()
            exts.update(self.ext_by_host.get(seed.host, set()))
            exts = sorted(e for e in exts if e)
            if exts:
                cmd += ["-e", ",".join("." + e.lstrip(".") for e in exts)]
        return cmd

    def _run_ffuf_blocking(self, cmd: List[str], out_log: Path) -> Tuple[int, List[str]]:
        hits_lines: List[str] = []
        try:
            with open(out_log, "w", encoding="utf-8") as lf:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1, text=True)
                assert proc.stdout
                for raw in proc.stdout:
                    line = ANSI_RE.sub("", raw).rstrip("\r\n")
                    lf.write(line + "\n"); lf.flush()
                    if "Status:" in line or ":: Progress:" in line:
                        hits_lines.append(line)
                proc.wait()
                return proc.returncode, hits_lines
        except Exception as e:
            return 1, [f"FFUF_EXCEPTION: {e}"]

    def _parse_ffuf_json(self, json_path: Path) -> List[Tuple[str,int]]:
        if not json_path.exists():
            return []
        try:
            raw = json.loads(json_path.read_text())
            results = raw.get("results", [])
            hits = []
            for r in results:
                status = int(r.get("status", 0)) if r.get("status") else 0
                path = (r.get("input") or {}).get("FUZZ", "")
                if not path:
                    url = r.get("url") or ""
                    path = url.rsplit("/", 1)[-1] if "/" in url else url
                if not path or " " in path or "#" in path:
                    continue
                hits.append((path.strip(), status))
            return hits
        except Exception:
            self._log("FFUF_PARSE_ERROR", {"file": str(json_path), "err": traceback.format_exc()})
            return []
    # -----------------------
    # Job orchestrators
    # -----------------------
    async def ffuf_dispatcher(self):
        loop = asyncio.get_event_loop()
        while not self.stop_requested:
            try:
                job = await asyncio.wait_for(self.ffuf_job_q.get(), timeout=1.0)
            except asyncio.TimeoutError:
                if self.ffuf_job_q.empty():
                    await asyncio.sleep(0.2)
                    continue
                else:
                    continue
            seed_scheme = job["seed_scheme"]
            seed_host = job["seed_host"]
            seed_port = job["seed_port"]
            base_url = job["base_url"]
            depth = job["depth"]
            phase = job["phase"]
            wordlist = job["wordlist"]
            use_ext = job.get("use_ext", False)
            seed_key = (seed_scheme, seed_port, seed_host)
            seed = self.seeds.get(seed_key)
            if not seed:
                seed = self._add_seed(seed_scheme, seed_host, seed_port, "ffuf_resume")
            host_key = f"{seed_host}:{seed_port}"
            
            # Update current URL being fuzzed
            self.current_url = f"{base_url} ({phase})"
            if host_key not in self.host_semaphores:
                self.host_semaphores[host_key] = asyncio.Semaphore(self.args.per_host_concurrency)
            sem = self.host_semaphores[host_key]
            await sem.acquire()
            await self.global_sem.acquire()
            out_json = self.paths["ffuf"] / f"ffuf_{seed_host}_{seed_port}_{depth}_{phase}.json"
            out_log = self.paths["ffuf"] / f"ffuf_{seed_host}_{seed_port}_{depth}_{phase}.log"
            cmd = self._build_ffuf_cmd(base_url, wordlist, use_ext, seed, depth, out_json, out_log)
            self._log("FFUF_START", {"cmd": sanitized_shell(cmd), "seed": seed.url, "base": base_url, "phase": phase, "depth": depth})
            fut = loop.run_in_executor(self.executor, self._run_ffuf_blocking, cmd, out_log)
            try:
                rc, stream_lines = await fut
                ffuf_hits = self._parse_ffuf_json(out_json)
                immediate_hits = []
                for ln in stream_lines:
                    m = HIT_RE.search(ln)
                    if m:
                        seg = m.group("path").strip()
                        st = int(m.group("code"))
                        immediate_hits.append((seg, st))
                hits = []
                seen = set()
                for p, s in immediate_hits + ffuf_hits:
                    if p in seen: continue
                    seen.add(p)
                    hits.append((p, s))
                self._log("FFUF_DONE", {"seed": seed.url, "base": base_url, "phase": phase, "hits": len(hits)})

                # Process hits and prevent duplicates
                for seg, sc in hits:
                    if not seg or "#" in seg or " " in seg:
                        continue
                    full_url = base_url.rstrip("/") + "/" + seg.lstrip("/")
                    
                    # Check if URL was already processed
                    if full_url in self.visited_urls:
                        continue
                    self.visited_urls.add(full_url)
                    
                    # enqueue every hit for capture
                    await self.capture_q.put({"seed": seed, "url": full_url, "depth": depth})

                    # Check for large directories and ask user
                    if len(hits) > 50:
                        if not self._ask_for_large_directory(base_url, len(hits)):
                            continue

                    try_path = "/" + seg.strip("/")
                    if depth < self.args.max_depth and sc in ENQUEUE_CODES and is_dir_like(try_path):
                        vid = f"{seed.host}:{seed.port}{try_path}{depth+1}"
                        if vid not in self.visited_bases:
                            self.visited_bases.add(vid)
                            new_base = base_url.rstrip("/") + (try_path if try_path.endswith("/") else try_path + "/")
                            next_job = {
                                "seed_scheme": seed.scheme,
                                "seed_host": seed.host,
                                "seed_port": seed.port,
                                "base_url": new_base,
                                "depth": depth + 1,
                                "phase": phase,
                                "wordlist": wordlist,
                                "use_ext": use_ext,
                            }
                            await self.ffuf_job_q.put(next_job)
                            try:
                                self._enqueue_ffuf_resume(new_base, seed, depth + 1, phase, wordlist, use_ext)
                            except Exception:
                                pass
                
                # Update progress (only when FFUF job actually completes)
                if time.time() - self.last_progress_update > 2:  # Update every 2 seconds
                    self._show_progress()
                    self._write_findings_periodically()
                    self.last_progress_update = time.time()

            except Exception as e:
                self._log("FFUF_EXCEPTION", {"err": str(e), "cmd": sanitized_shell(cmd)})
            finally:
                sem.release()
                # Mark this FFUF job as completed
                self.completed_jobs += 1
                self.ffuf_job_q.task_done()

    # -----------------------
    # run_phases, summary, run()
    # -----------------------
    async def run_phases(self):
        """Optimized phase execution"""
        if self.console:
            self.console.print("[bold green]🚀 Starting Hawkeye Scan[/bold green]")
        
        # Phase 0: Subdomain enumeration (if enabled)
        if self.args.enable_subdomain_enum:
            await self._run_subdomain_phase()
        
        # Phase 1: Quick wins (always run)
        await self._run_quick_wins_phase()
        
        # Phase 2: Deep scanning (only if not in fast mode)
        if not self.args.fast:
            await self._run_deep_scanning_phase()
        
        if self.console:
            self.console.print("[bold green]✅ All phases complete![/bold green]")

    async def _run_subdomain_phase(self):
        """Phase 0: Optimized subdomain enumeration"""
        phase_start = time.time()
        self._log("PHASE_START", {"phase": "subdomain_enum"})
        
        if self.console:
            self.console.print("[bold blue]🔍 Phase 0: Subdomain Enumeration[/bold blue]")
        
        # Get unique domains from seeds
        domains = set()
        for seed in self.seed_list:
            domains.add(seed.host)
        
        # Process domains in parallel
        tasks = []
        for domain in domains:
            if self.stop_requested:
                break
            tasks.append(self.enumerate_subdomains(domain))
        
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            total_subdomains = sum(len(result) if isinstance(result, list) else 0 for result in results)
            
            if self.console:
                self.console.print(f"[green]✅ Found {total_subdomains} total subdomains[/green]")
        
        self.phase_times["subdomain_enum"] = time.time() - phase_start
        self._log("PHASE_COMPLETE", {"phase": "subdomain_enum", "time": self.phase_times["subdomain_enum"]})

    async def _run_quick_wins_phase(self):
        """Phase 1: Optimized quick wins scanning"""
        phase_start = time.time()
        self._log("PHASE_START", {"phase": "quick_wins"})
        self.current_phase = "Quick Wins"
        
        if self.console:
            self.console.print("[bold yellow]⚡ Phase 1: Quick Wins[/bold yellow]")
        
        # Queue all quick win jobs at once
        jobs_queued = 0
        for s in list(self.seed_list):
            if self.stop_requested:
                break
            
            # Capture baseline
            self._capture_root_baseline(s)
            
            # Queue quick scan jobs
            base = s.url.rstrip("/")
            for phase_name, wordlist, use_ext in [("quick", str(self.args.quick_wordlist), False)]:
                vid = f"{s.scheme}://{s.host}:{s.port}{phase_name}"
                if vid in self.visited_bases:
                    continue
                self.visited_bases.add(vid)
                
                job = {
                    "seed_scheme": s.scheme, 
                    "seed_host": s.host, 
                    "seed_port": s.port, 
                    "base_url": base + "/", 
                    "depth": 0, 
                    "phase": phase_name, 
                    "wordlist": wordlist, 
                    "use_ext": use_ext
                }
                await self.ffuf_job_q.put(job)
                jobs_queued += 1
        
        # Set up progress tracking
        self.total_jobs = jobs_queued
        self.completed_jobs = 0
        
        if self.console:
            self.console.print(f"[blue]Queued {jobs_queued} quick scan jobs[/blue]")
        
        # Wait for completion
        if not self.args.background:
            # Wait for all ffuf jobs to complete
            while not self.ffuf_job_q.empty() and not self.stop_requested:
                await asyncio.sleep(0.5)
            # Wait for all capture jobs to complete
            while not self.capture_q.empty() and not self.stop_requested:
                await asyncio.sleep(0.5)
        else:
            await asyncio.sleep(self.args.background_delay)
        
        self.phase_times["quick_wins"] = time.time() - phase_start
        self._log("PHASE_COMPLETE", {"phase": "quick_wins", "time": self.phase_times["quick_wins"]})

    async def _run_deep_scanning_phase(self):
        """Phase 2: Optimized deep scanning with subdomain enumeration"""
        phase_start = time.time()
        self._log("PHASE_START", {"phase": "deep_scanning"})
        self.current_phase = "Deep Scanning"
        
        if self.console:
            self.console.print("[bold red]🔍 Phase 2: Deep Scanning[/bold red]")
        
        # First, run comprehensive subdomain enumeration for deep scanning
        if self.args.enable_subdomain_enum:
            if self.console:
                self.console.print("[blue]🔍 Deep subdomain enumeration...[/blue]")
            
            # Get unique domains from current seeds
            domains = set()
            for s in self.seed_list:
                domain_parts = s.host.split('.')
                if len(domain_parts) >= 2:
                    root_domain = '.'.join(domain_parts[-2:])
                    domains.add(root_domain)
            
            # Run subdomain enumeration for each domain
            for domain in domains:
                if self.stop_requested:
                    break
                new_subdomains = await self.enumerate_subdomains(domain)
                if self.console and new_subdomains:
                    self.console.print(f"[green]Found {len(new_subdomains)} new subdomains for {domain}[/green]")
        
        # Queue all deep scan jobs (including newly discovered subdomains)
        jobs_queued = 0
        for s in list(self.seed_list):
            if self.stop_requested:
                break
            
            base = s.url.rstrip("/")
            for phase_name, wordlist, use_ext in [("full", str(self.args.full_wordlist), False)]:
                vid = f"{s.scheme}://{s.host}:{s.port}{phase_name}"
                if vid in self.visited_bases:
                    continue
                self.visited_bases.add(vid)
                
                job = {
                    "seed_scheme": s.scheme, 
                    "seed_host": s.host, 
                    "seed_port": s.port, 
                    "base_url": base + "/", 
                    "depth": 0, 
                    "phase": phase_name, 
                    "wordlist": wordlist, 
                    "use_ext": use_ext
                }
                await self.ffuf_job_q.put(job)
                jobs_queued += 1
        
        # Set up progress tracking for deep scanning
        self.total_jobs = jobs_queued
        self.completed_jobs = 0
        
        if self.console:
            self.console.print(f"[blue]Queued {jobs_queued} deep scan jobs[/blue]")
        
        # Wait for completion
        if not self.args.background:
            # Wait for all ffuf jobs to complete
            while not self.ffuf_job_q.empty() and not self.stop_requested:
                await asyncio.sleep(0.5)
            # Wait for all capture jobs to complete
            while not self.capture_q.empty() and not self.stop_requested:
                await asyncio.sleep(0.5)
        else:
            await asyncio.sleep(self.args.background_delay)
        
        self.phase_times["deep_scanning"] = time.time() - phase_start
        self._log("PHASE_COMPLETE", {"phase": "deep_scanning", "time": self.phase_times["deep_scanning"]})

    # -----------------------
    # Capture and screenshot workers
    # -----------------------
    async def capture_worker(self):
        """Worker to capture HTTP responses and metadata"""
        while not self.stop_requested:
            try:
                item = await asyncio.wait_for(self.capture_q.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            
            seed = item["seed"]
            url = item["url"]
            depth = item["depth"]
            
            try:
                # Capture HTTP response
                cmd = ["curl", "-sS", "--max-time", str(self.args.curl_timeout), "-L", "-k", "-i", url]
                for h in (self.args.header or []):
                    cmd += ["-H", h]
                if self.args.cookie:
                    cmd += ["-H", f"Cookie: {self.args.cookie}"]
                
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    response = result.stdout
                    parts = response.split("\r\n\r\n")
                    if len(parts) < 2:
                        parts = response.split("\n\n")
                    
                    headers = parts[-2] if len(parts) >= 2 else ""
                    body = parts[-1] if len(parts) >= 2 else ""
                    
                    # Extract status code
                    status_match = re.search(r"HTTP/\d\.\d\s+(\d+)", headers)
                    status = int(status_match.group(1)) if status_match else 0
                    
                    # Calculate priority
                    priority = self._calculate_priority(url, status, body)
                    
                    # Create finding record
                    finding_id = len(self.findings) + 1
                    slug = slugify(url)
                    
                    # Save artifacts
                    headers_file = self.paths["headers"] / f"{finding_id:04d}_{slug}.txt"
                    body_file = self.paths["bodies"] / f"{finding_id:04d}_{slug}.html"
                    curl_file = self.paths["curl"] / f"{finding_id:04d}_{slug}.txt"
                    
                    headers_file.write_text(headers)
                    body_file.write_text(body)
                    curl_file.write_text(sanitized_shell(cmd))
                    
                    # Create finding record
                    finding = FindingRecord(
                        id=finding_id,
                        seed_id=seed.id,
                        url=url,
                        status=status,
                        length=len(body),
                        headers_file=str(headers_file),
                        body_file=str(body_file),
                        curl_file=str(curl_file),
                        screenshot=None,
                        meta=FindingMeta(),
                        depth=depth,
                        phase="unknown",
                        priority=priority
                    )
                    
                    self.findings.append(finding)
                    
                    # Show URL live in terminal
                    if self.console:
                        status_emoji = "🟢" if status == 200 else "🟡" if status in [301, 302] else "🔴" if status == 403 else "⚪"
                        self.console.print(f"{status_emoji} {url} ({status})")
                    
                    # Queue for screenshot if needed
                    if self.args.screenshot_phase == "all" or (self.args.screenshot_phase == "hits_only" and status in [200, 301, 302, 403, 404]):
                        await self.screenshot_q.put({"finding": finding, "url": url})
                    
                    self._log("FINDING_CAPTURED", {
                        "url": url, 
                        "status": status, 
                        "priority": priority,
                        "length": len(body)
                    })
                
            except Exception as e:
                self._log("CAPTURE_ERROR", {"url": url, "error": str(e)})
            finally:
                self.capture_q.task_done()

    async def screenshot_worker(self):
        """Worker to take screenshots of web pages"""
        while not self.stop_requested:
            try:
                item = await asyncio.wait_for(self.screenshot_q.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            
            finding = item["finding"]
            url = item["url"]
            
            try:
                if self.args.screenshot_engine == "gowitness":
                    screenshot_file = self.paths["shots"] / f"{finding.id:04d}_{slugify(url)}.png"
                    cmd = ["gowitness", "single", "--url", url, "--destination", str(screenshot_file)]
                    result = subprocess.run(cmd, capture_output=True, timeout=self.args.screenshot_timeout)
                    
                    if result.returncode == 0 and screenshot_file.exists():
                        finding.screenshot = str(screenshot_file)
                        self._log("SCREENSHOT_TAKEN", {"url": url, "file": str(screenshot_file)})
                    else:
                        self._log("SCREENSHOT_FAILED", {"url": url, "error": result.stderr.decode()})
                elif self.args.screenshot_engine == "playwright":
                    await self._take_screenshot_playwright(url, finding)
                elif self.args.screenshot_engine == "wkhtmltopdf":
                    await self._take_screenshot_wkhtmltopdf(url, finding)
                
            except Exception as e:
                self._log("SCREENSHOT_ERROR", {"url": url, "error": str(e)})
            finally:
                self.screenshot_q.task_done()

    async def _take_screenshot_playwright(self, url: str, finding: FindingRecord):
        """Take screenshot using playwright"""
        try:
            from playwright.async_api import async_playwright
            
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                await page.goto(url, timeout=self.args.screenshot_timeout * 1000)
                screenshot_file = self.paths["shots"] / f"{finding.id:04d}_{slugify(url)}.png"
                await page.screenshot(path=str(screenshot_file))
                await browser.close()
                
                if screenshot_file.exists():
                    finding.screenshot = str(screenshot_file)
                    self._log("SCREENSHOT_TAKEN", {"url": url, "file": str(screenshot_file)})
        except ImportError:
            self._log("PLAYWRIGHT_NOT_AVAILABLE", {"url": url})
        except Exception as e:
            self._log("PLAYWRIGHT_ERROR", {"url": url, "error": str(e)})

    async def _take_screenshot_wkhtmltopdf(self, url: str, finding: FindingRecord):
        """Take screenshot using wkhtmltopdf"""
        try:
            screenshot_file = self.paths["shots"] / f"{finding.id:04d}_{slugify(url)}.png"
            cmd = ["wkhtmltoimage", "--format", "png", "--width", "1920", "--height", "1080", url, str(screenshot_file)]
            result = subprocess.run(cmd, capture_output=True, timeout=self.args.screenshot_timeout)
            
            if result.returncode == 0 and screenshot_file.exists():
                finding.screenshot = str(screenshot_file)
                self._log("SCREENSHOT_TAKEN", {"url": url, "file": str(screenshot_file)})
            else:
                self._log("WKHTMLTOPDF_FAILED", {"url": url, "error": result.stderr.decode()})
        except FileNotFoundError:
            self._log("WKHTMLTOPDF_NOT_AVAILABLE", {"url": url})
            # Fallback to simple curl-based capture
            await self._take_screenshot_curl(url, finding)
        except Exception as e:
            self._log("WKHTMLTOPDF_ERROR", {"url": url, "error": str(e)})

    async def _take_screenshot_curl(self, url: str, finding: FindingRecord):
        """Fallback screenshot using curl to capture HTML and save as text"""
        try:
            screenshot_file = self.paths["shots"] / f"{finding.id:04d}_{slugify(url)}.html"
            cmd = ["curl", "-s", "-L", "--max-time", str(self.args.screenshot_timeout), url]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                with open(screenshot_file, "w", encoding="utf-8") as f:
                    f.write(f"<!-- Screenshot of {url} -->\n")
                    f.write(f"<!-- Captured at {now_iso()} -->\n")
                    f.write(result.stdout)
                finding.screenshot = str(screenshot_file)
                self._log("SCREENSHOT_TAKEN", {"url": url, "file": str(screenshot_file), "method": "curl"})
            else:
                self._log("CURL_SCREENSHOT_FAILED", {"url": url, "error": result.stderr})
        except Exception as e:
            self._log("CURL_SCREENSHOT_ERROR", {"url": url, "error": str(e)})

    def _calculate_priority(self, url: str, status: int, body: str) -> int:
        """Calculate priority score for a finding"""
        priority = 0
        
        # High priority indicators
        high_priority_keywords = [
            'admin', 'login', 'dashboard', 'panel', 'manage', 'control',
            'api', 'upload', 'file', 'backup', 'config', 'test', 'dev',
            'phpmyadmin', 'wp-admin', 'administrator', 'root'
        ]
        
        url_lower = url.lower()
        body_lower = body.lower()
        
        # Check for high priority keywords
        for keyword in high_priority_keywords:
            if keyword in url_lower:
                priority += 2
                break
        
        # Status code priority
        if status == 200:
            priority += 1
        elif status in [301, 302]:
            priority += 1
        elif status == 403:
            priority += 2  # Forbidden often indicates interesting content
        elif status == 401:
            priority += 2  # Authentication required
        
        # Check for interesting content in body
        interesting_content = [
            'password', 'username', 'login', 'error', 'debug', 'exception',
            'database', 'sql', 'mysql', 'postgres', 'oracle'
        ]
        
        for content in interesting_content:
            if content in body_lower:
                priority += 1
                break
        
        # Cap at 3 (high priority)
        return min(priority, 3)

    def write_summary(self):
        elapsed = int(time.time() - self.start_ts)
        competition_elapsed = int(time.time() - self.competition_start)
        
        lines = [
            f"HAWKEYE v2.0 — Super Fast CPTC Scanner",
            f"Scan started: {self.run_id}",
            f"Total elapsed: {elapsed}s",
            f"Seeds scanned: {len(self.seed_list)}",
            f"Subdomains found: {len(self.subdomains)}",
            f"Web findings: {len(self.findings)}",
            f"Results: {self.root}",
            "",
            "Phase timings:"
        ]
        
        for phase, time_taken in self.phase_times.items():
            lines.append(f"  {phase}: {time_taken:.1f}s")
        
        lines.extend([
            "",
            "Top hosts (by findings):"
        ])
        
        host_count = defaultdict(int)
        for f in self.findings:
            host = url_parts(f.url)[1]
            host_count[host] += 1
        top = sorted(host_count.items(), key=lambda x: x[1], reverse=True)[:10]
        for h,c in top:
            lines.append(f"  {h}: {c}")
        
        lines.extend([
            "",
            "Subdomain breakdown:"
        ])
        
        tool_count = defaultdict(int)
        for sub in self.subdomains:
            tool_count[sub.tool] += 1
        for tool, count in tool_count.items():
            lines.append(f"  {tool}: {count}")
        
        self.summary_txt.write_text("\n".join(lines))
        self._log("RUN_SUMMARY", {
            "elapsed_sec": elapsed, 
            "competition_sec": competition_elapsed,
            "seeds": len(self.seed_list), 
            "subdomains": len(self.subdomains),
            "findings": len(self.findings),
            "phase_times": self.phase_times
        })
        
        # Generate detailed reports
        self._generate_detailed_reports()

    def _generate_detailed_reports(self):
        """Generate detailed HTML and JSON reports for findings"""
        self._generate_html_report()
        self._generate_json_report()
        self._generate_competition_report()

    def _generate_html_report(self):
        """Generate HTML report for easy viewing"""
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Hawkeye v2.0 - CPTC Competition Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
        .finding {{ margin: 10px 0; padding: 10px; background: #f8f9fa; border-left: 4px solid #007bff; }}
        .high-priority {{ border-left-color: #dc3545; }}
        .medium-priority {{ border-left-color: #ffc107; }}
        .subdomain {{ margin: 5px 0; padding: 5px; background: #e9ecef; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Hawkeye v2.0 - Super Fast CPTC Scanner</h1>
        <p>Scan started: {self.run_id}</p>
        <p>Generated: {now_iso()}</p>
    </div>
    
    <div class="section">
        <h2>Executive Summary</h2>
        <p><strong>Total Subdomains Found:</strong> {len(self.subdomains)}</p>
        <p><strong>Total Web Findings:</strong> {len(self.findings)}</p>
        <p><strong>Seeds Scanned:</strong> {len(self.seed_list)}</p>
        <p><strong>Competition Time:</strong> {int(time.time() - self.competition_start)}s</p>
    </div>
    
    <div class="section">
        <h2>Subdomain Discovery</h2>
        <table>
            <tr><th>Subdomain</th><th>IP</th><th>Tool</th><th>Timestamp</th></tr>
"""
        
        for sub in self.subdomains:
            html_content += f"""
            <tr>
                <td>{sub.subdomain}</td>
                <td>{sub.ip or 'N/A'}</td>
                <td>{sub.tool}</td>
                <td>{sub.timestamp}</td>
            </tr>
"""
        
        html_content += """
        </table>
    </div>
    
    <div class="section">
        <h2>Web Findings</h2>
"""
        
        # Group findings by priority
        high_priority = [f for f in self.findings if f.priority >= 2]
        medium_priority = [f for f in self.findings if f.priority == 1]
        low_priority = [f for f in self.findings if f.priority == 0]
        
        if high_priority:
            html_content += "<h3>High Priority Findings</h3>"
            for finding in high_priority:
                html_content += f"""
                <div class="finding high-priority">
                    <strong>{finding.url}</strong> [{finding.status}]<br>
                    <small>Phase: {finding.phase} | Length: {finding.length} | Depth: {finding.depth}</small>
                </div>
"""
        
        if medium_priority:
            html_content += "<h3>Medium Priority Findings</h3>"
            for finding in medium_priority:
                html_content += f"""
                <div class="finding medium-priority">
                    <strong>{finding.url}</strong> [{finding.status}]<br>
                    <small>Phase: {finding.phase} | Length: {finding.length} | Depth: {finding.depth}</small>
                </div>
"""
        
        if low_priority:
            html_content += "<h3>Low Priority Findings</h3>"
            for finding in low_priority:
                html_content += f"""
                <div class="finding">
                    <strong>{finding.url}</strong> [{finding.status}]<br>
                    <small>Phase: {finding.phase} | Length: {finding.length} | Depth: {finding.depth}</small>
                </div>
"""
        
        html_content += """
    </div>
    
    <div class="section">
        <h2>Phase Timings</h2>
        <table>
            <tr><th>Phase</th><th>Time (seconds)</th></tr>
"""
        
        for phase, time_taken in self.phase_times.items():
            html_content += f"<tr><td>{phase}</td><td>{time_taken:.1f}</td></tr>"
        
        html_content += """
        </table>
    </div>
</body>
</html>
"""
        
        report_file = self.paths["reports"] / "hawkeye_report.html"
        report_file.write_text(html_content)
        self._log("HTML_REPORT_GENERATED", {"file": str(report_file)})

    def _generate_json_report(self):
        """Generate JSON report for programmatic analysis"""
        report_data = {
            "run_id": self.run_id,
            "timestamp": now_iso(),
            "competition_time": int(time.time() - self.competition_start),
            "summary": {
                "subdomains_found": len(self.subdomains),
                "web_findings": len(self.findings),
                "seeds_scanned": len(self.seed_list)
            },
            "phase_times": self.phase_times,
            "subdomains": [asdict(sub) for sub in self.subdomains],
            "findings": [asdict(finding) for finding in self.findings],
            "seeds": [asdict(seed) for seed in self.seed_list]
        }
        
        report_file = self.paths["reports"] / "hawkeye_report.json"
        report_file.write_text(json.dumps(report_data, indent=2, default=str))
        self._log("JSON_REPORT_GENERATED", {"file": str(report_file)})

    def _generate_competition_report(self):
        """Generate CPTC-specific competition report"""
        competition_content = f"""
# HAWKEYE v2.0 - Super Fast CPTC Scanner

## Scan Information
- **Scan started:** {self.run_id}
- **Generated:** {now_iso()}
- **Total time:** {int(time.time() - self.competition_start)}s

## Executive Summary
- **Subdomains Discovered:** {len(self.subdomains)}
- **Web Endpoints Found:** {len(self.findings)}
- **Targets Scanned:** {len(self.seed_list)}

## High-Value Findings
"""
        
        # Categorize findings by potential value
        admin_findings = [f for f in self.findings if any(keyword in f.url.lower() for keyword in ['admin', 'login', 'dashboard', 'panel'])]
        api_findings = [f for f in self.findings if 'api' in f.url.lower()]
        upload_findings = [f for f in self.findings if any(keyword in f.url.lower() for keyword in ['upload', 'file', 'attach'])]
        
        if admin_findings:
            competition_content += "\n### Administrative Interfaces\n"
            for finding in admin_findings:
                competition_content += f"- {finding.url} [{finding.status}]\n"
        
        if api_findings:
            competition_content += "\n### API Endpoints\n"
            for finding in api_findings:
                competition_content += f"- {finding.url} [{finding.status}]\n"
        
        if upload_findings:
            competition_content += "\n### File Upload Areas\n"
            for finding in upload_findings:
                competition_content += f"- {finding.url} [{finding.status}]\n"
        
        competition_content += f"""
## Subdomain Discovery Results
"""
        
        tool_breakdown = {}
        for sub in self.subdomains:
            tool_breakdown[sub.tool] = tool_breakdown.get(sub.tool, 0) + 1
        
        for tool, count in tool_breakdown.items():
            competition_content += f"- **{tool}:** {count} subdomains\n"
        
        competition_content += f"""
## Phase Performance
"""
        
        for phase, time_taken in self.phase_times.items():
            competition_content += f"- **{phase}:** {time_taken:.1f}s\n"
        
        competition_content += f"""
## Next Steps for Competition
1. **Immediate Actions:**
   - Review high-priority findings for quick wins
   - Test administrative interfaces for authentication bypass
   - Examine API endpoints for parameter manipulation

2. **Deep Analysis:**
   - Perform detailed vulnerability assessment on promising endpoints
   - Test for common web vulnerabilities (SQLi, XSS, etc.)
   - Analyze file upload functionality for exploitation

3. **Documentation:**
   - Document all findings with screenshots
   - Prepare exploitation steps for high-value targets
   - Create timeline of discovery for competition report
"""
        
        report_file = self.paths["reports"] / "competition_report.md"
        report_file.write_text(competition_content)
        self._log("COMPETITION_REPORT_GENERATED", {"file": str(report_file)})

    async def run(self):
        workers = []
        # Start live UI here ✅
        if self.live:
            self.live.start()
            self.live.console.print(f"[+] Hawkeye {self.run_id} started with {len(self.seed_list)} seed(s)…")

        ffuf_task = asyncio.create_task(self.ffuf_dispatcher())
        workers.append(ffuf_task)
        for _ in range(max(1, self.args.capture_workers)):
            workers.append(asyncio.create_task(self.capture_worker()))
        workers.append(asyncio.create_task(self.screenshot_worker()))
        phase_task = asyncio.create_task(self.run_phases())
        workers.append(phase_task)

        try:
            # Wait for phase task to complete
            await phase_task
            
            # Wait for all queues to empty
            await self.ffuf_job_q.join()
            await self.capture_q.join()
            await self.screenshot_q.join()
            
            # Cancel remaining workers
            for w in workers:
                if not w.done():
                    w.cancel()
            
            if self.live:
                self.live.stop()
            self.write_summary()
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self._log("RUN_EXCEPTION", {"err": str(e), "trace": traceback.format_exc()})

# ----------------------------
# CLI parsing & entrypoint
# ----------------------------
def detect_default_wordlist() -> Path:
    candidates = [
        "directories.txt",  # Our comprehensive wordlist
        "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
        "/opt/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt",
    ]
    for p in candidates:
        pp = Path(p)
        if pp.exists():
            return pp
    fallback = Path(__file__).with_name("hawkeye-mini.txt")
    if not fallback.exists():
        fallback.write_text("\n".join(["admin","login","images","img","css","js","api","uploads","dashboard","assets","wp-admin","wp-login.php"]))
    return fallback

def count_lines(path: Path) -> int:
    try:
        with path.open("rb") as f:
            c = 0
            last_nl = True
            while True:
                chunk = f.read(1<<15)
                if not chunk: break
                last_nl = chunk.endswith(b"\n")
                c += chunk.count(b"\n")
            if c == 0 and not last_nl:
                return 1
            if not last_nl:
                c += 1
            return c
    except Exception:
        return 0

def crop_wordlist(src: Path, dst: Path, max_lines: int) -> int:
    if max_lines <= 0:
        dst.write_bytes(b"")
        return 0
    written = 0
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        for ln in fin:
            fout.write(ln)
            written += 1
            if written >= max_lines:
                break
    return written

def build_parser():
    p = argparse.ArgumentParser(
        prog="hawkeye", 
        description="HAWKEYE v2.0 — Super Fast CPTC Competition Web Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan with subdomain enumeration
  python3 hawkeye.py http://example.com
  
  # Fast scan (quick wins only)
  python3 hawkeye.py https://example.com --fast
  
  # Scan specific port
  python3 hawkeye.py http://example.com:8080
  
  # Deep scan with custom wordlist
  python3 hawkeye.py http://example.com --wordlist /path/to/wordlist.txt
  
  # Resume from crash
  python3 hawkeye.py --resume ./results/2025-01-06_14-30-15/
  
  # Background mode (continuous scanning)
  python3 hawkeye.py http://example.com --background
        """
    )
    
    # Main target (positional argument)
    p.add_argument("target", nargs="?", help="Target URL (e.g., http://example.com or https://example.com:8080)")
    
    # Essential options
    p.add_argument("--fast", action="store_true", help="Quick scan only (skip deep scanning)")
    p.add_argument("--deep", action="store_true", help="Deep scan with full wordlist")
    p.add_argument("--background", action="store_true", help="Background mode for continuous scanning")
    p.add_argument("--resume", help="Resume from previous scan (provide results folder path)")
    
    # Subdomain options
    p.add_argument("--no-subdomains", action="store_true", help="Skip subdomain enumeration")
    p.add_argument("--subfinder-only", action="store_true", help="Use only subfinder (faster)")
    
    # Wordlist options
    p.add_argument("--wordlist", help="Custom wordlist for directory scanning")
    p.add_argument("--subdomain-wordlist", help="Custom subdomain wordlist")
    
    # Performance options
    p.add_argument("--threads", type=int, default=50, help="Number of threads (default: 50)")
    p.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    
    # Output options
    p.add_argument("--output", "-o", help="Output directory (default: ./results)")
    p.add_argument("--no-screenshots", action="store_true", help="Skip screenshot capture")
    p.add_argument("--screenshot-engine", choices=["gowitness", "playwright", "wkhtmltopdf"], default="wkhtmltopdf", help="Screenshot tool to use")
    
    # Advanced options (hidden from help)
    p.add_argument("--ports", default="80,443,8080,8443", help=argparse.SUPPRESS)
    p.add_argument("--max-depth", type=int, default=2, help=argparse.SUPPRESS)
    p.add_argument("--codes", default=DEFAULT_CODES, help=argparse.SUPPRESS)
    p.add_argument("--header", action="append", help=argparse.SUPPRESS)
    p.add_argument("--cookie", help=argparse.SUPPRESS)
    p.add_argument("--basic-auth", help=argparse.SUPPRESS)
    
    return p

def main():
    parser = build_parser()
    args = parser.parse_args()
    
    # Handle resume mode
    if args.resume:
        resume_path = Path(args.resume)
        if not resume_path.exists():
            print(f"❌ Resume path does not exist: {resume_path}")
            sys.exit(1)
        print(f"🔄 Resuming scan from: {resume_path}")
        # Extract run_id from resume path
        args.resume_run_id = resume_path.name
        args.results_root = str(resume_path.parent)
        args.target = None  # Will be loaded from resume
    else:
        # Validate target
        if not args.target:
            print("❌ Please provide a target domain or host")
            print("Usage: python3 hawkeye.py example.com")
            sys.exit(1)
        
        # Create results directory with timestamp
        args.results_root = args.output or "./results"
        args.resume_run_id = None
    
    # Setup wordlists with smart defaults
    setup_wordlists(args)
    
    # Convert simple args to internal format
    convert_args(args)
    
    # Create and run scanner
    hk = Hawkeye(args)
    
    if not args.resume:
        hk.build_initial_seeds()
        print(f"🎯 Target: {args.target}")
        print(f"📁 Results: {hk.root}")
        if not args.no_screenshots:
            print(f"📸 Screenshots: {args.screenshot_engine}")
    
    try:
        asyncio.run(hk.run())
    except KeyboardInterrupt:
        print("\n⏹️  Scan interrupted by user")
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)
    finally:
        print(f"\n✅ Scan complete!")
        print(f"📁 Results: {hk.root}")
        print(f"📊 Summary: {hk.root / 'summary.txt'}")
        if (hk.root / "reports" / "hawkeye_report.html").exists():
            print(f"🌐 HTML Report: {hk.root / 'reports' / 'hawkeye_report.html'}")

def setup_wordlists(args):
    """Setup wordlists with smart defaults"""
    results_dir = Path(args.results_root)
    results_dir.mkdir(exist_ok=True)
    
    # Directory scanning wordlist
    if args.wordlist:
        args.full_wordlist = args.wordlist
    else:
        args.full_wordlist = detect_default_wordlist()
    
    # Create quick wordlist (first 5000 lines for speed)
    quick_wl = results_dir / "quick_wordlist.txt"
    if not quick_wl.exists():
        crop_wordlist(Path(args.full_wordlist), quick_wl, 5000)
    args.quick_wordlist = str(quick_wl)
    
    # Subdomain wordlist
    if args.subdomain_wordlist:
        args.subdomain_wordlist = args.subdomain_wordlist
    else:
        args.subdomain_wordlist = DEFAULT_SUBDOMAIN_WORDLIST

def convert_args(args):
    """Convert simple CLI args to internal format"""
    # Performance settings
    args.workers = max(4, args.threads // 4)
    args.capture_workers = max(2, args.threads // 8)
    args.ffuf_threads = args.threads
    args.global_concurrency = min(args.threads, 20)
    args.per_host_concurrency = 3
    args.rate = min(args.threads * 10, 500)
    
    # Timeouts
    args.ffuf_timeout = args.timeout
    args.curl_timeout = args.timeout
    args.screenshot_timeout = 15
    
    # Screenshots
    args.screenshot_engine = "none" if args.no_screenshots else args.screenshot_engine
    args.screenshot_phase = "hits_only"
    
    # Subdomain settings
    args.enable_subdomain_enum = not args.no_subdomains
    args.use_subfinder = True
    args.use_amass = not args.subfinder_only
    args.subdomain_max_lines = 20000  # Use more subdomains for better coverage
    
    # Scan mode
    if args.fast:
        args.quick_lines = 1000  # Quick scan with 1k lines for speed
        args.max_depth = 1
    elif args.deep:
        args.quick_lines = 50000  # Deep scan with 50k lines for hours of scanning
        args.max_depth = 3
    else:
        args.quick_lines = 10000  # Default scan with 10k lines
        args.max_depth = 2
    
    # Background mode
    args.background_delay = 2.0
    
    # Default ports
    args.ports = "80,443,8080,8443"
    args.prefer_https = False
    
    # Extensions
    args.exts = "php,asp,aspx,jsp,html,htm,txt,xml,json"
    
    # Resume
    args.resume = None  # Will be set if resuming
    
    # Add missing attributes that might be referenced
    args.nmap_xml = []
    args.targets = []
    args.header = []
    args.cookie = None
    args.basic_auth = None

if __name__ == "__main__":
    main()

