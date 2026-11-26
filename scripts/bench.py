#!/usr/bin/env python3
"""ccwm benchmarks on synthetic fixtures (REQUIREMENTS.md §15; data rules §19).

Runs the real `ccwm serve` in throw-away synthetic environments under /tmp (never the real home)
and measures, per scenario, from /proc and the daemon's own status over its Unix socket:

  projects   N synthetic projects (each a small tree; every 5th a real Git repository): initial
             discovery time (start -> first finished scan, then -> Git and CPU quiet), watch count,
             RSS (VmRSS) and peak RSS (VmHWM), then idle CPU over --idle seconds.
  burst      on the same daemon: 10,000 files created across the projects at once; time until the
             daemon is quiet again, CPU used, overflows, peak RSS, and whether every touched project
             shows observed activity (checked over the HTTP API, signed in like the browser).
  exhaustion a small watch budget (`[watch] budget`): how many projects end up partly watched or
             polled, how long a reconciliation (`scan.refresh`) takes, and recovery after most
             projects are deleted (their watches are freed and the refused subtrees re-watched).
  sessions   ~--sessions-mb of synthetic Claude Code session files (realistic record shapes, big
             tool results the parser skips): time and CPU to index them from an empty database,
             peak RSS, a restart (checkpoints: nothing re-parsed) and an append.
  ignore     the worst case the ignore-file limits allow: --ignore-projects projects, each with a
             `.gitignore` of --ignore-rules rules that need a regular expression (more projects
             than the limit across projects admits): RSS and peak RSS after the first scan, which
             files were skipped, and the peak while every project is walked again next to the
             rules it already holds (a watch budget of 1, so every project is polled).

Usage (build first: cargo build --release --bins):
  scripts/bench.py --bin target/release [--projects 500] [--idle 600] [--sessions-mb 500]
                   [--only projects,burst,exhaustion,sessions,ignore] [--keep]
Prints a JSON document with every measurement and the host description. Standard library only.
"""

import argparse
import http.client
import json
import os
import platform
import random
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

CLK_TCK = os.sysconf("SC_CLK_TCK")
PAGE = os.sysconf("SC_PAGE_SIZE")


def log(*a):
    print("[bench]", *a, file=sys.stderr, flush=True)


# ---- process measurements ------------------------------------------------------------------


def cpu_seconds(pid):
    """(daemon utime+stime, reaped children's cutime+cstime) in seconds."""
    with open(f"/proc/{pid}/stat") as f:
        fields = f.read().rsplit(")", 1)[1].split()
    # fields[0] is state (field 3); utime=14, stime=15, cutime=16, cstime=17
    own = (int(fields[11]) + int(fields[12])) / CLK_TCK
    children = (int(fields[13]) + int(fields[14])) / CLK_TCK
    return own, children


def memory_kib(pid):
    out = {}
    with open(f"/proc/{pid}/status") as f:
        for line in f:
            k, _, v = line.partition(":")
            if k in ("VmRSS", "VmHWM", "Threads"):
                out[k] = int(v.split()[0])
    return out


def wait_quiet(pid, quiet_for=5.0, timeout=600.0, step=0.5):
    """Wait until the daemon used no CPU (own + children) for `quiet_for` seconds."""
    start = time.monotonic()
    last = sum(cpu_seconds(pid))
    still_since = time.monotonic()
    while time.monotonic() - start < timeout:
        time.sleep(step)
        now = sum(cpu_seconds(pid))
        if now > last:
            last, still_since = now, time.monotonic()
        elif time.monotonic() - still_since >= quiet_for:
            return still_since - start
    raise RuntimeError("the daemon never became quiet")


# ---- synthetic environments ---------------------------------------------------------------


class Env:
    def __init__(self, bindir, root, bulk):
        self.bindir = bindir
        self.root = root
        subprocess.run(
            [os.path.join(bindir, "ccwm-synth"), root, "--projects", str(bulk)],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        self.vars = dict(
            line.strip().split("=", 1) for line in open(os.path.join(root, "env")) if "=" in line
        )
        self.home = self.vars["HOME"]
        self.runtime = os.path.join(self.vars["XDG_RUNTIME_DIR"], "ccwm")
        self.claude = self.vars["CLAUDE_CONFIG_DIR"]

    def environ(self, extra=None):
        e = {"PATH": "/usr/bin:/bin", "NO_COLOR": "1", **self.vars}
        e.update(extra or {})
        return e

    def write_config(self, text):
        d = os.path.join(self.vars["XDG_CONFIG_HOME"], "ccwm")
        os.makedirs(d, mode=0o700, exist_ok=True)
        path = os.path.join(d, "config.toml")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(text)

    def flesh_out(self, n, git_every=5):
        """Give each bulk project a small tree (7 directories, 16 files); every `git_every`-th
        becomes a real Git repository with one commit (plain Git, the synthetic HOME)."""
        genv = {
            "PATH": "/usr/bin:/bin",
            "HOME": self.home,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_NAME": "Synthetic Author",
            "GIT_AUTHOR_EMAIL": "synthetic@example.invalid",
            "GIT_COMMITTER_NAME": "Synthetic Author",
            "GIT_COMMITTER_EMAIL": "synthetic@example.invalid",
        }
        git = shutil.which("git", path="/usr/bin:/bin")
        repos = 0
        for i in range(n):
            p = os.path.join(self.home, "bulk", f"proj-{i:04}")
            for d in ("src/core", "src/util", "src/api", "tests", "docs", "scripts", "assets"):
                os.makedirs(os.path.join(p, d), exist_ok=True)
                for k in range(2):
                    with open(os.path.join(p, d, f"file{k}.txt"), "w") as f:
                        f.write(f"synthetic {i} {d} {k}\n" * 20)
            with open(os.path.join(p, "README.md"), "w") as f:
                f.write("# synthetic\n")
            with open(os.path.join(p, ".gitignore"), "w") as f:
                f.write("target/\n")
            if git and i % git_every == 0:
                for args in (["init", "-q", "-b", "main"], ["add", "."], ["commit", "-q", "-m", "init"]):
                    subprocess.run([git, *args], cwd=p, env=genv, check=True)
                repos += 1
        return repos


def sock_call(env, op):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect(os.path.join(env.runtime, "ccwm.sock"))
    s.sendall(json.dumps({"op": op}).encode() + b"\n")
    data = b""
    while not data.endswith(b"\n"):
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
    s.close()
    v = json.loads(data)
    if "ok" not in v:
        raise RuntimeError(f"{op}: {v}")
    return v["ok"]


class Daemon:
    def __init__(self, env, extra_env=None):
        self.env = env
        self.started = time.monotonic()
        self.proc = subprocess.Popen(
            [os.path.join(env.bindir, "ccwm"), "serve", "--port", "0"],
            env=env.environ(extra_env),
            stdout=subprocess.DEVNULL,
            stderr=open(os.path.join(env.root, "daemon.log"), "ab"),
        )
        info = os.path.join(env.runtime, "instance.json")
        deadline = time.monotonic() + 30
        while True:
            try:
                with open(info) as f:
                    i = json.load(f)
                if i["pid"] == self.proc.pid:
                    self.port = i["port"]
                    break
            except (OSError, ValueError, KeyError):
                pass
            if self.proc.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError("daemon did not start; see " + env.root + "/daemon.log")
            time.sleep(0.02)
        self.pid = self.proc.pid
        self.token = None

    def scans(self):
        return sock_call(self.env, "discovery.status")

    def wait_scans(self, n, timeout=900):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            st = self.scans()
            if st.get("scans_finished", 0) >= n and st.get("phase") == "idle":
                return st
            time.sleep(0.1)
        raise RuntimeError(f"scan {n} did not finish")

    def refresh(self):
        """scan.refresh, then wait for it; returns seconds."""
        t = time.monotonic()
        target = sock_call(self.env, "scan.refresh")["done_at_scans_finished"]
        self.wait_scans(target)
        return time.monotonic() - t

    def login(self):
        boot = sock_call(self.env, "auth.bootstrap")["bootstrap_token"]
        st, body = self.http("POST", "/api/v1/auth/exchange", json.dumps({"bootstrap_token": boot}))
        self.token = json.loads(body)["session_token"]

    def http(self, method, path, body=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        headers = {"Host": f"127.0.0.1:{self.port}", "Origin": f"http://127.0.0.1:{self.port}"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if body is not None:
            headers["Content-Type"] = "application/json"
        if method == "GET":
            del headers["Origin"]
        c.request(method, path, body=body, headers=headers)
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, data

    def projects(self):
        out, cursor = [], None
        while True:
            q = "/api/v1/projects?limit=200&include_missing=1" + (f"&cursor={cursor}" if cursor else "")
            st, body = self.http("GET", q)
            v = json.loads(body)
            out.extend(v["items"])
            cursor = v.get("next_cursor")
            if not cursor:
                return out

    def status(self):
        return sock_call(self.env, "service.status")

    def stop(self):
        self.proc.send_signal(signal.SIGTERM)
        t = time.monotonic()
        code = self.proc.wait(timeout=30)
        return code, time.monotonic() - t


# ---- scenarios --------------------------------------------------------------------------------


def scenario_projects_and_burst(args, base, results):
    n = args.projects
    env = Env(args.bin, os.path.join(base, f"projects-{n}"), n)
    t = time.monotonic()
    repos = env.flesh_out(n)
    log(f"{n} projects ({repos} Git repositories) created in {time.monotonic() - t:.1f} s")
    d = Daemon(env)
    first = d.wait_scans(1)
    t_scan = time.monotonic() - d.started
    quiet = wait_quiet(d.pid)
    t_quiet = time.monotonic() - d.started - 5.0  # minus the quiet window itself
    st = d.status()
    mem = memory_kib(d.pid)
    own, children = cpu_seconds(d.pid)
    r = {
        "projects_created": n,
        "git_repositories": repos,
        "projects_found": first.get("projects_found"),
        "dirs_visited": first.get("dirs_visited"),
        "first_scan_finished_s": round(t_scan, 2),
        "quiet_after_start_s": round(t_quiet, 2),
        "cpu_s_startup_daemon": round(own, 2),
        "cpu_s_startup_children": round(children, 2),
        "watches": st["monitoring"]["watches"],
        "budget": st["monitoring"]["budget"],
        "watched_projects": st["monitoring"]["watched_projects"],
        "partial_projects": st["monitoring"]["partial_projects"],
        "polled_projects": st["monitoring"]["polled_projects"],
        "rss_kib_after_start": mem["VmRSS"],
        "peak_rss_kib_after_start": mem["VmHWM"],
        "threads": mem["Threads"],
    }
    log("projects:", r)
    if args.idle > 0:
        c0 = sum(cpu_seconds(d.pid))
        time.sleep(args.idle)
        c1 = sum(cpu_seconds(d.pid))
        r["idle_window_s"] = args.idle
        r["idle_cpu_s"] = round(c1 - c0, 3)
        r["idle_cpu_percent_of_one_core"] = round(100.0 * (c1 - c0) / args.idle, 4)
        r["rss_kib_after_idle"] = memory_kib(d.pid)["VmRSS"]
        log("idle:", r["idle_cpu_percent_of_one_core"], "% of one core")
    results["projects"] = r

    if "burst" in args.only:
        d.login()
        c0 = sum(cpu_seconds(d.pid))
        overflows0 = d.status()["monitoring"]["overflows"]
        per = max(1, 10_000 // n)
        touched = set()
        t = time.monotonic()
        count = 0
        for i in range(n):
            p = os.path.join(env.home, "bulk", f"proj-{i:04}", "src", "core")
            for k in range(per):
                if count >= 10_000:
                    break
                with open(os.path.join(p, f"burst{k}.txt"), "w") as f:
                    f.write("burst\n")
                count += 1
                touched.add(f"proj-{i:04}")
        written = time.monotonic() - t
        quiet = wait_quiet(d.pid, quiet_for=5.0)
        settled = time.monotonic() - t - 5.0
        c1 = sum(cpu_seconds(d.pid))
        st = d.status()
        items = d.projects()
        observed = sum(
            1 for p in items if p["name"] in touched and (p.get("activity") or {}).get("kind") == "observed"
        )
        b = {
            "files_written": count,
            "projects_touched": len(touched),
            "write_s": round(written, 2),
            "settled_after_s": round(settled, 2),
            "cpu_s": round(c1 - c0, 2),
            "overflows": st["monitoring"]["overflows"] - overflows0,
            "projects_with_observed_activity": observed,
            "peak_rss_kib": memory_kib(d.pid)["VmHWM"],
            "rss_kib_after": memory_kib(d.pid)["VmRSS"],
        }
        if b["overflows"]:
            b["refresh_after_overflow_s"] = round(d.refresh(), 2)
        log("burst:", b)
        results["burst"] = b
    code, stop_s = d.stop()
    results["projects"]["sigterm_exit"] = code
    results["projects"]["sigterm_stop_s"] = round(stop_s, 2)
    if not args.keep:
        shutil.rmtree(env.root, ignore_errors=True)


def scenario_exhaustion(args, base, results):
    n = args.projects
    budget = args.budget
    env = Env(args.bin, os.path.join(base, f"exhaustion-{n}"), n)
    env.flesh_out(n, git_every=10**9)
    env.write_config(f"[watch]\nbudget = {budget}\n")
    d = Daemon(env)
    d.wait_scans(1)
    wait_quiet(d.pid)
    st = d.status()["monitoring"]
    r = {
        "projects": n,
        "budget": budget,
        "watches": st["watches"],
        "watched_projects": st["watched_projects"],
        "partial_projects": st["partial_projects"],
        "polled_projects": st["polled_projects"],
        "degraded": st["degraded"],
    }
    # An edit in the last project (least recently active, so polled or partly watched): a
    # reconciliation picks it up.
    r["refresh_s"] = round(d.refresh(), 2)
    # Recovery: delete 80 % of the projects; their watches are freed, and the next
    # reconciliation re-watches the refused subtrees of the rest.
    keep = n // 5
    for i in range(keep, n):
        shutil.rmtree(os.path.join(env.home, "bulk", f"proj-{i:04}"))
    time.sleep(3)
    r["deleted_projects"] = n - keep
    r["refresh_after_delete_s"] = round(d.refresh(), 2)
    r["refresh_again_s"] = round(d.refresh(), 2)
    st = d.status()["monitoring"]
    r.update(
        {
            "after_watches": st["watches"],
            "after_watched_projects": st["watched_projects"],
            "after_partial_projects": st["partial_projects"],
            "after_polled_projects": st["polled_projects"],
            "after_degraded": st["degraded"],
        }
    )
    log("exhaustion:", r)
    results["exhaustion"] = r
    d.stop()
    if not args.keep:
        shutil.rmtree(env.root, ignore_errors=True)


def session_lines(sid, cwd, target_bytes, rng):
    """Synthetic records in Claude Code's verified shapes (ARCHITECTURE.md §11); the bulk of the
    bytes are tool results and assistant text, which the allowlist parser skips."""
    ts = 1_795_000_000
    out = []
    size = 0
    filler = "SYNTHETIC " * 50

    def emit(rec):
        nonlocal size
        line = json.dumps(rec, separators=(",", ":"))
        out.append(line)
        size += len(line) + 1

    def stamp():
        nonlocal ts
        ts += rng.randint(1, 30)
        return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(ts))

    base = {"sessionId": sid, "cwd": cwd, "version": "2.1.331", "gitBranch": "main", "entrypoint": "cli"}
    turn = 0
    while size < target_bytes:
        turn += 1
        emit({**base, "type": "user", "uuid": f"u{turn}", "timestamp": stamp(), "promptSource": "typed",
              "message": {"role": "user", "content": f"SYNTHETIC prompt {turn} " + filler[: rng.randint(50, 400)]}})
        emit({**base, "type": "assistant", "uuid": f"a{turn}", "timestamp": stamp(),
              "message": {"role": "assistant", "content": [
                  {"type": "thinking", "thinking": filler * rng.randint(1, 4)},
                  {"type": "text", "text": filler * rng.randint(1, 6)},
                  {"type": "tool_use", "id": f"t{turn}", "name": "Read", "input": {"file_path": cwd + "/src/x.rs"}}]}})
        result = filler * rng.randint(5, 60)
        emit({**base, "type": "user", "uuid": f"r{turn}", "timestamp": stamp(),
              "toolUseResult": {"stdout": result, "stderr": ""},
              "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": f"t{turn}", "content": result}]}})
        if turn % 10 == 0:
            emit({"type": "file-history-snapshot", "messageId": f"a{turn}", "snapshot": {"trackedFileBackups": {}}})
            emit({**base, "type": "system", "uuid": f"s{turn}", "timestamp": stamp(), "subtype": "info", "content": "SYNTHETIC"})
    emit({"type": "ai-title", "sessionId": sid, "aiTitle": f"SYNTHETIC session {sid[:8]}"})
    return out


def scenario_sessions(args, base, results):
    target = args.sessions_mb * 1024 * 1024
    env = Env(args.bin, os.path.join(base, "sessions"), 50)
    rng = random.Random(42)
    # One large file (60 MB, near the largest seen: 76 MB) and many 2–8 MB files.
    sizes = [60 * 1024 * 1024]
    while sum(sizes) < target:
        sizes.append(rng.randint(2, 8) * 1024 * 1024)
    t = time.monotonic()
    total = 0
    files = []
    for k, sz in enumerate(sizes):
        sid = f"{k:08x}-5e55-4000-8000-{rng.getrandbits(48):012x}"
        proj = os.path.join(env.home, "bulk", f"proj-{k % 50:04}")
        enc = os.path.join(env.claude, "projects", "-bench-" + proj.replace("/", "-").strip("-"))
        os.makedirs(enc, exist_ok=True)
        path = os.path.join(enc, sid + ".jsonl")
        data = "\n".join(session_lines(sid, proj, sz, rng)) + "\n"
        with open(path, "w") as f:
            f.write(data)
        total += len(data)
        files.append(path)
    log(f"{len(files)} session files, {total / 1048576:.0f} MiB, written in {time.monotonic() - t:.1f} s")
    # Drop the page cache's advantage? Not possible without root: the files were just written,
    # so this measures parsing from the page cache (stated in the results).
    d = Daemon(env)
    deadline = time.monotonic() + 1800
    while time.monotonic() < deadline:
        st = d.scans()
        s = st.get("sessions", {})
        if st.get("scans_finished", 0) >= 1 and s.get("indexed", 0) >= len(files) + 7:
            break
        time.sleep(0.2)
    indexed_s = time.monotonic() - d.started
    own, children = cpu_seconds(d.pid)
    mem = memory_kib(d.pid)
    r = {
        "files": len(files),
        "mib": round(total / 1048576, 1),
        "largest_mib": round(sizes[0] / 1048576, 1),
        "indexed_after_s": round(indexed_s, 2),
        "cpu_s": round(own + children, 2),
        "mib_per_cpu_s": round(total / 1048576 / max(own + children, 0.001), 1),
        "peak_rss_kib": mem["VmHWM"],
        "rss_kib": mem["VmRSS"],
        "page_cache": "warm (files written just before)",
    }
    wait_quiet(d.pid)
    d.stop()
    # Restart: checkpoints, so nothing is parsed again.
    d = Daemon(env)
    d.wait_scans(1)
    r["restart_first_scan_s"] = round(time.monotonic() - d.started, 2)
    wait_quiet(d.pid)
    own, children = cpu_seconds(d.pid)
    r["restart_cpu_s"] = round(own + children, 2)
    # Append 8 MiB to the largest file: parsed from its checkpoint only.
    c0 = sum(cpu_seconds(d.pid))
    sid = os.path.basename(files[0])[:-6]
    with open(files[0], "a") as f:
        f.write("\n".join(session_lines(sid, os.path.join(env.home, "bulk", "proj-0000"), 8 * 1024 * 1024, rng)) + "\n")
    r["append_refresh_s"] = round(d.refresh(), 2)
    wait_quiet(d.pid)
    r["append_mib"] = 8
    r["append_cpu_s"] = round(sum(cpu_seconds(d.pid)) - c0, 2)
    log("sessions:", r)
    results["sessions"] = r
    d.stop()
    if not args.keep:
        shutil.rmtree(env.root, ignore_errors=True)


def scenario_ignore(args, base, results):
    n, rules = args.ignore_projects, args.ignore_rules
    env = Env(args.bin, os.path.join(base, "ignore"), 0)
    for i in range(n):
        p = os.path.join(env.home, "rules", f"proj-{i:02}")
        os.makedirs(os.path.join(p, ".git"))  # a work tree: `.gitignore` applies
        with open(os.path.join(p, "CLAUDE.md"), "w") as f:
            f.write("# synthetic\n")
        with open(os.path.join(p, ".gitignore"), "w") as f:
            # Every rule needs a regular expression (the expensive kind); all are different.
            f.writelines(f"*{i}x{k}?b[c-d]*.x\n" for k in range(rules))
    r = {"projects": n, "rules_per_project": rules}

    def measure(d, prefix):
        st = d.status()["monitoring"]
        mem = memory_kib(d.pid)
        r[prefix + "ignore_files_skipped"] = st["ignore_files_skipped"]
        r[prefix + "rules_kept"] = (n - st["ignore_files_skipped"]) * rules
        r[prefix + "rss_mib"] = round(mem["VmRSS"] / 1024, 1)
        r[prefix + "peak_rss_mib"] = round(mem["VmHWM"] / 1024, 1)
        r[prefix + "polled_projects"] = st["polled_projects"]

    # Every project watched: the rules are compiled once and kept.
    d = Daemon(env)
    d.wait_scans(1)
    r["first_scan_s"] = round(time.monotonic() - d.started, 2)
    wait_quiet(d.pid)
    own, children = cpu_seconds(d.pid)
    r["cpu_s"] = round(own + children, 2)
    measure(d, "")
    code, _ = d.stop()
    r["exit_code"] = code

    # Every project polled (no watch left for them): each reconciliation walks every project
    # again, and the new rules exist next to the old ones until they replace them.
    env.write_config("[watch]\nbudget = 1\n")
    d = Daemon(env)
    d.wait_scans(1)
    wait_quiet(d.pid)
    r["polled_refresh_s"] = [round(d.refresh(), 2) for _ in range(2)]
    wait_quiet(d.pid)
    measure(d, "polled_")
    code, _ = d.stop()
    r["polled_exit_code"] = code
    log("ignore:", r)
    results["ignore"] = r
    if not args.keep:
        shutil.rmtree(env.root, ignore_errors=True)


def host():
    def first(path, key, sep=":"):
        try:
            for line in open(path):
                if line.startswith(key):
                    return line.split(sep, 1)[1].strip().strip('"')
        except OSError:
            return None

    def run(*cmd):
        try:
            return subprocess.run(cmd, capture_output=True, text=True).stdout.strip()
        except OSError:
            return None

    return {
        "cpu": first("/proc/cpuinfo", "model name"),
        "logical_cpus": os.cpu_count(),
        "memory_kib": int(first("/proc/meminfo", "MemTotal").split()[0]),
        "kernel": platform.release(),
        "os": first("/etc/os-release", "PRETTY_NAME", "="),
        "tmp_filesystem": run("findmnt", "-n", "-o", "FSTYPE,SOURCE", "-T", "/tmp"),
        "inotify_max_user_watches": int(open("/proc/sys/fs/inotify/max_user_watches").read()),
        "ccwm": run(os.path.join(ARGS.bin, "ccwm"), "--version"),
    }


def main():
    global ARGS
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--bin", required=True, help="directory with ccwm and ccwm-synth (a release build)")
    p.add_argument("--projects", type=int, default=500)
    p.add_argument("--idle", type=int, default=600, help="idle CPU window in seconds (0: skip)")
    p.add_argument("--budget", type=int, default=1000, help="watch budget for the exhaustion scenario")
    p.add_argument("--sessions-mb", type=int, default=500)
    p.add_argument("--ignore-projects", type=int, default=6, help="projects of the ignore scenario")
    p.add_argument("--ignore-rules", type=int, default=5000, help="ignore rules per project (ignore scenario)")
    p.add_argument("--only", default="projects,burst,exhaustion,sessions,ignore")
    p.add_argument("--keep", action="store_true", help="keep the synthetic environments")
    ARGS = p.parse_args()
    ARGS.only = set(ARGS.only.split(","))
    base = tempfile.mkdtemp(prefix="ccwm-bench-", dir="/tmp")
    os.chmod(base, 0o700)
    results = {"host": host(), "method": "real `ccwm serve --port 0` per scenario in a synthetic environment under /tmp; CPU from /proc/<pid>/stat (daemon + reaped Git children), memory from /proc/<pid>/status; daemon state over its Unix socket"}
    started = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    results["started"] = started
    if ARGS.only & {"projects", "burst"}:
        scenario_projects_and_burst(ARGS, base, results)
    if "exhaustion" in ARGS.only:
        scenario_exhaustion(ARGS, base, results)
    if "sessions" in ARGS.only:
        scenario_sessions(ARGS, base, results)
    if "ignore" in ARGS.only:
        scenario_ignore(ARGS, base, results)
    results["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    if not ARGS.keep:
        shutil.rmtree(base, ignore_errors=True)
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
