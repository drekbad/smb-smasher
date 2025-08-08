#!/usr/bin/env python3
import argparse
import csv
import os
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Iterable

# Matches classic netexec "SMB ..." share lines robust to spacing
LINE_RX = re.compile(
    r"""^SMB\s+                      # literal
        (?P<ip>\S+)\s+              # IP
        (?P<port>\d+)\s+            # Port (usually 445)
        (?P<host>\S+)\s+            # NetBIOS/Hostname
        (?P<share>\S+)\s+           # Share name (no spaces)
        (?P<perm>READ|WRITE)\b      # Permission keyword
        (?:\s+(?P<desc>.*))?        # Optional description
        $""",
    re.VERBOSE | re.IGNORECASE,
)

# Default excludes
DEFAULT_EXCLUDE_SHARES = [r'^IPC\$$', r'^print\$$']

def parse_id_arg(id_arg: str) -> List[str]:
    """
    Parse "1,2,5-10,17" into ordered unique list of strings: ["1","2","5",...]
    """
    out = []
    for chunk in id_arg.split(','):
        chunk = chunk.strip()
        if not chunk:
            continue
        if '-' in chunk:
            a, b = chunk.split('-', 1)
            a, b = a.strip(), b.strip()
            if a.isdigit() and b.isdigit():
                start, end = int(a), int(b)
                step = 1 if start <= end else -1
                out.extend(str(i) for i in range(start, end + step, step))
            else:
                raise ValueError(f"Bad range: {chunk}")
        else:
            if not chunk.isdigit():
                raise ValueError(f"Bad id: {chunk}")
            out.append(chunk)
    seen = set()
    ordered = []
    for x in out:
        if x not in seen:
            ordered.append(x)
            seen.add(x)
    return ordered

def load_targets(targets: Optional[str], targets_file: Optional[str]) -> List[str]:
    vals: List[str] = []
    if targets:
        for t in targets.split(','):
            t = t.strip()
            if t:
                vals.append(t)
    if targets_file:
        with open(targets_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                s = line.strip()
                if s and not s.startswith('#'):
                    vals.append(s)
    if not vals:
        raise SystemExit("No targets provided. Use --targets or --targets-file.")
    seen = set()
    out = []
    for v in vals:
        if v not in seen:
            out.append(v)
            seen.add(v)
    return out

def compile_excludes(patterns: Iterable[str]) -> List[re.Pattern]:
    return [re.compile(pat, re.IGNORECASE) for pat in patterns]

def share_is_excluded(share: str, ex_rx: List[re.Pattern]) -> bool:
    return any(rx.search(share) for rx in ex_rx)

def _run_nxc_batch(nxc_path, nxc_id, targets, nxc_threads, nxc_timeout, extra_args, capture_dir, extra_env):
    """
    One netexec invocation per ID over ALL targets (fast).
    """
    cmd = [nxc_path, "smb"] + targets + ["-id", nxc_id, "--shares", "-t", str(nxc_threads)] + extra_args
    env = os.environ.copy()
    env.update(extra_env or {})
    try:
        res = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=nxc_timeout if nxc_timeout > 0 else None,
            check=False,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
        )
        if capture_dir:
            Path(capture_dir).mkdir(parents=True, exist_ok=True)
            (Path(capture_dir) / f"all-shares_id{nxc_id}.txt").write_text(res.stdout, encoding="utf-8", errors="ignore")
        return res.stdout
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] id={nxc_id} targets={len(targets)}\n"
    except Exception as e:
        return f"[ERROR] id={nxc_id} -> {e}\n"

def _run_nxc_per_target(nxc_path, nxc_id, targets, nxc_threads, nxc_timeout, extra_args, capture_dir, extra_env):
    """
    One netexec invocation per target (safer for very flaky envs).
    """
    outputs = []
    env = os.environ.copy()
    env.update(extra_env or {})
    for tgt in targets:
        cmd = [nxc_path, "smb", tgt, "-id", nxc_id, "--shares", "-t", str(nxc_threads)] + extra_args
        try:
            res = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=nxc_timeout if nxc_timeout > 0 else None,
                check=False,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=env,
            )
            if capture_dir:
                Path(capture_dir).mkdir(parents=True, exist_ok=True)
                (Path(capture_dir) / f"all-shares_id{nxc_id}_{tgt.replace(':','_')}.txt").write_text(
                    res.stdout, encoding="utf-8", errors="ignore"
                )
            outputs.append(res.stdout)
        except subprocess.TimeoutExpired:
            outputs.append(f"[TIMEOUT] id={nxc_id} target={tgt}\n")
        except Exception as e:
            outputs.append(f"[ERROR] id={nxc_id} target={tgt} -> {e}\n")
    return "".join(outputs)

def parse_nxc_text(raw: str, user_label: str, exclude_rx: List[re.Pattern]) -> List[Tuple[str, str, str, str, str]]:
    """
    Extract (ip, host, share, perm, desc). Filters excluded shares.
    """
    rows = []
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("SMB"):
            continue
        m = LINE_RX.match(line)
        if not m:
            continue
        share = m.group('share')
        if share_is_excluded(share, exclude_rx):
            continue
        perm = (m.group('perm') or '').upper()
        rows.append((
            m.group('ip'),
            m.group('host'),
            shar
