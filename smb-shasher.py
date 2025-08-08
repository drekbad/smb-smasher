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
            share,
            perm,
            (m.group('desc') or "").strip()
        ))
    return rows

def parse_saved_files(file_paths: List[Path], user_label_from_name: bool, exclude_rx: List[re.Pattern]) -> Dict[str, List[Tuple[str, str, str, str, str]]]:
    """
    Offline mode: ingest saved nxc outputs.
    Returns dict[user_label] -> list[(ip, host, share, perm, desc)]
    """
    user_to_rows: Dict[str, List[Tuple[str, str, str, str, str]]] = defaultdict(list)
    id_rx = re.compile(r'id[_-]?(\d+)', re.IGNORECASE)
    for p in file_paths:
        text = p.read_text(encoding="utf-8", errors="ignore")
        label = p.name
        if user_label_from_name:
            m = id_rx.search(p.name)
            if m:
                label = m.group(1)
        rows = parse_nxc_text(text, label, exclude_rx)
        user_to_rows[label].extend(rows)
    return user_to_rows

def build_permission_map(
    all_rows_by_user: Dict[str, List[Tuple[str, str, str, str, str]]]
):
    """
    Build map: key=(ip, host, share) -> { 'desc': last_desc_seen, 'perms': {user: 'READ'|'WRITE'} }
    Prefer WRITE if both seen for same (user, share).
    """
    perm_map: Dict[Tuple[str, str, str], Dict] = {}
    for user, rows in all_rows_by_user.items():
        for ip, host, share, perm, desc in rows:
            key = (ip, host, share)
            if key not in perm_map:
                perm_map[key] = {'desc': desc, 'perms': {}}
            prev = perm_map[key]['perms'].get(user)
            if prev == 'WRITE':
                pass
            else:
                perm_map[key]['perms'][user] = perm.upper()
            if desc:
                perm_map[key]['desc'] = desc
    return perm_map

def classify_share(perms_by_user: Dict[str, str], user_order: List[str]) -> str:
    """
    'all_same' if every listed user has identical perm and none missing,
    'partial' if some users missing entries but others have,
    'mixed' if all present but differ,
    'none' if no entries.
    """
    vals = [perms_by_user.get(u) for u in user_order]
    have_vals = [v for v in vals if v is not None]
    if not have_vals:
        return 'none'
    unique = set(have_vals)
    missing = any(v is None for v in vals)
    if len(unique) == 1 and not missing:
        return 'all_same'
    if missing:
        return 'partial'
    return 'mixed'

def write_long_csv(out_path: Path, perm_map, user_order: List[str]):
    """
    Long format: ip, host, share, user, perm, description
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open('w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['ip', 'host', 'share', 'user', 'perm', 'description'])
        for (ip, host, share), info in sorted(perm_map.items(), key=lambda x: (x[0][1].lower(), x[0][2].lower())):
            desc = info['desc']
            for user in user_order:
                perm = info['perms'].get(user, '')
                if not perm:
                    continue
                w.writerow([ip, host, share, user, perm, desc])

def write_matrix_csv(out_path: Path, perm_map, user_order: List[str], include_flags: bool = True):
    """
    Matrix format: row per (host, share), columns are users with values W/R/-
    Extra: any_write, any_read, classification, description
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open('w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        header = ['ip', 'host', 'share'] + user_order
        if include_flags:
            header += ['any_write', 'any_read', 'classification', 'description']
        w.writerow(header)
        for (ip, host, share), info in sorted(perm_map.items(), key=lambda x: (x[0][1].lower(), x[0][2].lower())):
            perms = info['perms']
            row = [ip, host, share]
            vals = []
            any_w = False
            any_r = False
            for user in user_order:
                p = perms.get(user)
                if p == 'WRITE':
                    vals.append('W')
                    any_w = True
                elif p == 'READ':
                    vals.append('R')
                    any_r = True
                else:
                    vals.append('-')
            row.extend(vals)
            if include_flags:
                cls = classify_share(perms, user_order)
                row.extend(['Y' if any_w else 'N', 'Y' if any_r else 'N', cls, info['desc']])
            w.writerow(row)

def main():
    ap = argparse.ArgumentParser(
        description="Compare SMB share access across multiple NetExec credential IDs."
    )
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--ids", help="IDs to use with 'nxc smb -id', e.g. '1,2,5-7'")
    mode.add_argument("--infiles", help="Offline mode: comma-separated list of saved nxc outputs or a directory")

    # Fast vs safe execution style (default fast)
    style = ap.add_mutually_exclusive_group()
    style.add_argument("--batch-per-id", dest="batch_per_id", action="store_true",
                       help="Run one nxc invocation per ID over all targets (FAST).")
    style.add_argument("--per-target", dest="batch_per_id", action="store_false",
                       help="Run one nxc invocation per target (safer for very flaky envs).")
    ap.set_defaults(batch_per_id=True)

    ap.add_argument("--targets", help="Comma-separated IPs/hosts (for --ids mode)")
    ap.add_argument("--targets-file", help="File with IPs/hosts, one per line (for --ids mode)")
    ap.add_argument("--nxc-path", default="nxc", help="Path to netexec binary (default: nxc)")
    ap.add_argument("--nxc-threads", type=int, default=1, help="Threads passed to nxc -t (default: 1)")
    ap.add_argument("--nxc-timeout", type=int, default=900, help="Timeout seconds per run (default: 900)")
    ap.add_argument("--nxc-extra", default="", help="Extra args to pass to nxc (quoted), e.g. \"--dns-timeout 2 --timeout 6\"")
    ap.add_argument("--exclude-share", action="append", default=[], help="Regex to exclude shares (repeatable). Defaults include IPC$ and print$.")
    ap.add_argument("--outfile-prefix", "-o", default="smb_compare", help="Output prefix (default: smb_compare)")
    ap.add_argument("--capture-dir", help="Directory to store raw nxc outputs per id/target (auto-created)")
    ap.add_argument("--label-users-as-ids", action="store_true", help="(Reserved for future) Keep ID labels as headers")
    ap.add_argument("--usernames", help="Optional comma list of usernames aligned to IDs order (pretty headers)")
    ap.add_argument("--offline-label-from-name", action="store_true", help="When using --infiles, derive user label from filename '...id5...'")
    args = ap.parse_args()

    exclude_patterns = list(DEFAULT_EXCLUDE_SHARES) + args.exclude_share
    exclude_rx = compile_excludes(exclude_patterns)

    extra_args = args.nxc_extra.split() if args.nxc_extra else []
    extra_env = {
        # Try to keep child process (nxc + its Python deps) emitting UTF-8
        "PYTHONIOENCODING": "utf-8",
        "LC_ALL": "C.UTF-8",
        "LANG": "C.UTF-8",
    }

    if args.infiles:
        # Offline mode
        paths: List[Path] = []
        p = Path(args.infiles)
        if p.exists() and p.is_dir():
            paths = sorted([x for x in p.iterdir() if x.is_file()])
        else:
            for s in args.infiles.split(','):
                s = s.strip()
                if s:
                    paths.append(Path(s))
        if not paths:
            raise SystemExit("No files found for --infiles.")
        user_to_rows = parse_saved_files(paths, args.offline_label_from_name, exclude_rx)
        user_order = list(user_to_rows.keys())
    else:
        # Online mode: run nxc for each ID
        ids = parse_id_arg(args.ids)
        targets = load_targets(args.targets, args.targets_file)

        user_to_rows: Dict[str, List[Tuple[str, str, str, str, str]]] = {}
        cap_dir = Path(args.capture_dir) if args.capture_dir else None
        runner = _run_nxc_batch if args.batch_per_id else _run_nxc_per_target

        for id_ in ids:
            print(f"[+] Running nxc (batch={args.batch_per_id}) for id={id_} over {len(targets)} target(s)...", file=sys.stderr)
            raw = runner(
                nxc_path=args.nxc_path,
                nxc_id=id_,
                targets=targets,
                nxc_threads=args.nxc_threads,
                nxc_timeout=args.nxc_timeout,
                extra_args=extra_args,
                capture_dir=cap_dir,
                extra_env=extra_env,
            )
            rows = parse_nxc_text(raw, id_, exclude_rx)
            user_to_rows[id_] = rows
        user_order = ids

    # Optional pretty headers: replace IDs with usernames if provided
    header_users: List[str] = list(user_order)
    if args.usernames:
        provided = [u.strip() for u in args.usernames.split(',') if u.strip()]
        if len(provided) == len(user_order):
            header_users = provided
        else:
            print("[!] --usernames count does not match number of users/ids; ignoring.", file=sys.stderr)

    # Build final map & write outputs
    perm_map = build_permission_map(user_to_rows)

    out_prefix = Path(args.outfile_prefix)
    long_csv = out_prefix.with_suffix(".long.csv")
    matrix_csv = out_prefix.with_suffix(".matrix.csv")

    write_long_csv(long_csv, perm_map, user_order)
    write_matrix_csv(matrix_csv, perm_map, user_order, include_flags=True)

    print(f"[+] Wrote: {long_csv}")
    print(f"[+] Wrote: {matrix_csv}")
    print("[i] Tip: In Excel, conditional-format the matrix: 'W' bold/orange, 'R' green, '-' gray. Filter 'classification' for 'mixed'/'partial' to find deltas.")

if __name__ == "__main__":
    main()
