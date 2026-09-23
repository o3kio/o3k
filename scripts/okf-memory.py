#!/usr/bin/env python3
"""Deterministic, evidence-first repository memory using OKF v0.2.

Canonical tracked progress is append-only under
`.okf/workstreams/<id>/runs/.../*.md`. Current workstream files are deterministic
materialized views. Session-local state and validation receipts live under the
Git worktree metadata and are never committed.

The helper records observations only. It does not infer intent, completion,
architecture, blockers, root cause, or next steps.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time

TOOL_VERSION = "0.3"
ACTOR = f"process:o3k-okf-memory/{TOOL_VERSION}"
ROOT_INDEX = """---
okf_version: "0.2"
---

# O3K repository memory

This OKF bundle is an evidence index for development continuity. It does not
replace O3K's normative ADRs, specs, contracts, tests, compatibility evidence,
or Git history.

- [Current workstream projections](current/workstreams/) - generated bounded views for resuming work.
- [Development workstreams](workstreams/) - append-only deterministic run records.
- [Memory protocol](../docs/OKF_MEMORY.md) - trust model, workflow, and limitations.

`workstreams/*/runs/` is canonical tracked progress memory. `current/` is a
deterministic projection and may be regenerated at any time.
"""
WORKSTREAM_INDEX = """# Development workstreams

Each workstream owns append-only `Development Run` concepts under
`<workstream-id>/runs/YYYY/MM/DD/`.

For issue-driven O3K work, prefer the stable workstream ID `issue-<number>`.
Do not hand-edit committed run records.
"""
CURRENT_INDEX_EMPTY = """# Current workstreams

No development run records have been captured yet.
"""
RUN_NAME_RE = re.compile(r"^\d{8}T\d{12}Z-run-[0-9a-f]{12}\.md$")
SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?i)^(.*(?:password|passwd|token|secret|api[_-]?key|private[_-]?key|database_url|connection_string)=).*$"
)
SENSITIVE_FLAGS = {
    "--password",
    "--passwd",
    "--token",
    "--secret",
    "--api-key",
    "--private-key",
    "--database-url",
    "--connection-string",
}


def run(
    cmd: list[str], cwd: Path, *, check: bool = True, capture: bool = True
) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        check=False,
    )
    if check and proc.returncode != 0:
        stderr = proc.stderr or ""
        raise RuntimeError(
            f"command failed ({proc.returncode}): {shlex.join(cmd)}\n{stderr}"
        )
    return proc


def git(cwd: Path, *args: str, check: bool = True) -> str:
    return run(["git", *args], cwd, check=check).stdout.strip()


def repo_root(cwd: Path) -> Path:
    return Path(git(cwd, "rev-parse", "--show-toplevel")).resolve()


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso(timestamp: dt.datetime) -> str:
    return timestamp.isoformat(timespec="seconds").replace("+00:00", "Z")


def timestamp_filename(timestamp: dt.datetime) -> str:
    return timestamp.strftime("%Y%m%dT%H%M%S") + f"{timestamp.microsecond:06d}Z"


def slug(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9._-]+", "-", value.strip().lower())
    normalized = re.sub(r"-+", "-", normalized).strip("-.")
    return normalized or "unknown"


def yaml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def yaml_bool(value: bool) -> str:
    return "true" if value else "false"


def github_repo(root: Path) -> str | None:
    remote = git(root, "remote", "get-url", "origin", check=False)
    if not remote:
        return None
    match = re.search(r"github\.com[:/](.+?)(?:\.git)?$", remote)
    return match.group(1) if match else None


def current_pr(root: Path) -> dict | None:
    try:
        proc = run(
            ["gh", "pr", "view", "--json", "number,url,title,state"],
            root,
            check=False,
        )
    except FileNotFoundError:
        return None
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    try:
        value = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def dirty_paths(root: Path) -> list[str]:
    paths: set[str] = set()
    commands = [
        ["git", "diff", "--name-only", "--", ".", ":(exclude).okf"],
        [
            "git",
            "diff",
            "--cached",
            "--name-only",
            "HEAD",
            "--",
            ".",
            ":(exclude).okf",
        ],
        ["git", "ls-files", "--others", "--exclude-standard"],
    ]
    for command in commands:
        proc = run(command, root, check=False)
        for raw in proc.stdout.splitlines():
            path = raw.strip()
            if path and path != ".okf" and not path.startswith(".okf/"):
                paths.add(path)
    return sorted(paths)


def git_state(root: Path) -> dict:
    head = git(root, "rev-parse", "HEAD")
    branch = git(root, "branch", "--show-current") or "DETACHED"
    return {"head": head, "branch": branch, "dirty": bool(dirty_paths(root))}


def tracked_patch_hash(root: Path) -> tuple[str, bool]:
    unstaged = run(
        ["git", "diff", "--binary", "--", ".", ":(exclude).okf"], root
    ).stdout
    staged = run(
        [
            "git",
            "diff",
            "--cached",
            "--binary",
            "HEAD",
            "--",
            ".",
            ":(exclude).okf",
        ],
        root,
    ).stdout
    payload = (staged + "\n---UNSTAGED---\n" + unstaged).encode()
    return hashlib.sha256(payload).hexdigest(), bool(staged.strip() or unstaged.strip())


def metadata_dir(root: Path) -> Path:
    raw = git(root, "rev-parse", "--git-path", "okf-memory")
    path = Path(raw)
    if not path.is_absolute():
        path = root / path
    path.mkdir(parents=True, exist_ok=True)
    return path.resolve()


def session_file(root: Path) -> Path:
    return metadata_dir(root) / "session.json"


def receipts_file(root: Path) -> Path:
    return metadata_dir(root) / "receipts.jsonl"


def determine_workstream(root: Path, explicit: str | None) -> tuple[str, dict | None]:
    if explicit:
        return slug(explicit), current_pr(root)
    pr = current_pr(root)
    if pr and isinstance(pr.get("number"), int):
        return f"pr-{pr['number']}", pr
    branch = git_state(root)["branch"]
    if branch in {"main", "master", "DETACHED"}:
        raise RuntimeError(
            "cannot derive a stable workstream on the default/detached branch; "
            "pass --workstream issue-<number> (preferred for O3K issue-driven work)"
        )
    return f"branch-{slug(branch)}", None


def redact_command(command: list[str]) -> str:
    redacted: list[str] = []
    redact_next = False
    for argument in command:
        if redact_next:
            redacted.append("***REDACTED***")
            redact_next = False
            continue
        if argument.lower() in SENSITIVE_FLAGS:
            redacted.append(argument)
            redact_next = True
            continue
        if SENSITIVE_ASSIGNMENT_RE.match(argument):
            prefix = argument.split("=", 1)[0]
            redacted.append(f"{prefix}=***REDACTED***")
            continue
        redacted.append(argument)
    return shlex.join(redacted)


def ensure_bundle(root: Path) -> None:
    okf = root / ".okf"
    (okf / "workstreams").mkdir(parents=True, exist_ok=True)
    (okf / "current" / "workstreams").mkdir(parents=True, exist_ok=True)
    files = {
        okf / "index.md": ROOT_INDEX,
        okf / "workstreams" / "index.md": WORKSTREAM_INDEX,
        okf / "current" / "workstreams" / "index.md": CURRENT_INDEX_EMPTY,
    }
    for path, content in files.items():
        if not path.exists():
            path.write_text(content, encoding="utf-8")


def cmd_init(args: argparse.Namespace) -> int:
    root = repo_root(Path(args.cwd))
    ensure_bundle(root)
    print(root / ".okf")
    return 0


def cmd_start(args: argparse.Namespace) -> int:
    root = repo_root(Path(args.cwd))
    ensure_bundle(root)
    sf = session_file(root)
    if sf.exists():
        raise RuntimeError(
            "an OKF memory session is already active; end or checkpoint it first"
        )
    workstream, pr = determine_workstream(root, args.workstream)
    state = git_state(root)
    session = {
        "tool_version": TOOL_VERSION,
        "started_at": iso(utcnow()),
        "workstream_id": workstream,
        "start_head": state["head"],
        "start_branch": state["branch"],
        "dirty_at_start": state["dirty"],
        "pr": pr,
    }
    sf.write_text(
        json.dumps(session, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    receipts_file(root).write_text("", encoding="utf-8")
    print(json.dumps(session, indent=2, ensure_ascii=False))
    return 0


def cmd_exec(args: argparse.Namespace) -> int:
    root = repo_root(Path(args.cwd))
    if not session_file(root).exists():
        raise RuntimeError("no active OKF memory session; run start first")
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise RuntimeError("missing command after --")
    before_head = git_state(root)["head"]
    started = utcnow()
    started_monotonic = time.monotonic()
    proc = subprocess.run(command, cwd=root, text=True, check=False)
    ended = utcnow()
    receipt = {
        "command": redact_command(command),
        "started_at": iso(started),
        "ended_at": iso(ended),
        "elapsed_seconds": round(time.monotonic() - started_monotonic, 3),
        "exit_code": proc.returncode,
        "head": before_head,
    }
    with receipts_file(root).open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(receipt, ensure_ascii=False) + "\n")
    return proc.returncode


def history_relation(root: Path, start: str, end: str) -> str:
    if start == end:
        return "unchanged"
    proc = run(["git", "merge-base", "--is-ancestor", start, end], root, check=False)
    return "linear" if proc.returncode == 0 else "rewritten-or-diverged"


def commits_between(root: Path, start: str, end: str) -> list[dict[str, str]]:
    if start == end:
        return []
    if history_relation(root, start, end) != "linear":
        return [
            {
                "sha": end,
                "subject": "observed HEAD after history rewrite/divergence",
            }
        ]
    output = git(root, "log", "--reverse", "--format=%H%x09%s", f"{start}..{end}")
    commits: list[dict[str, str]] = []
    for line in output.splitlines():
        sha, separator, subject = line.partition("\t")
        if separator:
            commits.append({"sha": sha, "subject": subject})
    return commits


def changed_files_between(root: Path, start: str, end: str) -> list[str]:
    if start == end:
        return []
    proc = run(
        [
            "git",
            "diff",
            "--name-only",
            start,
            end,
            "--",
            ".",
            ":(exclude).okf",
        ],
        root,
        check=False,
    )
    return sorted(
        {line.strip() for line in proc.stdout.splitlines() if line.strip()}
    )


def load_receipts(root: Path) -> list[dict]:
    path = receipts_file(root)
    if not path.exists():
        return []
    receipts: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            receipts.append(json.loads(line))
    return receipts


def source_entries(
    root: Path, session: dict, observed_head: str
) -> list[tuple[str, str, str]]:
    repo = github_repo(root)
    sources: list[tuple[str, str, str]] = []
    workstream = str(session["workstream_id"])
    if repo and re.fullmatch(r"issue-\d+", workstream):
        number = workstream.split("-", 1)[1]
        sources.append(
            ("issue", f"https://github.com/{repo}/issues/{number}", f"Issue #{number}")
        )
    pr = session.get("pr")
    if isinstance(pr, dict) and pr.get("url"):
        sources.append(
            (
                "pull-request",
                str(pr["url"]),
                f"PR #{pr.get('number')}: {pr.get('title', '')}".strip(),
            )
        )
    if repo:
        sources.append(
            (
                "observed-head",
                f"https://github.com/{repo}/commit/{observed_head}",
                "Observed repository HEAD",
            )
        )
    return sources


def render_run(
    root: Path, session: dict, ended: dt.datetime
) -> tuple[str, list[str], list[dict]]:
    state = git_state(root)
    tracked_hash, tracked_patch_present = tracked_patch_hash(root)
    relation = history_relation(root, session["start_head"], state["head"])
    commits = commits_between(root, session["start_head"], state["head"])
    files = sorted(
        set(
            changed_files_between(root, session["start_head"], state["head"])
            + dirty_paths(root)
        )
    )
    receipts = load_receipts(root)
    untracked = run(
        ["git", "ls-files", "--others", "--exclude-standard"], root
    ).stdout.splitlines()
    untracked = sorted(
        path for path in untracked if path and not path.startswith(".okf/")
    )
    sources = source_entries(root, session, state["head"])

    lines = [
        "---",
        "type: Development Run",
        f"title: {yaml_string('Development run ' + session['workstream_id'])}",
        f"description: {yaml_string('Deterministically captured repository progress; no LLM-authored summary.')}",
        "status: stable",
        f"workstream_id: {yaml_string(session['workstream_id'])}",
        f"started_at: {yaml_string(session['started_at'])}",
        f"ended_at: {yaml_string(iso(ended))}",
        f"branch: {yaml_string(state['branch'])}",
        f"start_commit: {yaml_string(session['start_head'])}",
        f"observed_head: {yaml_string(state['head'])}",
        f"history_relation: {yaml_string(relation)}",
        f"dirty_at_start: {yaml_bool(bool(session.get('dirty_at_start')))}",
        f"dirty_at_end: {yaml_bool(state['dirty'])}",
        f"tracked_patch_present: {yaml_bool(tracked_patch_present)}",
        f"tracked_patch_sha256: {yaml_string(tracked_hash)}",
        f"untracked_paths_present: {yaml_bool(bool(untracked))}",
        "generated:",
        f"  by: {yaml_string(ACTOR)}",
        f"  at: {yaml_string(iso(ended))}",
    ]
    if sources:
        lines.append("sources:")
        for source_id, resource, title in sources:
            lines.extend(
                [
                    f"  - id: {yaml_string(source_id)}",
                    f"    resource: {yaml_string(resource)}",
                    f"    title: {yaml_string(title)}",
                ]
            )
    lines.extend(
        [
            "---",
            "",
            "# Repository state",
            "",
            f"- Workstream: `{session['workstream_id']}`",
            f"- Branch: `{state['branch']}`",
            f"- Start commit: `{session['start_head']}`",
            f"- Observed end HEAD: `{state['head']}`",
            f"- History relation: `{relation}`",
            f"- Dirty at start: `{str(bool(session.get('dirty_at_start'))).lower()}`",
            f"- Dirty at end: `{str(state['dirty']).lower()}`",
            f"- Tracked patch SHA-256 (excluding `.okf/`): `{tracked_hash}`",
            "",
            "# Commits observed",
            "",
        ]
    )
    if commits:
        lines.extend(
            f"- `{commit['sha'][:12]}` — {commit['subject']}" for commit in commits
        )
    else:
        lines.append("- None")
    lines.extend(["", "# Files changed or dirty", ""])
    if files:
        lines.extend(f"- `{path}`" for path in files)
    else:
        lines.append("- None")
    lines.extend(["", "# Validation receipts", ""])
    if receipts:
        for receipt in receipts:
            verdict = (
                "PASS"
                if receipt["exit_code"] == 0
                else f"FAIL({receipt['exit_code']})"
            )
            lines.append(
                f"- `{receipt['command']}` — **{verdict}** — "
                f"{receipt['elapsed_seconds']}s — HEAD `{receipt['head'][:12]}`"
            )
    else:
        lines.append("- None captured through `scripts/okf-memory.py exec`.")
    lines.extend(
        [
            "",
            "# Interpretation boundary",
            "",
            "This record contains observations only. It does not infer intent, completion,",
            "architecture, blockers, root cause, or next steps. Follow the linked issue/PR,",
            "accepted ADRs/specs/contracts, tests, and Git history for semantic claims.",
            "",
        ]
    )
    return "\n".join(lines), files, receipts


def emit_record(root: Path, *, force: bool, keep_session: bool) -> Path | None:
    sf = session_file(root)
    if not sf.exists():
        raise RuntimeError("no active OKF memory session; run start first")
    session = json.loads(sf.read_text(encoding="utf-8"))
    ended = utcnow()
    payload, files, receipts = render_run(root, session, ended)
    state = git_state(root)
    commits = commits_between(root, session["start_head"], state["head"])
    if not force and not commits and not files and not receipts:
        print("No meaningful repository/test activity; no run record created.")
        if not keep_session:
            sf.unlink(missing_ok=True)
            receipts_file(root).unlink(missing_ok=True)
        return None

    workstream = slug(session["workstream_id"])
    directory = (
        root
        / ".okf"
        / "workstreams"
        / workstream
        / "runs"
        / ended.strftime("%Y")
        / ended.strftime("%m")
        / ended.strftime("%d")
    )
    directory.mkdir(parents=True, exist_ok=True)
    record_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]
    path = directory / f"{timestamp_filename(ended)}-run-{record_hash}.md"
    path.write_text(payload, encoding="utf-8")

    if keep_session:
        next_session = {
            **session,
            "started_at": iso(ended),
            "start_head": state["head"],
            "start_branch": state["branch"],
            "dirty_at_start": state["dirty"],
            "pr": current_pr(root) or session.get("pr"),
        }
        sf.write_text(
            json.dumps(next_session, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        receipts_file(root).write_text("", encoding="utf-8")
    else:
        sf.unlink(missing_ok=True)
        receipts_file(root).unlink(missing_ok=True)
    return path


def cmd_checkpoint(args: argparse.Namespace) -> int:
    root = repo_root(Path(args.cwd))
    ensure_bundle(root)
    path = emit_record(root, force=args.force, keep_session=True)
    if path:
        refresh(root)
        print(path.relative_to(root))
    return 0


def cmd_end(args: argparse.Namespace) -> int:
    root = repo_root(Path(args.cwd))
    ensure_bundle(root)
    path = emit_record(root, force=args.force, keep_session=False)
    if path:
        refresh(root)
        print(path.relative_to(root))
    return 0


def parse_scalar(path: Path, key: str) -> str | bool | None:
    text = path.read_text(encoding="utf-8")
    match = re.search(rf"^{re.escape(key)}:\s*(.+)$", text, re.MULTILINE)
    if not match:
        return None
    raw = match.group(1).strip()
    if raw == "true":
        return True
    if raw == "false":
        return False
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw


def render_projection(workstream: str, paths: list[Path], current_dir: Path) -> str:
    latest = paths[-1]
    latest_relative = os.path.relpath(latest, current_dir).replace(os.sep, "/")
    latest_head = str(parse_scalar(latest, "observed_head") or "unknown")
    latest_branch = str(parse_scalar(latest, "branch") or "unknown")
    latest_ended = str(
        parse_scalar(latest, "ended_at") or "1970-01-01T00:00:00Z"
    )
    lines = [
        "---",
        "type: Workstream Projection",
        f"title: {yaml_string('Current projection ' + workstream)}",
        f"description: {yaml_string('Deterministic materialized view over immutable Development Run records.')}",
        "status: stable",
        f"workstream_id: {yaml_string(workstream)}",
        "generated:",
        f"  by: {yaml_string(ACTOR)}",
        f"  at: {yaml_string(latest_ended)}",
        "sources:",
        f"  - id: {yaml_string('latest-run')}",
        f"    resource: {yaml_string(latest_relative)}",
        f"    title: {yaml_string('Latest immutable Development Run')}",
        "---",
        "",
        "# Latest observed repository state",
        "",
        f"- Workstream: `{workstream}`",
        f"- Branch: `{latest_branch}`",
        f"- Observed HEAD: `{latest_head}`",
        f"- Latest run record: [{latest.name}]({latest_relative})",
        "",
        "# Recent run records",
        "",
    ]
    for path in reversed(paths[-5:]):
        relative = os.path.relpath(path, current_dir).replace(os.sep, "/")
        lines.append(f"- [{path.name}]({relative})")
    lines.extend(
        [
            "",
            "# Interpretation boundary",
            "",
            "This projection is mechanical. It does not state what is complete or what to do next.",
            "Use the immutable run records as evidence and follow their authoritative sources.",
            "",
        ]
    )
    return "\n".join(lines)


def expected_projections(root: Path) -> tuple[dict[Path, str], str]:
    workstreams_dir = root / ".okf" / "workstreams"
    current_dir = root / ".okf" / "current" / "workstreams"
    groups: dict[str, list[Path]] = {}
    if workstreams_dir.exists():
        for path in sorted(workstreams_dir.glob("*/runs/**/*.md")):
            workstream = str(parse_scalar(path, "workstream_id") or "unknown")
            groups.setdefault(workstream, []).append(path)
    outputs: dict[Path, str] = {}
    index_lines = ["# Current workstreams", ""]
    if not groups:
        return outputs, CURRENT_INDEX_EMPTY
    for workstream, paths in sorted(groups.items()):
        output = current_dir / f"{slug(workstream)}.md"
        outputs[output] = render_projection(workstream, paths, current_dir)
        index_lines.append(
            f"- [{workstream}]({output.name}) — latest deterministic development state"
        )
    return outputs, "\n".join(index_lines) + "\n"


def refresh(root: Path) -> None:
    ensure_bundle(root)
    current_dir = root / ".okf" / "current" / "workstreams"
    outputs, index = expected_projections(root)
    for path in current_dir.glob("*.md"):
        if path.name != "index.md" and path not in outputs:
            path.unlink()
    for path, content in outputs.items():
        path.write_text(content, encoding="utf-8")
    (current_dir / "index.md").write_text(index, encoding="utf-8")


def cmd_refresh(args: argparse.Namespace) -> int:
    root = repo_root(Path(args.cwd))
    refresh(root)
    outputs, _ = expected_projections(root)
    print(f"Refreshed {len(outputs)} workstream projection(s).")
    return 0


def frontmatter(text: str) -> dict[str, str]:
    if not text.startswith("---\n"):
        return {}
    end = text.find("\n---\n", 4)
    if end < 0:
        return {}
    result: dict[str, str] = {}
    for line in text[4:end].splitlines():
        if line.startswith(" ") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        result[key.strip()] = value.strip()
    return result


def check_append_only(root: Path, base: str) -> list[str]:
    errors: list[str] = []
    if (
        run(
            ["git", "rev-parse", "--verify", f"{base}^{{commit}}"],
            root,
            check=False,
        ).returncode
        != 0
    ):
        return [f"cannot resolve append-only comparison base: {base}"]
    proc = run(
        ["git", "ls-tree", "-r", "--name-only", base, "--", ".okf/workstreams"],
        root,
        check=False,
    )
    for relative in sorted(
        line
        for line in proc.stdout.splitlines()
        if "/runs/" in line and line.endswith(".md")
    ):
        path = root / relative
        if not path.is_file():
            errors.append(f"append-only run record deleted: {relative}")
            continue
        base_content = run(["git", "show", f"{base}:{relative}"], root, check=False)
        if base_content.returncode != 0:
            errors.append(f"cannot read base run record: {relative}")
            continue
        if path.read_text(encoding="utf-8") != base_content.stdout:
            errors.append(f"append-only run record modified: {relative}")
    return errors


def check_bundle(root: Path) -> list[str]:
    errors: list[str] = []
    okf = root / ".okf"
    if not okf.is_dir():
        return ["missing .okf/ bundle; run scripts/okf-memory.py init"]
    for required in [
        okf / "index.md",
        okf / "workstreams" / "index.md",
        okf / "current" / "workstreams" / "index.md",
    ]:
        if not required.is_file():
            errors.append(f"missing required OKF index: {required.relative_to(root)}")
    run_paths = sorted((okf / "workstreams").glob("*/runs/**/*.md"))
    for path in run_paths:
        meta = frontmatter(path.read_text(encoding="utf-8"))
        if meta.get("type") != "Development Run":
            errors.append(f"{path.relative_to(root)}: type must be Development Run")
        for key in [
            "workstream_id",
            "started_at",
            "ended_at",
            "branch",
            "start_commit",
            "observed_head",
            "history_relation",
        ]:
            if key not in meta:
                errors.append(f"{path.relative_to(root)}: missing {key}")
        if not RUN_NAME_RE.fullmatch(path.name):
            errors.append(f"{path.relative_to(root)}: invalid immutable run filename")
        expected_hash = hashlib.sha256(
            path.read_text(encoding="utf-8").encode()
        ).hexdigest()[:12]
        if not path.name.endswith(f"-run-{expected_hash}.md"):
            errors.append(
                f"{path.relative_to(root)}: filename hash does not match content"
            )
    expected, expected_index = expected_projections(root)
    current_dir = okf / "current" / "workstreams"
    actual_projection_paths = {
        path for path in current_dir.glob("*.md") if path.name != "index.md"
    }
    if actual_projection_paths != set(expected):
        missing = set(expected) - actual_projection_paths
        extra = actual_projection_paths - set(expected)
        for path in sorted(missing):
            errors.append(f"missing generated projection: {path.relative_to(root)}")
        for path in sorted(extra):
            errors.append(f"unexpected generated projection: {path.relative_to(root)}")
    for path, content in expected.items():
        if path.exists() and path.read_text(encoding="utf-8") != content:
            errors.append(
                f"stale generated projection: {path.relative_to(root)}; run refresh"
            )
    index_path = current_dir / "index.md"
    if index_path.exists() and index_path.read_text(encoding="utf-8") != expected_index:
        errors.append(
            f"stale generated projection index: {index_path.relative_to(root)}; run refresh"
        )
    return errors


def cmd_check(args: argparse.Namespace) -> int:
    root = repo_root(Path(args.cwd))
    errors = check_bundle(root)
    if args.base:
        errors.extend(check_append_only(root, args.base))
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("OKF repository memory check passed.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cwd", default=".", help="path inside the Git repository")
    subparsers = parser.add_subparsers(dest="command_name", required=True)
    subparsers.add_parser("init", help="initialize the tracked .okf bundle")
    start = subparsers.add_parser(
        "start", help="start a local development-memory session"
    )
    start.add_argument(
        "--workstream", help="stable ID, preferably issue-<number> for O3K work"
    )
    execute = subparsers.add_parser(
        "exec", help="run a validation command and record its receipt"
    )
    execute.add_argument("command", nargs=argparse.REMAINDER)
    for name in ["checkpoint", "end"]:
        command = subparsers.add_parser(
            name, help=f"{name} the current development-memory session"
        )
        command.add_argument(
            "--force",
            action="store_true",
            help="emit a record even without observed activity",
        )
    subparsers.add_parser(
        "refresh", help="regenerate deterministic current projections"
    )
    check = subparsers.add_parser(
        "check", help="validate the OKF bundle and generated projections"
    )
    check.add_argument(
        "--base", help="Git ref whose existing run records must remain byte-identical"
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command_name == "init":
            return cmd_init(args)
        if args.command_name == "start":
            return cmd_start(args)
        if args.command_name == "exec":
            return cmd_exec(args)
        if args.command_name == "checkpoint":
            return cmd_checkpoint(args)
        if args.command_name == "end":
            return cmd_end(args)
        if args.command_name == "refresh":
            return cmd_refresh(args)
        if args.command_name == "check":
            return cmd_check(args)
    except (RuntimeError, OSError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
