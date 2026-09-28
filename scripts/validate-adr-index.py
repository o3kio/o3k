#!/usr/bin/env python3
"""
validate-adr-index.py

Validates ADR index integrity, lifecycle states, supersession links, affected-service metadata,
duplicate ADR numbers, broken links in docs/adr and docs/specs, normative source ownership,
and CI detection of contradictory summaries in summary documents.

Usage:
    python3 scripts/validate-adr-index.py [--update-index] [--root REPO_ROOT]
"""

import argparse
import pathlib
import re
import sys
import urllib.parse

ALLOWED_STATUSES = {"draft", "proposed", "accepted", "rejected", "superseded"}


def slugify(text: str) -> str:
    text = text.lower()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[\s_]+", "-", text)
    return text.strip("-")


def parse_adr_file(path: pathlib.Path):
    text = path.read_text(encoding="utf-8")
    filename = path.name

    # Check filename format: ADR-XXXX-description.md
    fn_match = re.fullmatch(r"ADR-(\d{4})-(.+)\.md", filename)
    if not fn_match:
        raise ValueError(f"Invalid ADR filename format: {filename} (expected ADR-XXXX-description.md)")

    number = fn_match.group(1)
    adr_id = f"ADR-{number}"

    # Heading check
    heading_m = re.search(r"^#\s+(ADR-\d{4})\b(?:[:\s—-]+(.*))?$", text, re.MULTILINE)
    if not heading_m:
        raise ValueError(f"{filename}: Top heading must start with '# ADR-XXXX'")
    heading_id = heading_m.group(1)
    if heading_id != adr_id:
        raise ValueError(f"{filename}: Heading ID {heading_id} does not match filename ID {adr_id}")
    heading_title = heading_m.group(2).strip() if heading_m.group(2) else ""

    # Status check
    status_m = re.search(r"^Status:\s*(.+)$", text, re.MULTILINE | re.IGNORECASE)
    if not status_m:
        sec = re.search(r"^##\s+Status\s*\n+([^\n#]+)", text, re.MULTILINE | re.IGNORECASE)
        if sec:
            raw_status = sec.group(1).strip()
        else:
            raise ValueError(f"{filename}: Missing Status metadata header")
    else:
        raw_status = status_m.group(1).strip()

    first_word = raw_status.split()[0].rstrip(".").lower()
    if first_word not in ALLOWED_STATUSES:
        raise ValueError(f"{filename}: Invalid status '{raw_status}' (must begin with one of {ALLOWED_STATUSES})")

    # Date check
    date_m = re.search(r"^Date:\s*(.+)$", text, re.MULTILINE | re.IGNORECASE)
    date = date_m.group(1).strip() if date_m else ""

    # Supersedes check
    supersedes = []
    sup_m = re.search(r"^Supersedes:\s*(.+)$", text, re.MULTILINE | re.IGNORECASE)
    if sup_m and sup_m.group(1).strip().lower() != "none":
        supersedes = re.findall(r"ADR-\d{4}", sup_m.group(1))

    # Superseded-by check
    superseded_by = []
    supby_m = re.search(r"^Superseded-by:\s*(.+)$", text, re.MULTILINE | re.IGNORECASE)
    if supby_m and supby_m.group(1).strip().lower() != "none":
        superseded_by = re.findall(r"ADR-\d{4}", supby_m.group(1))

    # Affected services check
    aff_m = re.search(r"^(Affected services?|Affected-services?|Services?|Components?|Scope):\s*(.+)$", text, re.MULTILINE | re.IGNORECASE)
    if not aff_m or not aff_m.group(2).strip():
        raise ValueError(f"{filename}: Missing or empty Affected-services metadata")
    affected_services = [s.strip() for s in aff_m.group(2).split(",") if s.strip()]

    return {
        "id": adr_id,
        "number": number,
        "filename": filename,
        "path": path,
        "title": heading_title,
        "status_raw": raw_status,
        "status": first_word.capitalize(),
        "date": date,
        "supersedes": supersedes,
        "superseded_by": superseded_by,
        "affected_services": affected_services,
        "text": text,
    }


def validate_adr_dir(adr_dir: pathlib.Path):
    adr_files = sorted(list(adr_dir.glob("ADR-*.md")))
    if not adr_files:
        raise ValueError(f"No ADR files found in {adr_dir}")

    records = {}

    for path in adr_files:
        rec = parse_adr_file(path)
        adr_id = rec["id"]
        if adr_id in records:
            raise ValueError(f"Duplicate ADR number detected: {adr_id} ({path.name} and {records[adr_id]['filename']})")
        records[adr_id] = rec

    # Validate supersession links and cycles
    for adr_id, rec in records.items():
        for target in rec["supersedes"]:
            if target not in records:
                raise ValueError(f"{rec['filename']}: Supersedes link points to non-existent ADR '{target}'")
        for target in rec["superseded_by"]:
            if target not in records:
                raise ValueError(f"{rec['filename']}: Superseded-by link points to non-existent ADR '{target}'")

        if rec["status"] == "Superseded" and not rec["superseded_by"]:
            raise ValueError(f"{rec['filename']}: Status is Superseded but Superseded-by metadata is empty")

    # Cycle detection follows the canonical forward relation only.  The
    # metadata is intentionally bidirectional: a successor may declare
    # ``Supersedes: ADR-xxxx`` while the predecessor records the reciprocal
    # ``Superseded-by: ADR-yyyy``.  Traversing both fields treats every valid
    # reciprocal pair as a false cycle.
    visited = set()

    def visit(adr_id, stack):
        if adr_id in stack:
            cycle = " -> ".join(stack[stack.index(adr_id) :] + [adr_id])
            raise ValueError(f"ADR supersession cycle detected: {cycle}")
        if adr_id in visited:
            return
        stack.append(adr_id)
        for target in records[adr_id]["supersedes"]:
            visit(target, stack)
        stack.pop()
        visited.add(adr_id)

    for adr_id in records:
        visit(adr_id, [])

    return records


def generate_adr_index_table(records: dict) -> str:
    lines = [
        "## ADR index",
        "",
        "| ADR | Subject | Status | Affected Services |",
        "| --- | --- | --- | --- |",
    ]
    for adr_id, rec in sorted(records.items()):
        title = rec["title"].replace("|", "\\|")
        status = rec["status"]
        services = ", ".join(rec["affected_services"])
        link = f"[{rec['id']}]({rec['filename']})"
        lines.append(f"| {link} | {title} | {status} | {services} |")
    return "\n".join(lines)


def validate_or_update_index_file(repo_root: pathlib.Path, records: dict, update: bool = False):
    readme_path = repo_root / "docs" / "adr" / "README.md"
    if not readme_path.exists():
        raise ValueError(f"ADR index document missing: {readme_path}")

    text = readme_path.read_text(encoding="utf-8")
    new_table = generate_adr_index_table(records)

    # Replace or append ## ADR index section
    if "## ADR index" in text:
        prefix, rest = text.split("## ADR index", 1)
        next_sec_m = re.search(r"^(##\s+[^\n]+)", rest, re.MULTILINE)
        if next_sec_m:
            sec_body, suffix = rest[: next_sec_m.start()], rest[next_sec_m.start() :]
        else:
            sec_body, suffix = rest, ""
        updated_text = prefix.rstrip() + "\n\n" + new_table + "\n\n" + suffix.lstrip()
    elif "## Governance entrypoints" in text:
        prefix, rest = text.split("## Governance entrypoints", 1)
        next_sec_m = re.search(r"^(##\s+[^\n]+)", rest, re.MULTILINE)
        if next_sec_m:
            sec_body, suffix = rest[: next_sec_m.start()], rest[next_sec_m.start() :]
        else:
            sec_body, suffix = rest, ""
        updated_text = prefix.rstrip() + "\n\n" + new_table + "\n\n" + suffix.lstrip()
    else:
        updated_text = text.rstrip() + "\n\n" + new_table + "\n"

    if update:
        readme_path.write_text(updated_text, encoding="utf-8")
        print(f"Updated ADR index table in {readme_path}")
    else:
        for adr_id, rec in records.items():
            if rec["filename"] not in text:
                raise ValueError(f"{readme_path}: ADR file '{rec['filename']}' ({adr_id}) is not referenced in the ADR index")


def validate_broken_links(repo_root: pathlib.Path):
    search_dirs = [repo_root / "docs" / "adr", repo_root / "docs" / "specs"]
    md_files = []
    for d in search_dirs:
        if d.exists():
            md_files.extend(d.glob("*.md"))

    broken = []
    for md_file in md_files:
        text = md_file.read_text(encoding="utf-8")
        links = re.findall(r"\[([^\]]+)\]\(([^)]+)\)", text)
        for title, link in links:
            link = link.strip()
            if link.startswith(("http://", "https://", "mailto:", "ftp://")):
                continue
            parts = link.split("#", 1)
            path_part = parts[0]
            anchor_part = parts[1] if len(parts) > 1 else None

            if path_part == "":
                target_path = md_file
            else:
                path_unquoted = urllib.parse.unquote(path_part)
                target_path = (md_file.parent / path_unquoted).resolve()

            if not target_path.exists():
                broken.append(f"{md_file.relative_to(repo_root)}: broken link '{link}' -> {target_path}")
                continue

            if anchor_part and target_path.suffix == ".md":
                target_text = target_path.read_text(encoding="utf-8")
                headings = re.findall(r"^#+\s+(.+)$", target_text, re.MULTILINE)
                slugs = [slugify(h) for h in headings]
                if slugify(anchor_part) not in slugs and anchor_part.lower() not in [h.lower() for h in headings]:
                    broken.append(f"{md_file.relative_to(repo_root)}: broken anchor '{link}' -> anchor '{anchor_part}' not found in {target_path.name}")

    if broken:
        raise ValueError("Broken markdown links detected:\n" + "\n".join(broken))


def validate_normative_sources(repo_root: pathlib.Path):
    ns_file = repo_root / "docs" / "NORMATIVE_SOURCES.md"
    if not ns_file.exists():
        raise ValueError(f"Missing normative sources authority file: {ns_file}")

    text = ns_file.read_text(encoding="utf-8")
    table_m = re.search(r"## Authority map\s*\n\s*\|[^\n]+\|\s*\n\s*\|[^\n]+\|\s*\n([\s\S]*?)(?=\n\n|\n##|\Z)", text)
    if not table_m:
        raise ValueError(f"{ns_file}: Failed to parse ## Authority map table")

    rows = table_m.group(1).strip().splitlines()
    subjects_seen = set()
    summary_docs_found = set()

    for row in rows:
        parts = [p.strip() for p in row.split("|")[1:-1]]
        if len(parts) < 3:
            continue
        subject, normative_srcs, summary_docs = parts[0], parts[1], parts[2]

        if subject in subjects_seen:
            raise ValueError(f"{ns_file}: Duplicate subject in authority map: '{subject}'")
        subjects_seen.add(subject)

        norm_files = re.findall(r"`([^`]+)`", normative_srcs)
        sum_files = re.findall(r"`([^`]+)`", summary_docs)

        for nf in norm_files:
            target = repo_root / nf
            if not target.exists():
                raise ValueError(f"{ns_file}: Normative source file not found: '{nf}'")
        for sf in sum_files:
            target = repo_root / sf
            if not target.exists():
                raise ValueError(f"{ns_file}: Summary document file not found: '{sf}'")
            summary_docs_found.add(sf)

        overlap = set(norm_files).intersection(set(sum_files))
        if overlap:
            raise ValueError(f"{ns_file}: File(s) listed as both normative and summary for subject '{subject}': {overlap}")

    return summary_docs_found


def validate_summary_documents(repo_root: pathlib.Path, summary_docs: set):
    errors = []
    for doc_name in summary_docs:
        p = repo_root / doc_name
        if not p.exists():
            continue
        text = p.read_text(encoding="utf-8")

        # Rule A: Unqualified PostgreSQL support claim
        pg_unqualified = re.findall(r"(?i)\bpostgresql\s+(?:is\s+)?supported\b", text)
        for match in pg_unqualified:
            snippet_idx = text.lower().find(match.lower())
            if snippet_idx != -1:
                ctx = text[max(0, snippet_idx - 60) : min(len(text), snippet_idx + 60)].lower()
                if not any(k in ctx for k in ["not", "planned", "target", "unsupported", "future", "until"]):
                    errors.append(f"{doc_name}: Unqualified claim of PostgreSQL support: '{match}'")

        # Rule B: Unqualified 50 MB footprint claim
        fp_matches = re.finditer(r"(?i)\b50\s*mb\b", text)
        for m in fp_matches:
            ctx = text[max(0, m.start() - 50) : min(len(text), m.end() + 50)].lower()
            if not any(k in ctx for k in ["target", "approx", "goal", "aim", "estimate", "profile"]):
                errors.append(f"{doc_name}: 50 MB footprint claim missing target qualifier: '{ctx.strip()}'")

    if errors:
        raise ValueError("Contradictory summary document claims detected:\n" + "\n".join(errors))


def main():
    parser = argparse.ArgumentParser(description="Validate ADR index and normative governance")
    parser.add_argument("--root", type=str, default=".", help="Path to repository root")
    parser.add_argument("--update-index", action="store_true", help="Update ADR index table in docs/adr/README.md")
    args = parser.parse_args()

    repo_root = pathlib.Path(args.root).resolve()
    adr_dir = repo_root / "docs" / "adr"

    print("Validating ADR directory metadata...")
    records = validate_adr_dir(adr_dir)

    print(f"Validating ADR index document ({len(records)} ADR records)...")
    validate_or_update_index_file(repo_root, records, update=args.update_index)

    print("Validating markdown links in docs/adr and docs/specs...")
    validate_broken_links(repo_root)

    print("Validating normative sources authority map...")
    summary_docs = validate_normative_sources(repo_root)

    print("Checking summary documents for contradictory claims...")
    validate_summary_documents(repo_root, summary_docs)

    print(f"Clean validation: {len(records)} ADRs verified, acyclic supersession links, valid metadata, 0 broken links, normative authority verified.")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Validation failed: {e}", file=sys.stderr)
        sys.exit(1)
