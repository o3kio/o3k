"""Classify Rust source lines that are excluded from production builds."""

import re
from pathlib import Path


class RustLexState:
    """Small Rust-aware lexer for cfg(test) item and module scope tracking."""

    def __init__(self):
        self.block_comment_depth = 0
        self.quote = None
        self.raw_hashes = None

    def code(self, line):
        output = []
        i = 0
        while i < len(line):
            if self.block_comment_depth:
                if line.startswith("/*", i):
                    self.block_comment_depth += 1
                    i += 2
                elif line.startswith("*/", i):
                    self.block_comment_depth -= 1
                    i += 2
                else:
                    i += 1
                continue
            if self.raw_hashes is not None:
                terminator = '"' + ("#" * self.raw_hashes)
                if line.startswith(terminator, i):
                    output.append(terminator)
                    i += len(terminator)
                    self.raw_hashes = None
                else:
                    i += 1
                continue
            if self.quote is not None:
                if line[i] == "\\":
                    i += 2
                elif line[i] == self.quote:
                    self.quote = None
                    i += 1
                else:
                    i += 1
                continue
            if line.startswith("//", i):
                break
            if line.startswith("/*", i):
                self.block_comment_depth = 1
                i += 2
                continue
            if line[i] == "'" and not re.match(r"'(?:\\.|[^'\\n])'", line[i:]):
                output.append(line[i])
                i += 1
                continue
            if line[i] in ('"', "'"):
                self.quote = line[i]
                i += 1
                continue
            if line[i] == "r":
                match = re.match(r'r(#+)?"', line[i:])
                if match:
                    self.raw_hashes = len(match.group(1) or "")
                    i += len(match.group(0))
                    continue
            output.append(line[i])
            i += 1
        return "".join(output)


def is_test_only_cfg(attribute):
    inner = attribute[len("#[cfg("):-2].replace(" ", "")
    if inner == "test":
        return True
    return inner.startswith("all(") and re.search(r"(?:all\(|,)test(?:,|\))", inner) is not None


def _is_test_attribute(line):
    stripped = line.strip()
    return (
        stripped.startswith("#[cfg(")
        and stripped.endswith(")]")
        and is_test_only_cfg(stripped)
    )


def classify_rust_lines(lines, dedicated_test=False):
    """Return a bool per line indicating whether it is test-only Rust code."""
    if dedicated_test:
        return [True] * len(lines)

    lexer = RustLexState()
    brace_depth = 0
    test_modules = []
    test_item = None
    pending_test = False
    classified = []
    for line in lines:
        code = lexer.code(line)
        stripped = code.strip()
        is_attribute = stripped.startswith("#[") and stripped.endswith("]")
        if _is_test_attribute(stripped):
            pending_test = True
            classified.append(True)
            continue
        if pending_test and (not stripped or is_attribute):
            classified.append(True)
            continue

        active_test = bool(test_modules) or test_item is not None
        if pending_test and stripped:
            if re.search(r"\bmod\b", stripped) and "{" in stripped:
                test_modules.append({"open_depth": brace_depth + 1})
            else:
                test_item = {"opened": False}
            active_test = True
            pending_test = False
        classified.append(active_test)

        opens = code.count("{")
        closes = code.count("}")
        if test_item is not None:
            if not test_item["opened"] and opens:
                test_item["opened"] = True
                test_item["body_depth"] = brace_depth + 1
            if ";" in code and not test_item["opened"]:
                test_item = None
        brace_depth += opens - closes
        if test_item is not None and test_item["opened"] and brace_depth < test_item["body_depth"]:
            test_item = None
        while test_modules and brace_depth < test_modules[-1]["open_depth"]:
            test_modules.pop()
    return classified


def is_dedicated_test_file(path):
    path = Path(path)
    return path.name == "tests.rs" or "tests" in path.parts
