#!/usr/bin/env python3
"""Structure-only inspection of Claude Code session files (REQUIREMENTS.md section 19).

THE MAINTAINER RUNS THIS SCRIPT AND PASTES THE OUTPUT BACK. The coding agent must not run it and
must not open real session files.

What it prints (JSON on stdout):
  * the shape of the directory tree, with UUIDs and unknown names replaced by placeholders;
  * per record type: counts and the set of JSON key paths with value types. Key names that are not
    plain identifiers are replaced by "<key>". An object whose set of distinct keys (over the whole
    corpus) grows beyond a small threshold is treated as data-keyed (server names, project names,
    file names, ...): ALL of its keys are replaced by "<key>", whatever order the records come in.
    Depth is limited;
  * the values of an explicit allowlist of low-cardinality discriminator fields, and only when the
    value is a short token ([A-Za-z0-9_.:-]{1,32}); anything else is printed as "<other>";
  * a table of combinations of the signals that distinguish genuine user prompts from tool results
    and meta records (booleans, enum values, content *kinds*, never content). A string that starts
    with an XML-ish tag is labelled with an entry of the script's own KNOWN_TAGS table or as
    "<other-tag>"; no tag name is ever copied from the text;
  * numeric facts (line counts, sizes, ordering of timestamps, cwd changes). No strings from record
    bodies, no paths, no session ids, no prompts, no titles and no tool data are ever printed.

Usage:  python3 scripts/inspect-session-schema.py [--root DIR] [--policy]
        DIR defaults to $CLAUDE_CONFIG_DIR, then ~/.claude.   --policy prints the allowlists and exits.
Read-only: it opens files for reading only.
"""
import argparse
import collections
import json
import os
import re
import sys

MAX_DEPTH = 4                      # record -> message -> content[] -> type
# More distinct keys than this under one object (counted over all records of a type) => data-keyed.
MAP_KEY_THRESHOLD = 12
# The record's own top level is the record schema; it gets a higher limit but is still bounded.
ROOT_KEY_THRESHOLD = 64
MASK = "<key>"
MAX_LINE_BYTES = 16 * 1024 * 1024
IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,40}$")
TOKEN = re.compile(r"^[A-Za-z0-9_.:\-]{1,32}$")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
AGENT = re.compile(r"^agent-[0-9a-f]+\.(jsonl|json)$")
LEADING_TAG = re.compile(r"^<([a-z][a-z0-9_-]{0,40})[ >]")
TS_KEEP = set("-:.TZ+")
TS_MAX = 40

# Fields whose *values* may be printed (when they are short tokens).
DISCRIMINATORS = {
    "type", "subtype", "message.role", "message.content[].type", "isMeta", "isSidechain",
    "isCompactSummary", "version", "promptSource", "turnOrigin", "entrypoint", "userType",
    "permissionMode", "operation", "sessionKind", "origin",
}
KNOWN_DIRS = {"projects", "subagents", "tool-results", "memory"}
KNOWN_FILES = {".session-aliases"}
KNOWN_EXT = {".jsonl", ".json", ".md", ".txt"}
# Leading XML-ish tags of synthetic "user" strings that may be named (anything else is "<other-tag>").
KNOWN_TAGS = {
    "task-notification", "local-command-caveat", "command-name", "command-message", "command-args",
    "local-command-stdout", "local-command-stderr", "bash-input", "bash-stdout", "bash-stderr",
    "system-reminder", "artifact-content-authored-by-others", "pasted_content", "user-prompt-submit-hook",
}
# The only tag labels that can ever be printed: built from the constant above, never from input text.
TAG_LABELS = {t: "string:<%s>" % t for t in KNOWN_TAGS}
OTHER_TAG_LABEL = "string:<other-tag>"


def policy():
    return {
        "discriminator_fields": sorted(DISCRIMINATORS),
        "discriminator_value_pattern": TOKEN.pattern,
        "key_name_pattern": IDENT.pattern,
        "key_mask": MASK,
        "map_key_threshold": MAP_KEY_THRESHOLD,
        "root_key_threshold": ROOT_KEY_THRESHOLD,
        "max_depth": MAX_DEPTH,
        "known_dir_names": sorted(KNOWN_DIRS),
        "known_file_names": sorted(KNOWN_FILES),
        "known_synthetic_tags": sorted(KNOWN_TAGS),
        "other_tag_label": OTHER_TAG_LABEL,
        "timestamp_shape": "digits -> 9, characters in '-:.TZ+' kept, anything else -> x, first %d characters" % TS_MAX,
    }


def jtype(v):
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, (int, float)):
        return "number"
    if isinstance(v, str):
        return "string"
    if isinstance(v, list):
        return "array"
    return "object"


def safe_value(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return "<number>"
    if isinstance(v, str) and TOKEN.match(v):
        return v
    return "<other>"


class Node:
    """One position in the key tree of a record type. Keys are stored only as printable labels."""
    __slots__ = ("types", "keys", "items", "is_map")

    def __init__(self):
        self.types = collections.Counter()
        self.keys = {}        # label (an identifier key name, or MASK) -> Node
        self.items = None     # Node for list elements
        self.is_map = False   # data-keyed: every key is MASK from now on


def named_keys(node):
    return [k for k in node.keys if k != MASK]


def merge(dst, src, limit):
    """Fold the subtree `src` into `dst` (both describe the same masked position)."""
    dst.types.update(src.types)
    for label, sub in src.keys.items():
        target = MASK if dst.is_map else label
        merge(dst.keys.setdefault(target, Node()), sub, MAP_KEY_THRESHOLD)
    if src.items is not None:
        if dst.items is None:
            dst.items = Node()
        merge(dst.items, src.items, MAP_KEY_THRESHOLD)
    if src.is_map or len(named_keys(dst)) > limit:
        collapse(dst)


def collapse(node):
    """Mark `node` as data-keyed and fold every named child into the single MASK child."""
    node.is_map = True
    named = [(k, node.keys.pop(k)) for k in named_keys(node)]
    if not named:
        return
    masked = node.keys.setdefault(MASK, Node())
    for _, sub in named:
        merge(masked, sub, MAP_KEY_THRESHOLD)


def child(node, key, limit):
    if not IDENT.match(key) or node.is_map:
        return node.keys.setdefault(MASK, Node())
    if key not in node.keys and len(named_keys(node)) >= limit:
        collapse(node)  # this key would be one too many: the object is keyed by data
        return node.keys.setdefault(MASK, Node())
    return node.keys.setdefault(key, Node())


class Stats:
    def __init__(self):
        self.records = collections.Counter()
        self.trees = collections.defaultdict(Node)                                                   # type -> key tree
        self.discr = collections.defaultdict(collections.Counter)                                    # field -> value -> n
        self.user_combo = collections.Counter()
        self.has_field = collections.defaultdict(collections.Counter)                                # type -> field -> n
        self.numbers = collections.Counter()
        self.ts_shapes = collections.Counter()
        self.dirs = collections.Counter()


def walk(stats, node, value, raw_path, depth):
    """`raw_path` uses the real key names but is only compared with DISCRIMINATORS, never printed."""
    node.types[jtype(value)] += 1
    if raw_path in DISCRIMINATORS and not isinstance(value, (dict, list)):
        stats.discr[raw_path][safe_value(value)] += 1
    if depth >= MAX_DEPTH:
        return
    if isinstance(value, dict):
        limit = ROOT_KEY_THRESHOLD if depth == 0 else MAP_KEY_THRESHOLD
        for k, v in value.items():
            walk(stats, child(node, k, limit), v, f"{raw_path}.{k}" if raw_path else k, depth + 1)
    elif isinstance(value, list):
        if node.items is None:
            node.items = Node()
        for item in value[:50]:
            walk(stats, node.items, item, f"{raw_path}[]", depth + 1)


def flatten(node, prefix, out):
    for label, sub in sorted(node.keys.items()):
        path = f"{prefix}.{label}" if prefix else label
        out[path] = dict(sorted(sub.types.items()))
        flatten(sub, path, out)
    if node.items is not None and prefix:
        path = f"{prefix}[]"
        out[path] = dict(sorted(node.items.types.items()))
        flatten(node.items, path, out)
    return out


def timestamp_shape(ts):
    return "".join("9" if c in "0123456789" else (c if c in TS_KEEP else "x") for c in ts[:TS_MAX])


def content_kind(content):
    if isinstance(content, str):
        m = LEADING_TAG.match(content)
        if not m:
            return "string:plain"
        return TAG_LABELS.get(m.group(1), OTHER_TAG_LABEL)
    if isinstance(content, list):
        kinds = sorted({(i.get("type") if isinstance(i, dict) else "?") for i in content})
        return "array[" + ",".join(safe_value(k) for k in kinds) + "]"
    return jtype(content)


def user_signature(rec):
    msg = rec.get("message") if isinstance(rec.get("message"), dict) else {}
    return (
        f"isMeta={safe_value(rec.get('isMeta', False))}",
        f"isSidechain={safe_value(rec.get('isSidechain', False))}",
        f"isCompactSummary={safe_value(rec.get('isCompactSummary', False))}",
        f"promptSource={safe_value(rec['promptSource']) if 'promptSource' in rec else '<absent>'}",
        f"turnOrigin={safe_value(rec['turnOrigin']) if 'turnOrigin' in rec else '<absent>'}",
        f"toolUseResult={'toolUseResult' in rec}",
        f"content={content_kind(msg.get('content'))}",
    )


def dir_pattern(rel_parts):
    out = []
    for i, p in enumerate(rel_parts):
        if UUID.match(p) or UUID.match(os.path.splitext(p)[0]):
            ext = os.path.splitext(p)[1]
            out.append("<uuid>" + (ext if ext in KNOWN_EXT else ""))
        elif AGENT.match(p):
            out.append("agent-<id>" + os.path.splitext(p)[1])
        elif p in KNOWN_DIRS or p in KNOWN_FILES:
            out.append(p)
        elif i == 1 and rel_parts[0] == "projects":
            out.append("<encoded-cwd>")
        else:
            ext = os.path.splitext(p)[1]
            out.append("<name>" + (ext if ext in KNOWN_EXT else ""))
    return "/".join(out)


def inspect_file(stats, path, stem, kind):
    st = {"lines": 0, "bad": 0, "oversized": 0, "ts_unordered": False, "ts_first_not_min": False,
          "ts_last_not_max": False, "sid_eq_stem": 0, "sid_other": 0, "cwds": [], "types_with_cwd": set()}
    ts_list = []
    last_ts = None
    with open(path, "rb") as fh:
        for raw in fh:
            st["lines"] += 1
            if len(raw) > MAX_LINE_BYTES:
                st["oversized"] += 1
                continue
            try:
                rec = json.loads(raw)
            except ValueError:
                st["bad"] += 1
                continue
            if not isinstance(rec, dict):
                st["bad"] += 1
                continue
            rtype = safe_value(rec.get("type")) if "type" in rec else "<no-type>"
            stats.records[(kind, rtype)] += 1
            for f in ("sessionId", "cwd", "timestamp", "uuid", "agentId", "parentUuid"):
                if f in rec:
                    stats.has_field[rtype][f] += 1
            walk(stats, stats.trees[rtype], rec, "", 0)
            sid = rec.get("sessionId")
            if isinstance(sid, str):
                st["sid_eq_stem" if sid == stem else "sid_other"] += 1
            ts = rec.get("timestamp")
            if isinstance(ts, str):
                stats.ts_shapes[timestamp_shape(ts)] += 1
                ts_list.append(ts)
                if last_ts is not None and ts < last_ts:
                    st["ts_unordered"] = True
                last_ts = ts
            cwd = rec.get("cwd")
            if isinstance(cwd, str):
                st["types_with_cwd"].add(rtype)
                if not st["cwds"] or st["cwds"][-1] != cwd:
                    st["cwds"].append(cwd)
            if rtype == "user":
                stats.user_combo[user_signature(rec)] += 1
    if ts_list:
        st["ts_first_not_min"] = ts_list[0] != min(ts_list)
        st["ts_last_not_max"] = ts_list[-1] != max(ts_list)
    n = stats.numbers
    n[f"{kind}.files"] += 1
    n[f"{kind}.lines"] += st["lines"]
    n[f"{kind}.malformed_lines"] += st["bad"]
    n[f"{kind}.oversized_lines"] += st["oversized"]
    n[f"{kind}.files_with_unordered_timestamps"] += st["ts_unordered"]
    n[f"{kind}.files_where_first_timestamp_is_not_min"] += st["ts_first_not_min"]
    n[f"{kind}.files_where_last_timestamp_is_not_max"] += st["ts_last_not_max"]
    n[f"{kind}.files_with_multiple_cwds"] += len(set(st["cwds"])) > 1
    n[f"{kind}.files_with_no_cwd"] += not st["cwds"]
    n[f"{kind}.records_with_sessionId_equal_to_file_stem"] += st["sid_eq_stem"]
    n[f"{kind}.records_with_sessionId_different_from_file_stem"] += st["sid_other"]
    n[f"{kind}.max_file_bytes"] = max(n[f"{kind}.max_file_bytes"], os.path.getsize(path))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", help="Claude config directory (default $CLAUDE_CONFIG_DIR or ~/.claude)")
    ap.add_argument("--policy", action="store_true", help="print the allowlists and exit")
    args = ap.parse_args()
    if args.policy:
        json.dump(policy(), sys.stdout, indent=2, sort_keys=True)
        print()
        return 0
    root = args.root or os.environ.get("CLAUDE_CONFIG_DIR") or os.path.join(os.path.expanduser("~"), ".claude")
    projects = os.path.join(root, "projects")
    if not os.path.isdir(projects):
        print("no projects directory found at the given root", file=sys.stderr)
        return 1
    stats = Stats()
    for dirpath, dirnames, filenames in os.walk(projects, followlinks=False):
        dirnames.sort()
        rel = os.path.relpath(dirpath, root).split(os.sep)
        for fn in sorted(filenames):
            pattern = dir_pattern(rel + [fn])
            stats.dirs[pattern] += 1
            if not fn.endswith(".jsonl"):
                continue
            # Sessions: projects/<enc>/<uuid>.jsonl ; sidechains: projects/<enc>/<uuid>/subagents/agent-*.jsonl
            depth = len(rel)  # includes "projects"
            full = os.path.join(dirpath, fn)
            if depth == 2:
                inspect_file(stats, full, os.path.splitext(fn)[0], "session")
            elif depth == 4 and rel[-1] == "subagents":
                inspect_file(stats, full, rel[2], "subagent")
    out = {
        "note": "structure only: key paths, types, allowlisted discriminator values and counts. No content.",
        "policy": policy(),
        "directory_patterns": dict(sorted(stats.dirs.items())),
        "record_counts": {f"{k}:{t}": n for (k, t), n in sorted(stats.records.items())},
        "numbers": dict(sorted(stats.numbers.items())),
        "discriminator_values": {f: dict(sorted(c.items())) for f, c in sorted(stats.discr.items())},
        "fields_present_by_record_type": {t: dict(sorted(c.items())) for t, c in sorted(stats.has_field.items())},
        "timestamp_shapes": dict(sorted(stats.ts_shapes.items())),
        "user_record_signatures": [{"signature": list(sig), "count": n} for sig, n in stats.user_combo.most_common()],
        "key_paths_by_record_type": {t: flatten(tree, "", {}) for t, tree in sorted(stats.trees.items())},
    }
    json.dump(out, sys.stdout, indent=1, sort_keys=True)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
