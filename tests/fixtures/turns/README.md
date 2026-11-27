# Synthetic session records of a turn's end (REQUIREMENTS.md §21.2a)

**Every value here is invented.** Each file is a short session (id `5e55a0b1-…`) with the record
shapes Claude Code 2.1.332 wrote in the O11 runs (ARCHITECTURE.md §11a): Esc during a reply, "No" in a
permission dialog, Esc on the dialog, Esc while an approved tool runs, a normal turn, an approved tool's
result, the records `/clear` writes (`rowSource: "harness"` without an interruption), and an interrupted
turn followed by a finished one. The fixed interruption strings are in them as Claude Code writes them:
`src/claude/parse.rs` checks that the structural rule finds an interruption in exactly the files whose
records carry one, for the same turn, without ever reading message text. A change of Claude Code's
format fails those tests. Canaries in prompts, replies and tool output must never reach ccwm.
