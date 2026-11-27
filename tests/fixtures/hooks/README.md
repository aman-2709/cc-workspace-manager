# Synthetic Claude Code hook inputs

**Every value here is invented** (REQUIREMENTS.md §19, §21.11). The shapes follow the hook input
schemas of Claude Code 2.1.332 and one live `claude -p` run, recorded in ARCHITECTURE.md §11a: one
file per event `ccwm hook` handles (`<event>[-<variant>].json`), plus inputs it must not send (an
`auth_success` notification, a tool event from inside a subagent).

Every field the hook command skips holds a canary (`SYNTHETIC-*-CANARY`: the prompt, the assistant's
last message, tool input and output, errors, background commands, cron prompts, the title and the
transcript path). `src/claude/hook.rs` checks that none reaches the socket request, and that every
file here is tested.
