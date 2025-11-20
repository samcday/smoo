
## Purpose

This document defines the workflow for **Sam**, **GPT‑5**, and **Codex** when collaborating on smoo.

The goal is to keep a clean, comprehensible codebase while safely harnessing LLM acceleration.

## Roles

### Sam
- Final decision‑maker
- Provides architectural direction
- Writes manual commits where needed
- Prepares Codex prompts as **markdown attachment files**

### GPT‑5
- Design reasoning, critique, clarification
- Produces small sketches but **not** large hunks of code
- Helps refine Codex prompts and architecture

### Codex
- Emits large diffs, modules, entire files
- Must follow HACKING.md precisely
- Must produce compilable Rust and pass `cargo build --workspace --locked`

## Process

1. Sam prepares a prompt
2. GPT‑5 reviews the prompt and ensures architectural correctness.
3. Codex is invoked with that prompt.
4. Codex returns a diff or new file.
5. Sam reviews and commits.

## Ground Rules

- Code must be formatted with `rustfmt --edition 2021`.
- Codex output must compile.
- Agents must refer back to **HACKING.md** for protocol, invariants, and architecture.
- Prefer async‑only code; blocking must be justified.
- After changes, return a commit-style summary in 50/80 format with a
  subsystem prefix (e.g. `gadget:`) in the subject:
  * Subject line ≤50 chars.
  * Up to 3 detail lines, each ≤80 chars.
  * Base the summary on the diff vs HEAD (staged + unstaged).

## Notes

This workflow is intentionally strict to maintain project integrity while allowing rapid iteration.
