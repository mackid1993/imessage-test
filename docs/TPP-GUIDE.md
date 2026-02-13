# TPP Guide — Technical Project Plans

## What is a TPP?

A TPP transfers expertise, not just instructions. It reads like having the previous engineer sitting next to you. It captures what was tried, what failed, what was learned, and what comes next.

## File conventions

- Active TPPs live in `_todo/` with date-prefixed filenames: `20260213-feature-name.md`
- Completed TPPs move to `_done/` for future reference
- **Max 400 lines.** If a TPP exceeds this, split it into separate tasks.
  - Claude's ReadTool silently truncates files over ~500 lines. The 400-line cap ensures the next session reads the complete plan.

## TPP Template

```markdown
# TPP: Feature Name

## Summary

Short description of the problem (under 10 lines).

## Current Phase

- [x] Research & Planning
- [ ] Write breaking tests
- [ ] Design alternatives
- [ ] Task breakdown
- [ ] Implementation
- [ ] Review & Refinement
- [ ] Final Integration
- [ ] Review

## Required Reading

Files and docs the engineer must study before starting work.
Always include CLAUDE.md. Add specific source files relevant to the task.

## Description

Detailed context about the problem (under 20 lines).

## Tribal Knowledge

- Non-obvious details that save time
- Prior gotchas that tripped up previous sessions
- Relevant functions, file:line references, historical context

## Solutions

### Option A (preferred)

Description with pros/cons and code snippets if helpful.

### Option B (alternative)

Why this was considered and why Option A is better.

## Tasks

- [x] Task 1: Clear deliverable, files to change, verification command
- [ ] Task 2: ...
```

## Phase Definitions

| Phase | What happens |
|-------|-------------|
| **Research & Planning** | Read referenced docs and code, update TPP with findings |
| **Write breaking tests** | Write failing tests first (if applicable — this project has no test suite yet, so this phase may be "write manual verification steps") |
| **Design alternatives** | Generate and critique 2-4 approaches |
| **Task breakdown** | Create specific tasks with verification commands |
| **Implementation** | Work through tasks, update TPP as you go |
| **Review & Refinement** | Review changed code for correctness and gotchas |
| **Final Integration** | Run `make build`, verify compilation, test manually if possible |
| **Review** | Final check, move TPP to `_done/` |

## Rules for updating TPPs

1. **Trim ruthlessly.** Each session must remove redundancy and simplify. No lava-flow documentation.
2. **Accumulate insight, not filler.** Add to Tribal Knowledge when you learn something non-obvious.
3. **Record failures.** When an approach doesn't work, say what was tried and why it failed. This is often more valuable than recording what worked.
4. **Be specific.** Reference files by path and line number. Include exact error messages. Name functions.
5. **Update the phase checklist.** The first thing the next session checks is which phase is current.
6. **Mark tasks done.** Use `[x]` and add brief notes about what was actually done if it differed from the plan.

## Why keep completed TPPs

When a bug surfaces in code built via a TPP, the completed plan tells the next engineer:
- What was tried and rejected (and why)
- Which edge cases were discovered
- What the original design intent was

`_done/` is institutional memory that costs nothing to maintain.
