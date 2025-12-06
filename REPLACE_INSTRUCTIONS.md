This repository contains a helper script and instructions to replace the remote `main` branch with this workspace snapshot.

Files added
- `scripts/replace_main_with_workspace.sh` — safe helper script that:
  - fetches `origin` (or a supplied remote),
  - creates a timestamped backup branch pointing at the remote `main` (e.g. `backup/origin-main-20250101-123000`),
  - initializes git if not present, stages all files, and commits them (if there are changes),
  - by default runs in `--dry-run` mode and will not perform a destructive push,
  - when run with `--force` will perform a destructive `git push --force` to `origin/main`.

Why this is safer
- The script creates a backup branch that preserves the prior `origin/main` pointer so you can recover if needed.
- The default behavior is a dry-run. You must explicitly pass `--force` to overwrite remote history.

How to use
1) Inspect the script: `less scripts/replace_main_with_workspace.sh`
2) Make it executable (once):
   chmod +x scripts/replace_main_with_workspace.sh
3) Run a dry-run to see what would happen:
   ./scripts/replace_main_with_workspace.sh --dry-run
4) If you're happy and you *intend* to replace the remote `main` branch, run:
   ./scripts/replace_main_with_workspace.sh --force --commit-message "Replace repo with v0.1.6 snapshot"

Safer alternative (recommended if others collaborate):
- Instead of `--force`, push to a review branch and open a Pull Request:
  ./scripts/replace_main_with_workspace.sh
  (the script will push to a `replace-with-v0.1.6-<timestamp>` branch when not run with --force)

Recovery notes
- The backup branch pushed is named `backup/origin-main-<timestamp>` and points at the previous `origin/main` commit.
- To restore the old main, on a machine with git access:
  git fetch origin
  git checkout backup/origin-main-<timestamp>
  git branch -M main
  git push -f origin main

Risks
- A forced push rewrites remote history. If other developers have based work on the old history, they will have to rebase/force-update their clones.
- Double-check CI, GH Actions, and any protected-branch rules before forcing the push.

If you want, I can also create a small convenience Makefile target or provide the exact single-line zsh commands to run locally. Please confirm how you'd like to proceed.