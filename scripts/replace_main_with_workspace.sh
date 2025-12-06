#!/usr/bin/env zsh
# Safe helper to backup remote main and (optionally) force-replace origin/main with current working tree.
# Usage:
#   ./scripts/replace_main_with_workspace.sh [--commit-message "msg"] [--remote <remote>] [--dry-run] [--force]
# Example (dry run):
#   ./scripts/replace_main_with_workspace.sh --dry-run
# Example (perform destructive force push):
#   ./scripts/replace_main_with_workspace.sh --force --commit-message "Replace repo with v0.1.6 snapshot"

set -euo pipefail

# Defaults
REMOTE="origin"
DRY_RUN=true
FORCE=false
COMMIT_MESSAGE="Replace repository content with new project snapshot"

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --remote)
      REMOTE="$2"; shift 2;;
    --commit-message)
      COMMIT_MESSAGE="$2"; shift 2;;
    --dry-run)
      DRY_RUN=true; shift;;
    --force)
      FORCE=true; DRY_RUN=false; shift;;
    -h|--help)
      echo "Usage: $0 [--commit-message \"msg\"] [--remote <remote>] [--dry-run] [--force]"; exit 0;;
    *)
      echo "Unknown arg: $1"; exit 1;;
  esac
done

timestamp() {
  date +%Y%m%d-%H%M%S
}

echo "Running in: $(pwd)"

echo "WARNING: This script can perform a destructive force-push to $REMOTE/main when run with --force."
if [ "$DRY_RUN" = true ]; then
  echo "Mode: DRY RUN (no destructive push will be performed)."
else
  echo "Mode: LIVE (will perform destructive push if --force supplied)."
fi

# Ensure git is available
if ! command -v git >/dev/null 2>&1; then
  echo "git not found in PATH. Install git and retry."; exit 1
fi

# Ensure there is a workspace (pwd assumed to be repo root)
# Check for remote
if ! git remote get-url "$REMOTE" >/dev/null 2>&1; then
  echo "Remote '$REMOTE' not configured."
  read -r "REPLY?Would you like to add https://github.com/Penterep/ptnetinspector.git as '$REMOTE'? (y/N): "
  if [[ "$REPLY" = [Yy]* ]]; then
    git remote add "$REMOTE" https://github.com/Penterep/ptnetinspector.git
    echo "Added remote $REMOTE -> https://github.com/Penterep/ptnetinspector.git"
  else
    echo "Please add a remote named '$REMOTE' and re-run."; exit 1
  fi
fi

# Fetch remote
echo "Fetching from $REMOTE..."
git fetch "$REMOTE"

# Create backup branch name
BACKUP_BRANCH="backup/origin-main-$(timestamp)"

# Create and push backup branch that points to remote/main
if git show-ref --verify --quiet "refs/remotes/$REMOTE/main"; then
  echo "Creating local branch $BACKUP_BRANCH pointing at $REMOTE/main"
  git branch --force "$BACKUP_BRANCH" "$REMOTE/main"
  if [ "$DRY_RUN" = false ]; then
    echo "Pushing backup branch $BACKUP_BRANCH to $REMOTE"
    git push -u "$REMOTE" "$BACKUP_BRANCH"
  else
    echo "DRY RUN: would push $BACKUP_BRANCH to $REMOTE"
  fi
else
  echo "No $REMOTE/main found to backup (remote may be empty). Skipping backup creation."
fi

# Initialize git if needed
if [ ! -d .git ]; then
  echo "No .git found: initializing repository"
  git init
fi

# Add all files and commit
# If there are no changes to commit, skip commit creation.
git add --all
if git diff --staged --quiet && git diff --quiet; then
  echo "No changes to commit (working tree clean). Will not create a new commit."
else
  echo "Creating commit: $COMMIT_MESSAGE"
  git commit -m "$COMMIT_MESSAGE" || true
fi

# Ensure branch is main
git branch -M main

if [ "$DRY_RUN" = true ]; then
  echo "DRY RUN summary:" 
  echo "  - Backup branch: $BACKUP_BRANCH (created locally)"
  echo "  - Would set branch to 'main' and (optionally) force push to $REMOTE/main"
  echo "To perform the destructive push, re-run with --force"
  exit 0
fi

if [ "$FORCE" = true ]; then
  echo "Performing destructive force-push to $REMOTE/main"
  git push -u "$REMOTE" main --force
  echo "Force-push complete. Remote main now points to local main."
else
  echo "Safety: Not performing force push because --force flag not present."
  echo "Pushing to a non-destructive branch 'replace-with-v0.1.6' instead."
  NEW_BRANCH="replace-with-v0.1.6-$(timestamp)"
  git checkout -b "$NEW_BRANCH"
  git push -u "$REMOTE" "$NEW_BRANCH"
  echo "Pushed to $REMOTE/$NEW_BRANCH. Consider opening a Pull Request to merge into main on GitHub."
fi

exit 0
