#!/usr/bin/env bash
# One-shot publisher: commits the repo and creates a GitHub repo with `gh`, then pushes.
# Usage: ./scripts/publish_to_github.sh <owner>/<repo-name>
# Example: ./scripts/publish_to_github.sh jremy/node-chat-app
set -euo pipefail
REPO="$1"
if [ -z "$REPO" ]; then
  echo "Usage: $0 <owner>/<repo-name>"
  exit 2
fi

# Ensure we're in repo root (script expects to be run from project root)
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

# Check for git
if ! command -v git >/dev/null 2>&1; then
  echo "git not found. Install git and try again." >&2
  exit 1
fi

# Check for gh (GitHub CLI)
if ! command -v gh >/dev/null 2>&1; then
  echo "gh (GitHub CLI) not found. This script prefers gh to create the remote repo for you." >&2
  echo "Install gh (https://cli.github.com/) and run 'gh auth login', or create the repo manually and run the manual commands in README_DEPLOY.md" >&2
  exit 1
fi

# Initialize git if needed
if [ ! -d .git ]; then
  git init
fi

# Add and commit
git add -A
# If there's nothing to commit, skip committing
if git diff --cached --quiet; then
  echo "No changes to commit." 
else
  git commit -m "Prepare for Vercel: add vercel.json and env-friendly server"
fi

# Create the repo using gh
echo "Creating repository $REPO on GitHub (you'll be prompted by gh if needed)..."
gh repo create "$REPO" --public --source=. --remote=origin --push --yes

echo "Repository created and pushed. Remote origin: $(git remote get-url origin)"

echo
echo "Next steps (quick):"
echo "  - Add Vercel environment variables: JWT_SECRET and FIREBASE_DB_URL"
echo "  - Import the repo into Vercel or run 'vercel' to deploy"

echo "Done."
