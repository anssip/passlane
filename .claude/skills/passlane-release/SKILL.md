---
name: passlane-release
description: Publish a new version of passlane — determine the next semantic version, update CHANGELOG.md and Cargo.toml, commit, and create the git tag (vX.Y.Z) that triggers the GitHub release build. Use when the user wants to release, publish, ship, cut, or tag a new version of passlane, or bump its version.
allowed-tools: Bash(git:*), Bash(cargo:*), Bash(gh:*), Read, Edit
---

# passlane-release

Cut and publish a new passlane release. Releases are driven entirely by git tags: pushing a tag
matching `v[0-9]+.*` triggers `.github/workflows/release.yml`, which creates a GitHub Release (with
notes parsed from `CHANGELOG.md`) and builds + uploads binaries for macOS, Windows, and Linux.

So a release is: pick the next version → update `CHANGELOG.md` and `Cargo.toml` → commit → tag
`vX.Y.Z` → push the tag. CI does the rest.

Work through the steps below in order. **Pushing the tag publishes a public release and starts
binary builds — confirm with the user before that step.**

## 1. Preflight

```bash
git rev-parse --abbrev-ref HEAD     # expect: master
git status --short                  # expect: clean (or only intended release changes)
git fetch --tags
```

If the branch isn't `master` or the tree has unrelated changes, stop and surface it — don't release
from a dirty or unexpected state.

## 2. Find the current version and the changes since it

```bash
LATEST=$(git tag --sort=-v:refname | head -1)   # e.g. v3.0.2
git log "$LATEST"..HEAD --oneline               # commits to be released
```

Cross-check that `Cargo.toml`'s `version` matches `$LATEST` without the `v` (it should — the repo
keeps them in lockstep). The tag is the source of truth for "latest released version".

## 3. Determine the next version

Tags are `vMAJOR.MINOR.PATCH`. Decide the bump from the commits since `$LATEST`:

- **patch** (`v3.0.2` → `v3.0.3`) — only bug fixes / internal changes.
- **minor** (`v3.0.2` → `v3.1.0`) — new user-facing features, backward-compatible.
- **major** (`v3.0.2` → `v4.0.0`) — breaking changes to the CLI, vault format, or behavior.

If the user named a bump level or explicit version, use it. Otherwise propose one based on the
commit log and **confirm the target version with the user** before changing files.

## 4. Update CHANGELOG.md

Insert a new section at the **top of the list**, immediately after the `# Changelog` heading and
above the previous latest section. Match the existing format exactly — `## [X.Y.Z]` (no `v` prefix,
square brackets), a blank line, then terse bullet points:

```markdown
# Changelog

## [3.1.0]

- Add scriptable TOTP code retrieval (`list --code`, `show -o --once`)
- Add a Claude agent skill for using passlane in automations
- Fix: <user-facing description>

## [3.0.2]
...
```

Guidelines for the bullets:
- Rewrite commit subjects into **user-facing** entries — describe what changed for users, not the
  internal mechanics. Group related commits.
- Keep the project's voice: imperative bullets, `Add ...` for features, `Fix: ...` / `Fix to ...`
  for fixes, backtick-quote commands and flags.
- **Skip non-user-facing commits** — internal docs, refactors with no behavior change, change
  proposals, CI tweaks. (e.g. a "change proposal" commit does not belong in the changelog.)
- The release workflow parses this section by version, so the `## [X.Y.Z]` heading must contain the
  exact version that the tag refers to.

## 5. Bump Cargo.toml (and Cargo.lock)

Edit the `version = "X.Y.Z"` line in `Cargo.toml` to the new version. Then refresh the lockfile so
its `passlane` entry matches (avoids a dirty lockfile on the next build):

```bash
cargo update -p passlane --precise X.Y.Z 2>/dev/null || cargo build
```

## 6. Commit

Stage the release files and commit:

```bash
git add CHANGELOG.md Cargo.toml Cargo.lock
git commit -m "Release vX.Y.Z"
```

## 7. Tag

Existing tags are lightweight and point straight at the release commit. Match that:

```bash
git tag vX.Y.Z
```

## 8. Push (publishes the release — confirm first)

Pushing the tag triggers the GitHub Actions release build and a public GitHub Release. Confirm with
the user, then push the commit and the tag together:

```bash
git push origin master
git push origin vX.Y.Z
```

## 9. Verify

The `Release` workflow now runs. Watch it and confirm the release and binaries land:

```bash
gh run watch          # or: gh run list --workflow=release.yml
gh release view vX.Y.Z
```

If the workflow fails, report what failed — the tag is already public, so fixes go in a follow-up
patch release rather than by re-tagging.

## Quick reference

| Step | Command |
| ---- | ------- |
| Latest released version | `git tag --sort=-v:refname \| head -1` |
| Changes since release | `git log "$(git tag --sort=-v:refname \| head -1)"..HEAD --oneline` |
| Tag | `git tag vX.Y.Z` |
| Publish | `git push origin master && git push origin vX.Y.Z` |
| Watch build | `gh run watch` |
