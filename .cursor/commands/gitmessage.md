# Git Commit to Local

Based on the current workspace's git changes (`git status`, `git diff`), generate a commit message that follows project conventions and directly execute `git commit` to commit to the local repository.

## Execution Steps

1. Run `git status` and `git diff --staged` (or `git diff`) to review changes
2. Analyze the nature of each change (new feature / fix / addition / refactor, etc.) and categorize with the appropriate prefix
3. Generate a commit message following the rules below (summary uses prefix, body lines also use prefixes)
4. **If the staging area is empty**: Run `git add -u` to stage modifications to tracked files
5. **Execute `git commit -m "<generated message>"` to commit locally**

## Required Rules

### 1. Use English

Commit messages must be written in English.

### 2. Analyze Change Content

Each change should be clearly described:
- **Nature**: feat / fix / add / refactor / chore, etc.
- **Content**: What the change does and what problem it solves

### 3. Message Format (Must Use Conventional Commits Prefixes)

**Summary line**: Use prefixes like `feat:`, `fix:`, `add:`, `refactor:`, `chore:` to summarize the commit's nature.

**Body list**: Each change on its own line, **must start with the corresponding prefix**, followed by a brief description of that change.

```
<prefix>: <brief summary>

- feat: describe new feature
- fix: describe fix
- add: describe addition
- refactor: describe refactoring
- chore: describe miscellaneous change
```

**Common prefixes**:
- `feat:` New feature
- `fix:` Bug fix
- `add:` New file/dependency/config
- `refactor:` Code refactoring
- `chore:` Build, tools, non-logic miscellaneous
- `docs:` Documentation
- `perf:` Performance optimization

### 4. Examples

- Good example:
```
feat: refactor XXX module and fix YYY issue

- feat: change default instance to be managed by Manager
- fix: stop faking paths in ZZZ scenario to avoid breaking privileged capabilities
- add: add hasXXX() detection method
- chore: enhance read/write log output
```

- Good example (single line):
```
fix: unauthorized scenario causing sync failure
```

- Bad examples: "fix bug", "update code", body lines without prefixes

## Output

1. After committing, output a brief confirmation (e.g., "Committed locally" and a summary of the commit message)
2. If the staging area is empty but the working tree has unstaged changes, run `git add -A` first then `git commit`
