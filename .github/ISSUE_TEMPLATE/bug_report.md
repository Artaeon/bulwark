---
name: Bug report
about: Report a bug in bulwark
title: '[BUG] '
labels: bug
assignees: ''
---

<!--
Before filing, please:
- Check existing issues to avoid duplicates
- Verify the bug on the latest master
- If this is a security vulnerability, DO NOT file a public issue — see SECURITY.md
-->

## Description

A clear description of what the bug is.

## Steps to reproduce

1. Run `bulwark ...`
2. ...
3. See error

## Expected behavior

What you expected to happen.

## Actual behavior

What actually happened. Include relevant log output:

```
paste log output here
```

## Environment

- bulwark version: `bulwark --version`
- OS / distribution: (e.g. Arch Linux, Ubuntu 22.04)
- Kernel: `uname -a`
- Running as: (systemd service / foreground / manual)
- Configuration (redact sensitive values):

```toml
# relevant section of your bulwark.toml
```

## `--check-config` output

```
paste output of `bulwark --check-config --config /path/to/your.toml`
```

## Additional context

Anything else that might help diagnose the issue.
