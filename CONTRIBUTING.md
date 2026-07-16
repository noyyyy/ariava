# Contributing

Thanks for your interest in contributing to Ariava.

For feature changes, we recommend opening a pull request to discuss the idea, scope, and approach before investing in a full implementation.

For fixes, feel free to submit a pull request. Please describe the problem, the fix, and the validation you performed.

Before submitting a pull request, run:

```bash
bun install --frozen-lockfile
bun run verify
```

Please preserve Ariava's security boundaries, including the `reply` and `interrupt` command allowlist and the loopback-only authenticated Agent Adapter.

Contributions are licensed under the Apache License 2.0 under this repository's license terms.
