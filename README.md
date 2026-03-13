# Build Secure Transport

End-to-end encrypted communication layer for [Build](https://getbuild.ing).

## What is Build?

Build is a local-first coding agent orchestration platform. It lets you coordinate AI coding agents across any device — your laptop, your workstation, your CI runner — through a single web interface. Install on a device, configure it via TUI, and manage all your agents from the web UI.

- **Local-first**: Agents run on your hardware, not in someone else's cloud
- **Multi-device**: One mesh network across all your machines
- **Full observability**: Always-visible complications for git status, CI/CD, tests, and more
- **Planning & tracking**: Create agents, assign tasks, and monitor implementation progress

## Why is this repo public?

Build is a commercial product. The client and web platform are proprietary.

This encryption layer is public **for auditability**. When a product claims end-to-end encryption, you shouldn't have to take their word for it. By publishing the secure transport implementation, anyone can:

- **Verify** that communication between devices is truly end-to-end encrypted
- **Audit** the cryptographic implementation for correctness
- **Inspect** that no backdoors or key escrow mechanisms exist
- **Contribute** improvements to the encryption layer

## License

This software is released under the [Business Source License 1.1](LICENSE.md) (BSL 1.1).

**You may**: read, audit, fork, and contribute to this code. Use it for non-production purposes including research, testing, and security review.

**You may not**: use this software in a production commercial product or service without a separate license agreement.

The intent is clear: this code is public so you can verify our encryption claims, not so competitors can ship it as their own. If you have questions about permitted use, open an issue.
