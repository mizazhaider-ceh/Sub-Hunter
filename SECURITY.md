# Security Policy

## Supported versions

SubHunter v5.x is the supported line. Older releases receive no security
updates, so upgrade before reporting an issue.

## Reporting a vulnerability

If you find a security problem **in SubHunter itself** (the scanner code, its
dependencies, or the report generator), do not open a public issue. Email the
maintainer instead:

- GitHub: [@mizazhaider-ceh](https://github.com/mizazhaider-ceh)

Include:

1. What the problem is and where it lives (file and line if you have it).
2. Steps to reproduce, or a minimal proof of concept.
3. What you think the impact is.

You will get a reply within a reasonable time, and the fix will be credited
in the release notes unless you ask to stay anonymous.

## Scope notes

SubHunter is an **offensive-security testing tool**. The security policy above
covers flaws in the tool itself, not findings the tool reports on your targets.
Report a real-world vulnerability you discovered with SubHunter to that
system's owner or bug bounty program, never to this repo.

## Responsible use

- Only scan domains and systems you own or have explicit written permission
  to test.
- API keys for passive sources go in a local `.env` file (copy
  `.env.example`). Never commit keys, tokens, or scan output containing
  credentials.
- The HTML report generator escapes all reflected content, but treat any
  generated report as untrusted input before sharing it.

## Dependency hygiene

- `httpx` and `aiodns` are the only runtime dependencies. Keep them current:
  `pip install -U httpx aiodns`.
- Screenshot support (`playwright` / `selenium`) is optional and pulls in a
  browser binary. Install it only if you need screenshots.
