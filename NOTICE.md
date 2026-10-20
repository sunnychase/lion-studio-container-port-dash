# Notices

**Lion Studio - Container Port Dash.** Created by [Sunny Chase](https://github.com/sunnychase) in collaboration with Claude (Anthropic).
Copyright (c) 2026 Sunny Chase (https://github.com/sunnychase) · Lion Studio - Container Port Dash.

All code and documentation in this repository were written for it and are under the MIT licence ([LICENSE](LICENSE)).

## What it uses (not included in this repository)

| Software | Licence | Used for |
|---|---|---|
| Python 3.12 (`python:3.12-slim` image) | PSF | the page and the sampler (standard library only, plus paramiko) |
| [paramiko](https://www.paramiko.org/) 3.5.1 | LGPL-2.1 | asking the machine's own SSH server to check the Kill password; installed from PyPI in the image, unmodified |
| iproute2 (`ss`, `ip`) | GPL-2.0 | reading sockets, byte counters and close events; run as a separate program |
| systemd (`busctl`) | LGPL-2.1 | starting, stopping, enabling and disabling your systemd --user services; run as a separate program |
| Docker Engine API | Apache-2.0 | naming and stopping containers, over the local socket |
| Playwright (only `scripts/record_demo.cjs`) | Apache-2.0 | recording the demo video in `docs/media` |

## The demo

Everything in `docs/media` and in demo mode is made up: the services, containers and host names are invented and every
address is from the ranges reserved for documentation (RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).

## Disclaimer

This is a monitoring aid, not a security product. It sees what an unprivileged account can see; a program running as root
can hide from it (see [SECURITY.md](SECURITY.md)). Kill stops real services: read the plan the page shows before you confirm.
The software is provided "as is", without warranty of any kind (see the licence).
