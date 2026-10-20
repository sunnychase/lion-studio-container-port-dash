# Changelog

## 2.0.0 — 2026-10-20

- **Container Port Dash** (was a private "ports" page): every listening port with a plain-words description of what it is
  and the account, service or container that owns it (exact, from the socket's cgroup, root services and containers included).
- **Traffic:** live in / out rates and connections per port, from the kernel's per-connection TCP byte counters.
- **Data leaving this machine:** every program that exchanged data with another machine in the last 24 h, the other end
  (address, reverse-DNS name, internet or LAN), what it is (HTTPS, DNS, …), bytes sent and received, first seen.
- **Connection log:** every connection to another machine recorded as it opens and as it closes (`ss -E`), short ones too,
  one JSON-lines file per day, kept 30 days, searchable on the page and downloadable.
- **Alerts:** a new destination network for a program, a program uploading more than 100 MB an hour to the internet, a port
  newly open to the LAN; the first 30 minutes learn what is normal.
- **Kill** with your login password (checked by the machine's own SSH server, never stored): your services are stopped and
  disabled, your programs ended, Docker containers stopped with their restart turned off; nothing is deleted. System
  services are view only. Five wrong passwords lock Kill for 15 minutes; every attempt is in the audit log.
- ON / OFF switches for your systemd --user services (panel token); a service Kill disabled is enabled again when switched on.
- Demo mode with made-up data (`PORTS_DEMO=1`) for screenshots and tests; `tests/check.sh`.

## 1.0.0 — 2026-10-19

- Every listening port and ON / OFF switches for systemd --user services (private build).
