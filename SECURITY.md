# Security

## What the container can do, and why

| Access | Why | What it means |
|---|---|---|
| `--network host`, `--pid host`, `--cgroupns host` | to see this machine's sockets, processes and which service owns each socket | it sees every socket and process on the machine (read only) |
| the Docker socket | to name containers and stop them | **anyone who controls the container controls Docker, which is root on the machine** |
| your user D-Bus (`/run/user/UID`) | to start, stop, enable and disable your systemd --user services | it can manage your own services |
| the host's `/etc/passwd`, read only | to show account names instead of numbers | no passwords are in that file |

It runs as your account (not root), with a read-only file system, every Linux capability dropped and `no-new-privileges`.
AppArmor is set to `unconfined` because Docker's default profile blocks reading other processes' socket links even for
the same account. If you do not want Kill for containers, leave the Docker socket out of `run.sh`: containers are then
shown by their ID and are view only.

## The password

- Kill asks for the login password of `PORTS_LOGIN` (the account that ran `run.sh`). The page sends it to the container,
  which asks this machine's own SSH server on `127.0.0.1:22` to check it (the normal PAM login check) and closes the
  connection without running anything. The password is never stored and never written to a log.
- SSH must allow password logins from the machine itself (`PasswordAuthentication yes`, the OpenSSH default). If you turn
  password logins off, Kill reports that it cannot check the password and does nothing.
- **The page is plain HTTP unless you add a certificate.** On a network you do not fully trust, put `cert.pem` and
  `key.pem` in `DATA/tls/` and restart: the page is then served over HTTPS and the password never crosses the network in
  clear. Or reach the page only through an SSH tunnel or a VPN.
- Five wrong passwords from one address (fifteen from all addresses) within 15 minutes lock Kill for 15 minutes. Each
  attempt (address, action, target, result; never the password) is appended to `DATA/audit.log`. The SSH server logs the
  checks too (`/var/log/auth.log`).
- The ON / OFF switches use a separate panel token (`DATA/token`, created by `run.sh`).

## What it cannot see

- **A program running as root can hide** from any tool on the same machine (it can change what the kernel reports to other
  accounts). Use this page as an early warning; for proof, look at the traffic from outside: your router's or firewall's logs.
- **Short connections:** every connection is logged when it closes, with its bytes and the other end. A connection that opens
  and closes between two samples (2 s) is logged as "unknown (closed between two samples)": the kernel's close event does not
  say which program owned it. A root add-on (an eBPF connection tracer) would name those programs.
- **UDP** has no byte counters: UDP flows are listed (who to whom), not measured. DNS lookups are made by the local resolver,
  so they show as the resolver, not as the program that asked.
- Reverse-DNS names come from your resolver and can be wrong or missing; the address is always shown.

## Reporting a problem

Open an issue on GitHub; for anything that could hurt users, ask for a private contact first.
