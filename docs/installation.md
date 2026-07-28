# TraceQuarry Installation And Persistence

TraceQuarry supports Docker and isolated native installations on Linux, macOS,
and Windows. Every supported installation keeps application files separate from
case data so upgrades can replace the application without deleting evidence,
timelines, findings, or analyst annotations.

## Docker Compose

Docker is the recommended repeatable deployment for a dedicated analysis
workstation. It runs TraceQuarry as an unprivileged user with a read-only root
filesystem, no Linux capabilities, and a host port bound to loopback only.

```bash
git clone https://github.com/Chill-Ethical-People/TraceQuarry.git
cd TraceQuarry
cp .env.example .env
docker compose up --build --detach
docker compose ps
```

Open `http://127.0.0.1:8765`. The named `tracequarry-data` volume stores the
entire `/data` tree, including browser uploads, case outputs, annotations, and
the case-repository database. The optional `./evidence` bind mount appears
inside the container as read-only `/evidence` for server-path ingestion.

```bash
docker compose down       # application stops; case data remains
docker compose up -d      # the same case volume is attached again
```

Do not run `docker compose down -v` unless the case volume is intentionally
being destroyed. Confirm a backup before removing the volume.

Run the CLI with the same persistent volume and read-only evidence mount:

```bash
docker compose run --rm --entrypoint tracequarry tracequarry \
  /evidence/host01-uac.tar.gz --out /data/cli/host01
```

### Back Up The Docker Case Volume

Stop the application before a filesystem-level backup so every output and
database file is captured consistently:

```bash
mkdir -p backups
docker compose stop
docker run --rm --entrypoint tar \
  -v tracequarry-data:/data:ro \
  tracequarry:local \
  -C /data -czf - . > backups/tracequarry-data.tar.gz
docker compose start
```

Store backups on encrypted case storage and apply the engagement's retention
policy. A Docker volume is persistence, not a backup.

## Linux Installer

The Linux installer creates an isolated environment under
`~/.local/share/tracequarry`, launchers under `~/.local/bin`, and persistent case
data under `~/.local/share/tracequarry/data`.

```bash
./install/install-linux.sh
tracequarry --help
tracequarry-web
```

Set `TRACEQUARRY_PYTHON` to select a particular Python 3.11 or 3.12
interpreter. Add `~/.local/bin` to `PATH` if the distribution does not already
include it.

## macOS Installer

The macOS installer stores the isolated application and case data under
`~/Library/Application Support/TraceQuarry` and creates launchers under
`~/.local/bin`.

```bash
./install/install-macos.sh
tracequarry-web
```

## Windows Installer

Run PowerShell from the cloned repository:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\install\install-windows.ps1
tracequarry-web
```

The installer uses Python 3.12 or 3.11, stores application and case data below
`%LOCALAPPDATA%\TraceQuarry`, and adds its managed launcher directory to the
user `PATH`. Use `-NoPathUpdate` to leave `PATH` unchanged.

## Upgrade And Uninstall

Run the platform installer again from a newer checkout to upgrade the managed
environment. Existing case data remains in place.

```bash
./install/install-linux.sh --uninstall
./install/install-macos.sh --uninstall
```

```powershell
.\install\install-windows.ps1 -Uninstall
```

A normal uninstall preserves the data directory. To remove it as a separate,
explicit action, pass `--purge-data` on Linux or macOS, or `-PurgeData` on
Windows. The Windows wrapper also removes its managed launcher directory from
the user `PATH`; pass `-NoPathUpdate` to leave `PATH` unchanged. Preserve and
verify a case backup first.

## Security Boundaries

- Docker publishes `8765` only on `127.0.0.1` by default. Do not change the
  bind address to `0.0.0.0` without an authenticated access layer.
- The Docker-only wildcard bind is accepted only inside the packaged container;
  browser Host, Origin, and request-token checks remain active.
- Evidence mounted at `/evidence` is read-only. Generated material belongs in
  `/data`.
- Native and Docker deployments remain local-first and do not upload evidence
  to TraceQuarry services.
