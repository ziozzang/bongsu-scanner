# Install and deploy bscan

Build with the Go toolchain selected by `go.mod` (minimum Go 1.25). Run
`make dist VERSION=0.5.0` on a POSIX build host with Go, make, tar, gzip and
sha256sum. It builds static archives for linux/amd64, linux/arm64,
darwin/arm64, darwin/amd64 and windows/amd64. Each
`dist/bscan_<ver>_<os>_<arch>.tar.gz` contains `bscan` (`bscan.exe` on Windows),
`LICENSE` and `THIRD_PARTY_NOTICES.txt`. Checksums go into `dist/SHA256SUMS`;
regeneration removes its old signature. Run `make release` **before**
`make dist` if legacy Linux self-update binaries are also needed, then
`make release-sign` last. Do not run these three targets concurrently.
Tag releases upload both the legacy binaries and the archives, sign checksums
when `BONGSU_RELEASE_KEY` is configured, then publish a linux/amd64 + linux/arm64
image to `ghcr.io/<repository>:<tag>`. DEB/RPM packages are not produced.

Directory/archive scans, `db`, `match` and `report` are intended to be portable;
host inventory and host metadata are Linux features. CI builds all packages
for Linux, macOS, Windows and FreeBSD; cross-compilation alone does not prove
native runtime behavior. The Unix-only walk helpers live in
`internal/scan/walk_unix.go`, with portable fallbacks in `walk_windows.go`,
so `GOOS=windows go build ./cmd/bscan` succeeds; Windows host scanning is
still unsupported (scan directories, archives and images there).

## Container

```sh
make image VERSION=0.5.0
# Or use a published tag:
image=ghcr.io/ziozzang/bongsu-scanner:v0.5.0
docker run --rm "$image" version
mkdir -p scan-results
docker run --rm --read-only --network none \
  --user "$(id -u):$(id -g)" --cap-drop ALL \
  --security-opt no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=256m,mode=1777 \
  --mount "type=bind,src=$PWD,dst=/input,readonly" \
  --mount "type=bind,src=$PWD/scan-results,dst=/reports" \
  "$image" scan --no-sign --exclude scan-results --workers 2 --output /reports /input
```

The scratch image contains a static binary, CA certificates and license notices;
it defaults to UID/GID 65532 and `/reports` as its working directory. Bind-mount
output and `/var/lib/bscan` (the image's `BONGSU_HOME`) with ownership matching
the selected UID. Writable temporary storage is needed for directory-walk
spooling, archive processing, and catalog operations; size it for the inputs.
Even an unsigned directory scan needs writable temporary storage in addition
to its output directory. Set the tmpfs mode explicitly to `1777` so the selected
non-root UID can write to it. The image's `/tmp` is world-writable with the
sticky bit (`1777`); a read-only root filesystem still requires a writable
tmpfs mount.

To scan a Linux host's bind-mounted root as a directory:

```sh
docker run --rm --read-only --network none \
  --user "$(id -u):$(id -g)" --cap-drop ALL \
  --security-opt no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=256m,mode=1777 \
  --mount type=bind,src=/,dst=/host,readonly \
  --mount "type=bind,src=$PWD/scan-results,dst=/reports" \
  "$image" scan --no-sign --files=false --one-file-system --workers 2 \
  --exclude /host/proc --exclude /host/sys --exclude /host/dev \
  --exclude /host/run --exclude /host/tmp --exclude /host/var/tmp \
  --exclude /host/mnt --exclude /host/media --exclude /host/swapfile \
  --exclude /host/var/lib/docker --exclude /host/var/lib/containerd \
  --exclude /host/var/lib/containers --exclude /host/var/lib/bscan \
  --exclude /host/var/lib/flatpak --exclude /host/var/lib/machines \
  --exclude /host/var/lib/libvirt/images --exclude /host/snap --exclude /host/var/snap \
  --exclude /host/var/cache/apt/archives --exclude 'home/*/.cache' --exclude root/.cache \
  --exclude 'home/*/go/pkg/mod' --exclude root/go/pkg/mod \
  --exclude 'home/*/.local/share/containers' --exclude root/.local/share/containers \
  --exclude 'home/*/.local/share/docker' --exclude root/.local/share/docker \
  --exclude "/host$PWD/scan-results" --output /reports /host
```

`scan /host` does **not** enable host policy, default host exclusions, or host
metadata. `--files=false` avoids per-file hashes; exclusions are explicit, and
`--workers` bounds parallel directory traversal. `--one-file-system` skips
mount points below `/host`, including separate `/usr`, `/var` or `/home`
filesystems: scan those roots separately when they contain needed inventory.
Unreadable files make an inventory partial; inspect the scan summary and SBOM
metadata or use `--fail-on-partial`. For protected host files, an administrator
may replace the `--user` argument with `--user 0:0` and add
`--cap-add DAC_READ_SEARCH`; the mounts remain read-only. `scan host` inside
the container describes the container, not the host.

Docker source targets invoke an external **docker CLI**, which is intentionally
not bundled. Mount a trusted **static Linux docker client** matching the image
architecture, plus the socket read-only (a dynamically linked host client will
not run in scratch). Set `docker_cli` to that client's absolute path:

```sh
docker_cli=/opt/docker-static/docker
docker run --rm --read-only --network none \
  --user "$(id -u):$(id -g)" --group-add "$(stat -c %g /var/run/docker.sock)" \
  --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=2g,mode=1777 \
  --mount "type=bind,src=$docker_cli,dst=/usr/local/bin/docker,readonly" \
  --mount type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock,readonly \
  --mount "type=bind,src=$PWD/scan-results,dst=/reports" \
  "$image" scan --no-sign --output /reports docker://alpine:3.20
```

The image must already exist in the daemon. `container://NAME` works similarly.
A read-only socket mount does **not** restrict Docker API requests; access to
the socket grants control of the daemon. To avoid daemon access, run
`docker save -o image.tar IMAGE` on the host and scan the mounted archive.

For local validation, run `docker build --platform linux/amd64 -t bscan:test .`
then `sh deploy/container-smoke.sh bscan:test`. Multi-architecture buildx
publishing runs only in the release workflow.

## systemd (Linux)

Install a verified binary at `/usr/local/bin/bscan`. Create the persistent
service account and directories once (skip `useradd` if it already exists):

```sh
sudo useradd --system --user-group --home-dir /var/lib/bscan --shell /usr/sbin/nologin bscan
sudo install -d -m 0700 -o bscan -g bscan /var/lib/bscan /var/lib/bscan/reports
sudo -u bscan env BONGSU_HOME=/var/lib/bscan /usr/local/bin/bscan init --signer host-scanner
sudo install -m 0644 deploy/systemd/bscan-*.service deploy/systemd/bscan-*.timer /etc/systemd/system/
sudo systemctl daemon-reload
# Populate the catalog before enabling matched scans.
sudo systemctl start bscan-db-update.service
sudo systemctl enable --now bscan-db-update.timer bscan-scan.timer
sudo systemctl start bscan-scan.service
journalctl -u bscan-scan.service -u bscan-db-update.service
```

The scan runs daily and the catalog update weekly, with randomized delays and
persistent catch-up. The scan is offline and waits for a running catalog-update
unit; a missing catalog manifest skips the scan. Both units use the `bscan`
account (`DynamicUser=no`), a read-only filesystem, private temporary storage,
and writable `/var/lib/bscan` for configuration, keys, catalog and reports.
Only the scan receives `CAP_DAC_READ_SEARCH` (bounding and ambient) so it can
read protected host files without UID 0. The update service has no capabilities.
`ProtectHome` is intentionally not enabled because home directories are inputs.

The scan excludes its own state, applies host defaults and stays on one
filesystem. Review separate mounts and add separate scans if necessary.
PrivateTmp hides the host temporary directories, already excluded by host
policy. Reports under `/var/lib/bscan/reports` use stable target names and are
replaced each run; copy them elsewhere if historical retention is required.
State mode 0700 and umask 0077 keep keys and inventories private.

## Cron alternative

After the same account, directory and initial catalog setup, install
`deploy/cron/bscan` as `/etc/cron.d/bscan` (root-owned, mode 0644).
Do not also enable the systemd timers. This example uses root for the host
scan because cron cannot supply ambient capabilities, and returns state
ownership to `bscan` afterward. It lacks the systemd sandbox; prefer the units
when available. Cron emails command output if a local mail transport exists.

For air-gapped hosts, import a signed catalog as `bscan` using the flow in the
[main README](../README.md#install-and-deploy), and enable only the scan timer.
