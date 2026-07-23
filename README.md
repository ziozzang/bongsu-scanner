# bongsu-scanner

`bongsu` is a dependency-free Go scanner that creates SPDX 2.3 and
CycloneDX 1.6 SBOMs from a host filesystem, directory, tar/tgz archive,
Docker image/container, or OCI image archive. It also creates SHA-256
manifests, timestamp-bound Ed25519 signatures, verifies scan artifacts, and
provides a signed reversible binary scrambler.

Author: ziozzang@gmail.com

Project: https://github.com/ziozzang/bongsu-scanner

## Build and initialize

```sh
make build VERSION=0.1.0
./dist/bongsu init --signer ziozzang@gmail.com
./dist/bongsu about
```

Configuration and keys are stored at `~/.bongsu/scaner.yaml`,
`~/.bongsu/signing.key` (mode 0600), and `~/.bongsu/signing.pub`.
`BONGSU_HOME` can override the directory.

## Scan, sign, and check

```sh
bongsu scan --sign docker://alpine:3.20
bongsu scan --sign container://my-running-container
bongsu scan --output results image.tar
bongsu scan --format spdx /some/rootfs
bongsu scan host://
bongsu check results/image.tar.sha256.sig
bongsu check --source image.tar results/image.tar.layers.sha256
```

Docker targets use `docker container inspect` and `docker image save`. Archive
scanning itself is embedded: Docker/OCI manifests, gzip/tar layers, OCI
whiteouts, package databases, and language manifests are parsed in Go without
calling Syft, Trivy, or another SBOM executable.

Embedded catalogers currently cover Debian dpkg, Alpine apk, npm lockfiles,
Go modules, Python requirements/dist-info, Cargo lockfiles, and Maven
`pom.properties`. RPM's binary Berkeley DB / SQLite databases are not decoded
in this release.

Each scan writes the requested SBOM, a SHA-256 manifest, an optional layer
digest manifest, and (with `--sign`) a detached `.sig`. Signatures cover the
target digest, UTC signing timestamp, and 256-bit random salt.

## Scrambler

```sh
bongsu scramble encrypt --chunk-size 4MiB -o payload.bgs payload.bin
bongsu scramble decrypt --pubkey ~/.bongsu/signing.pub -o restored.bin payload.bgs
```

This is an authenticated **scrambler, not confidentiality encryption**.
The private key signs the artifact and its public key derives the reversible
byte stream, so anyone with the public key can restore it by design.

## Batch and updates

```sh
bongsu batch --jobs 4 --sign image-a.tar docker://alpine:3.20 ./rootfs
bongsu update --check
bongsu update
```

Interactive commands perform a non-blocking update check at most once every
24 hours. Set `BONGSU_NO_UPDATE_CHECK=1` for air-gapped or fully silent use.
Updates download the matching Linux release binary, verify it against the
release `SHA256SUMS`, and atomically replace the current executable.

## Security notes

- Pin a trusted public key with `bongsu key trust NAME KEY` and use
  `bongsu check --pubkey NAME artifact.sig` for provenance. An embedded key
  alone proves consistency, not identity.
- SHA256SUMS protects update transfer integrity. GitHub account/release
  security remains part of the update trust boundary.
- Host scans skip virtual/transient `/proc`, `/sys`, `/dev`, `/run`, `/tmp`,
  `/mnt`, and `/media`.

License: MIT.
