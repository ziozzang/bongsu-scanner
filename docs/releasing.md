# Releasing bscan

`make test` checks Go formatting, runs uncached race tests, and runs `go vet`.
`make release` builds both Linux architectures and writes `dist/SHA256SUMS`,
then copies `LICENSE` and `THIRD_PARTY_NOTICES.txt` into `dist/`. It removes
any previous checksum signature and prints a reminder to sign before publishing.

Use a persistent publisher identity selected by `BONGSU_HOME`:

```sh
export BONGSU_HOME="$HOME/.bongsu-release"
make build VERSION=0.6.0
# Initialize once; keep this directory and its private key for future releases.
./dist/bscan init --signer publisher@example.com
make release VERSION=0.6.0
make release-sign VERSION=0.6.0
./dist/bscan verify --pubkey "$BONGSU_HOME/signing.pub" dist/SHA256SUMS.sig
```

`release-sign` builds a native `dist/bscan` and runs
`./dist/bscan sign -o dist/SHA256SUMS.sig dist/SHA256SUMS` using that identity.
Publish both versioned binaries, `SHA256SUMS`, `SHA256SUMS.sig`, `LICENSE`, and
`THIRD_PARTY_NOTICES.txt` together. Distribute the publisher's public key through
a trusted channel. Re-run `make release-sign` after regenerating the checksums;
`make clean` also removes `dist/SHA256SUMS.sig`.

For `bscan update`, a pinned release key requires a valid `SHA256SUMS.sig`,
even without `--require-signature`. Pin the publisher with
`bscan key trust release publisher.pub`; a built-in release key also counts
as pinned. Missing or invalid signatures then fail the update. Without a pinned
key, updates warn that the signature is unverified and use checksum validation;
`--require-signature` also rejects this unpinned case. `bscan update --check`
only checks the available version and does not verify release artifacts.

## Maintainer checklist for v0.6.0

1. Finalize [CHANGELOG](../CHANGELOG.md): replace `Unreleased` with `v0.6.0`
   and the actual release date; point its compare link at `2de24ef...v0.6.0`.
   Add a fresh empty `Unreleased` section linking `v0.6.0...HEAD`. Check all
   user-visible changes against the release commit.
2. Decide the publisher trust policy before building. Configure the repository
   secret `BONGSU_RELEASE_KEY` with an **unencrypted Ed25519 PKCS#8 PEM private
   key** for signed checksums. Pin its public half in
   `internal/selfupdate.ReleasePublicKey` before building, or distribute the
   public key through a trusted channel and require users to run
   `bscan key trust release publisher.pub`. The current built-in key is empty;
   a signing secret alone does not configure trust on clients. Never commit the
   private key. Without the secret, the workflow publishes unsigned checksums.
3. Require CI to be green on the exact release commit: formatting, analysis,
   vet/module verification, race tests, cross-builds, container smoke and
   vulnerability checks. Run the full test job for that commit as well; the
   workflow normally schedules it or exposes it through manual dispatch.
   The tag workflow itself builds and publishes; it does not gate on CI status.
4. Review [deployment](../deploy/README.md). For local packaging, use
   `make release VERSION=0.6.0`, then `make dist VERSION=0.6.0`, then
   `BONGSU_HOME=/path/to/release-identity make release-sign VERSION=0.6.0`.
   Re-sign after any checksum regeneration and do not run these targets concurrently.
5. Create the release tag on the reviewed commit and push **`v0.6.0`**. This is
   the publishing step: the release workflow triggers on pushed `v*` tags.
   Check both the release and subsequent image jobs.
6. Verify the published artifacts and perform the smoke checks below.

## Expected tag artifacts

| Artifact | Expected name / contents |
| --- | --- |
| Two raw Linux self-update binaries | `bscan_0.6.0_linux_x86_64`, `bscan_0.6.0_linux_arm64` |
| Five portable archives | `bscan_0.6.0_linux_amd64.tar.gz`, `bscan_0.6.0_linux_arm64.tar.gz`, `bscan_0.6.0_darwin_amd64.tar.gz`, `bscan_0.6.0_darwin_arm64.tar.gz`, `bscan_0.6.0_windows_amd64.tar.gz` |
| Checksums | `SHA256SUMS` covering all seven binaries/archives; `SHA256SUMS.sig` only when the release key is configured |
| Licenses | `LICENSE`, `THIRD_PARTY_NOTICES.txt` as release assets and inside every archive |
| Container | `ghcr.io/ziozzang/bongsu-scanner:v0.6.0`, with `linux/amd64` and `linux/arm64` manifests |

FreeBSD is cross-built by CI but has **no release archive**. DEB/RPM packages
are not produced. Archive binaries use `0.6.0` as their version string; the tag
workflow's raw binaries and image use `v0.6.0`.

These expectations come from [dist.sh](../deploy/dist.sh),
[the release workflow](../.github/workflows/release.yml),
[CI](../.github/workflows/ci.yml), [Makefile](../Makefile), and
[the updater](../internal/selfupdate/selfupdate.go).

## Post-release smoke checks

- Download checksums and assets. With an already trusted verifier and an
  independently trusted publisher key, verify `SHA256SUMS.sig` when required,
  then verify the exact downloaded artifact's checksum. Follow the
  [installation procedure](../deploy/README.md#install-a-release).
- Extract each archive and check its executable and both license files. On
  available native runners, run `version`, `about`, `help`, and a small directory
  scan; record platforms that were only cross-built.
- In an isolated `BONGSU_HOME`, run `init`, scan a small fixture, and verify its
  detached SBOM signatures. Import a trusted small catalog, run
  `BONGSU_OFFLINE=1 bscan scan --match --report json,html --output results FIXTURE`,
  and confirm SBOMs, findings JSON and HTML are present with no `.report.json`.
- Match a known vulnerable fixture with `--fail-on HIGH`, then repeat using
  global `--findings-exit-code 7`; check default exit 2/custom exit 7 and retained
  reports. Use [CI guidance](ci-integration.md) for cancellation and partial scans.
- On a disposable Linux installation, test `update --check` and an authenticated
  `update --require-signature`; confirm the final version and test failure with
  an untrusted key. `--check` alone does not verify downloaded release artifacts.
- Inspect the published image's two platform manifests and run `version` and a
  writable-output directory scan on each available architecture using the
  [container examples](../deploy/README.md#container).

Publishing, secrets and these post-release network/native-platform checks are
maintainer actions; documenting this checklist does not mean they have run.

## Local Docker checks

The Docker packaging tests in `deploy/` build an image and run the container
smoke test only when `BSCAN_DOCKER_TESTS=1` is set (the CI Docker job sets
it); without the variable they are skipped so a developer machine without a
daemon or network stays green.
