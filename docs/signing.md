# Signing and verification

Output and signing depend on the target:

- `host`, directories, `docker://`, and `container://` write only the requested
  SBOMs. With automatic or explicit signing, each SBOM receives its own
  detached `.sig`.
- Physical tar/tgz image files additionally receive a SHA-256 manifest covering
  the original archive and generated SBOMs, plus a layer digest manifest when
  applicable. With automatic or explicit signing, the main SHA-256 manifest is
  signed.

Signatures cover the exact target digest, UTC signing timestamp, and
time-derived 256-bit random salt.

## Automatic signing

After an identity has been initialized with both a signer label and private
key, every scan signs its normal signing target automatically:

```sh
bscan init --signer scanner-01@example.com
bscan scan --output ./host-scan host
```

The startup log reports `auto-sign enabled` and the configured signer.
Automatic signing requires a non-empty `signer` in
the [selected configuration file](configuration.md) and a valid
configured/default private key. Use
`--no-sign` for an intentionally unsigned scan. `--sign` remains available to
force signing and initialize a missing default key.

## Signature verification

`verify` validates the Ed25519 signature, the signed target digest, the current
SBOM contents, and a pinned/trusted public key. Multiple signatures can be
verified in one invocation:

```sh
# Verify with this scanner's local public key
bscan verify \
  --pubkey ~/.bongsu/signing.pub \
  host-scan/host.spdx.json.sig \
  host-scan/host.cdx.json.sig

# Or register a remote scanner's key once and verify by trust name
bscan key trust scanner-01 scanner-01.pub
bscan verify --pubkey scanner-01 incoming/*.sig
```

New signatures use Version 2. Its payload has a version-specific domain followed
by the digest, target, signer, UTC signing timestamp, and salt, each prefixed
with its byte length (big-endian uint64). Changing any of these signed values
fails verification. The signer label and target name are authenticated by the
signing key; publisher identity still depends on trusting that key.

Version 1 signatures remain accepted for compatibility. They authenticate only
the digest, UTC signing timestamp, and salt under the v1 domain. Their signer
and target fields are unauthenticated and can be changed without invalidating
the signature. Re-sign legacy artifacts to bind those fields. JSON formatting
and equivalent timestamp encodings are not authenticated in either version.

`verify` fails when a key is not pinned, a signed value was modified, the target
is missing, or the current target digest differs. `check` remains the general
command for SHA manifests and layer manifests as well as signatures.

## Scrambler

```sh
bscan scramble encrypt --chunk-size 4MiB -o payload.bgs payload.bin
bscan scramble decrypt --pubkey ~/.bongsu/signing.pub -o restored.bin payload.bgs
```

This is an authenticated **scrambler, not confidentiality encryption**.
The private key signs the artifact and its public key derives the reversible
byte stream, so anyone with the public key can restore it by design.
