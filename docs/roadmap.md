# Roadmap

## Future server submission

This is a proposed design, not an implemented upload service or command.

A future bongsu server should register each scanner's public-key fingerprint
and accept an upload envelope containing scanner ID, scan ID, target type,
scan/signing timestamps, SBOM files, and detached signatures. The server must
recalculate each SBOM digest and verify it against the registered key before
accepting the scan.

For periodic collection, `bscan` should write completed signed scans to a local
outbox. A systemd timer or cron job can run scans, while a separate submit
worker uploads outbox entries with idempotent scan IDs, retries with backoff,
and deletes or archives an entry only after server acknowledgement. This keeps
scanning functional while the server is offline and avoids giving the scanner
private key to the server.
