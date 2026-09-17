# LLM applicability review

`match --llm` adds an environmental applicability hypothesis to existing
findings using an OpenAI-compatible Chat Completions endpoint. Configure the
server and model explicitly; no provider or model is selected automatically.
The API key is read from an environment variable, never stored in configuration.

```sh
export BSCAN_LLM_BASE_URL=https://your-llm-server.example/v1
export BSCAN_LLM_MODEL=your-model-name
# Set BSCAN_LLM_API_KEY in your shell/secret manager if the server needs a key.
bscan match --llm --llm-max-findings 20 --format json -o reviewed.json scan.cdx.json

# Supply known deployment facts when the SBOM does not contain them.
bscan match --llm --target-os linux --target-arch amd64 \
  --env-fact windows_compatibility_layer=absent scan.cdx.json
```

Flags `--llm-base-url`, `--llm-model`, and `--llm-key-env` override those settings.
The URL is an API base ending in `/v1` when required by the server; bscan appends
`/chat/completions`. HTTPS is required except for loopback HTTP endpoints such as
`http://127.0.0.1:11434/v1`. A server must support JSON-mode Chat Completions.
No calls are made unless `--llm` is present; `BONGSU_OFFLINE=1` or `offline: true`
disables all LLM requests, including calls to a local HTTP server.

The model receives the matched package/version, advisory summary/description,
and target OS/architecture plus explicitly declared environment facts. SBOM
hostnames, IP addresses, filesystem paths and the whole inventory are excluded.
Reference URLs are context only; bscan does not follow them. Advisory text is
handled as untrusted data, with no model tools or command execution.

Results use `likely_affected`, `likely_not_affected`, or `needs_review` and include
verbatim advisory evidence, preconditions, and checks to perform. For example,
a Windows-only precondition can support `likely_not_affected` on a known Linux
deployment. Missing facts or a truncated description require further review.
Evidence not present in the supplied text is rejected as support for a conclusion.
Verbatim evidence does not prove that the model interpreted it correctly: a
model can quote a real sentence and still draw a contradictory conclusion.
Review the evidence and deployment assumptions before acting on an annotation.
These annotations preserve the original finding, severity and `--fail-on`
behavior; CycloneDX output uses custom properties rather than a definitive VEX
`not_affected` assertion. Request failures retain the findings and write the
report before returning an execution error.

At most 20 distinct findings per input SBOM are reviewed by default. Remaining
findings are marked `not_assessed`; `--llm-max-findings` changes the limit.
Identical inputs reuse cached results keyed by input, model, endpoint and prompt
version. Cache files are private and live under `$BONGSU_HOME/cache/llm`;
`--llm-cache ''` disables caching. `--llm-timeout` bounds each request.

New downloads preserve advisory descriptions up to 64 KiB with an explicit
truncation flag. To replace descriptions truncated by the older 2 KiB format,
refresh the same selected sources using `db update --force`; a normal 304 refresh
or offline SQLite conversion preserves the existing text.

API protocol reference: [OpenAI Chat Completions](https://developers.openai.com/api/reference/resources/chat).
