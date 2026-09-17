# syntax=docker/dockerfile:1
ARG GO_VERSION=1.27.1
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS build
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
    -ldflags "-s -w -X main.version=$VERSION" -o /out/bscan ./cmd/bscan
RUN mkdir -p /out/state /out/reports /out/rootfs/tmp && chmod 1777 /out/rootfs/tmp

FROM scratch
ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="bongsu-scanner" \
      org.opencontainers.image.description="Offline SBOM and vulnerability scanner" \
      org.opencontainers.image.source="https://github.com/ziozzang/bongsu-scanner" \
      org.opencontainers.image.url="https://github.com/ziozzang/bongsu-scanner" \
      org.opencontainers.image.version=$VERSION \
      org.opencontainers.image.revision=$REVISION \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/bscan /bscan
COPY --from=build --chown=65532:65532 /out/state /var/lib/bscan
COPY --from=build --chown=65532:65532 /out/reports /reports
# Copy the child directory itself so its sticky mode survives COPY.
COPY --from=build /out/rootfs/ /
COPY LICENSE THIRD_PARTY_NOTICES.txt /usr/share/licenses/bscan/
ENV BONGSU_HOME=/var/lib/bscan HOME=/var/lib/bscan PATH=/usr/local/bin
USER 65532:65532
WORKDIR /reports
ENTRYPOINT ["/bscan"]
