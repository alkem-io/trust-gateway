# syntax=docker/dockerfile:1.26

ARG GO_VERSION=1.26

FROM golang:${GO_VERSION}-bookworm@sha256:9fdc884aacc3bec89b20ffc69f4bb369c78210e3e4f600387b5128b12c199f81 AS builder
WORKDIR /src
ARG TARGETARCH
COPY go.mod ./
COPY go.sum ./
RUN go mod download
COPY .scripts/ .scripts/
COPY cmd/ cmd/
COPY internal/ internal/
RUN lib_dir="$(GOOS=linux GOARCH="${TARGETARCH}" .scripts/ci/setup-cleverbase-ffi.sh)" && \
    CGO_ENABLED=1 GOOS=linux GOARCH="${TARGETARCH}" CGO_LDFLAGS="-L${lib_dir}" \
    go build -trimpath -ldflags="-s -w" -o /trust-gateway ./cmd/server/

# distroless/cc is retained for the forthcoming cgo-linked Cleverbase static library.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
COPY --from=builder /trust-gateway /usr/local/bin/trust-gateway
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/trust-gateway"]
