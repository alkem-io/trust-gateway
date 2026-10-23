# syntax=docker/dockerfile:1.26

ARG GO_VERSION=1.26.10

FROM golang:${GO_VERSION}-bookworm@sha256:632dff7351799a5a9954a48dc06670ade72ee44e8c351cdc0e5a57af2fea21af AS builder
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
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:83b9b50586253821cf63ffcec87d3d94265a093ad30da232039af962dd8f4edf
COPY --from=builder /trust-gateway /usr/local/bin/trust-gateway
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/trust-gateway"]
