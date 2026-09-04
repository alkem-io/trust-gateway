# syntax=docker/dockerfile:1.26

ARG GO_VERSION=1.26

FROM golang:${GO_VERSION}-bookworm@sha256:9fdc884aacc3bec89b20ffc69f4bb369c78210e3e4f600387b5128b12c199f81 AS builder
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /trust-gateway ./cmd/server/

# distroless/cc is retained for the forthcoming cgo-linked Cleverbase static library.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
COPY --from=builder /trust-gateway /usr/local/bin/trust-gateway
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/trust-gateway"]
