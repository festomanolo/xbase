# =============================================================================
# Multi-stage Dockerfile for the xbase Go backend (~10MB static binary)
# =============================================================================
FROM golang:1.25-bookworm AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/xbase-go-backend .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/xbase-go-backend /usr/local/bin/xbase-go-backend
EXPOSE 3000
USER nonroot:nonroot
HEALTHCHECK --interval=10s --timeout=4s --start-period=20s --retries=3 \
    CMD ["/usr/local/bin/xbase-go-backend", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/xbase-go-backend"]
