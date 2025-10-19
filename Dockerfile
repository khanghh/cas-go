# ---- Build stage ----
FROM golang:1.25.1-alpine AS builder

WORKDIR /workdir

RUN apk add --no-cache git ca-certificates tzdata && update-ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags "\
      -w -s \
      -X 'main.gitCommit=$(git rev-parse HEAD)' \
      -X 'main.gitDate=$(git show -s --format=%cI HEAD)' \
      -X 'main.gitTag=$(git describe --tags --always --dirty)'" \
    -o cas-server .

RUN ls -lah /workdir/build/bin

# ---- Runtime stage ----
FROM scratch

WORKDIR /app

COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /workdir/cas-server /app/cas-server
COPY --from=builder /workdir/templates /app/templates
COPY --from=builder /workdir/static /app/static

ENTRYPOINT ["/app/cas-server", "--config", "/config.yaml"]
