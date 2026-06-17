FROM golang:1.24-alpine AS builder
RUN apk add --no-cache git ca-certificates
WORKDIR /src
COPY . .
RUN go mod tidy && \
    go build -o /usr/local/bin/ls-inject ./inject && \
    go build -o /usr/local/bin/ls-verify ./verify

FROM alpine:3.21
COPY --from=builder /usr/local/bin/ls-inject /usr/local/bin/
COPY --from=builder /usr/local/bin/ls-verify /usr/local/bin/
CMD ["sleep", "infinity"]
