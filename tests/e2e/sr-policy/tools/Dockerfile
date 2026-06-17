FROM golang:1.24-alpine AS builder
RUN apk add --no-cache git ca-certificates
WORKDIR /src
COPY . .
RUN go mod tidy && \
    go build -o /usr/local/bin/sr-inject ./inject && \
    go build -o /usr/local/bin/sr-verify ./verify && \
    go build -o /usr/local/bin/sr-debug ./debug

FROM alpine:3.21
COPY --from=builder /usr/local/bin/sr-inject /usr/local/bin/
COPY --from=builder /usr/local/bin/sr-verify /usr/local/bin/
COPY --from=builder /usr/local/bin/sr-debug /usr/local/bin/
CMD ["sleep", "infinity"]
