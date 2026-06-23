FROM golang:1.23-alpine AS builder
WORKDIR /src
COPY go.mod .
COPY main.go .
RUN go mod tidy && go build -o /bmp-receiver .

FROM alpine:3.21
COPY --from=builder /bmp-receiver /usr/local/bin/bmp-receiver
ENTRYPOINT ["bmp-receiver"]
