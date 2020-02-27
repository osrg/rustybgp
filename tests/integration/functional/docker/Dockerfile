FROM alpine
WORKDIR /root
EXPOSE 50051

RUN apk add --no-cache --update supervisor
ADD tests/integration/functional/docker/supervisord.conf /etc/

ADD target/x86_64-unknown-linux-musl/release/daemon /usr/bin/rustybgpd
COPY gobgp /usr/bin

ENTRYPOINT ["/usr/bin/supervisord"]
