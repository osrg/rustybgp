#! /bin/sh

cd `dirname $0`

case "$1" in
    build)
        if [[ ! -f gobgp  ]]; then
            curl -OL https://github.com/osrg/gobgp/releases/download/v2.11.0/gobgp_2.11.0_linux_amd64.tar.gz
            tar xzf gobgp_2.11.0_linux_amd64.tar.gz
        fi
        cd ../../.. && cargo build --release --target x86_64-unknown-linux-musl
        cd -
        cp ../../../target/x86_64-unknown-linux-musl/release/daemon rustybgpd
        cat <<EOF > Dockerfile
FROM alpine
WORKDIR /root
EXPOSE 50051

RUN apk add --no-cache --update supervisor
ADD docker/supervisord.conf /etc/
ADD rustybgpd /usr/bin
ADD gobgp /usr/bin
ENTRYPOINT ["/usr/bin/supervisord"]
EOF
        docker build . -t rustybgp-ci -f Dockerfile
    ;;

    start)
        GOBGP_IMAGE_NAME=tomo/gobgp go test ./... -v
    ;;

    stop)
         docker rm -f $(docker ps -a -q -f "label=rustybgp-ci")
    ;;

    cleanup)
        rm -f gobgp gobgpd gobgp_2.11.0_linux_amd64.tar.gz Dockerfile rustybgpd README.md LICENSE
    ;;

    *)
        echo "Usage: {build|stop|cleanup}" >&2
        exit 1
    ;;
esac

exit 0
