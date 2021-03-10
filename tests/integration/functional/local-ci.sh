#! /bin/bash

cd `dirname $0`

DEFAULT_GOBGP_IMAGE="ghcr.io/fujita/gobgp-for-rustybgp-ci"

rm_containers() {
    ids=($(docker ps -a -q -f "label=rustybgp-ci"))
    if [ $ids ]; then
        docker rm -f ${ids[@]} > /dev/null
    fi
}

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
        tests=($(grep "func Test" pkg/*_test.go|gawk -F " " '{ print gensub("\\(t", "", 1, $2) }'))
        for name in ${tests[@]}
        do
            rm_containers
            GOBGP_IMAGE_NAME=${DEFAULT_GOBGP_IMAGE} go test ./... -v -count 1 -run $name
            if [ $? -ne 0 ]; then
                exit 1
            fi
        done
    ;;

    run)
        if [ $# -ne 2 ]; then
            echo "Usage: local-ci.sh run TESTFILE"
            exit 1
        fi
        name=$(grep "func Test" $2|gawk -F " " '{ print gensub("\\(t", "", 1, $2) }')
        rm_containers
        GOBGP_IMAGE_NAME=${DEFAULT_GOBGP_IMAGE} go test ./... -v -count 1 -run $name
    ;;

    stop)
        rm_containers
    ;;

    cleanup)
        rm -f gobgp gobgpd gobgp_2.11.0_linux_amd64.tar.gz Dockerfile rustybgpd README.md LICENSE
    ;;

    *)
        echo "Usage: {build|start|run|stop|cleanup}" >&2
        exit 1
    ;;
esac

exit 0
