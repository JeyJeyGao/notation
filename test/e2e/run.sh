#!/bin/bash -e

# check notation binary path.
export NOTATION_E2E_BINARY_PATH=$(if [ ! -z "$1" ]; then realpath $1; fi)
if [ ! -f "$NOTATION_E2E_BINARY_PATH" ];then
    echo "notation binary path doesn't exist."
    echo ""
    echo "run.sh <notation-binary-path> [old-notation-binary-path]"
    exit 1
fi

# check old notation binary path for forward compatibility test.
export NOTATION_E2E_OLD_BINARY_PATH=$(if [ ! -z "$2" ]; then realpath $2; fi)
if [ ! -f "$NOTATION_E2E_OLD_BINARY_PATH" ];then
    OLD_NOTATION_DIR=/tmp/notation_old
    export NOTATION_E2E_OLD_BINARY_PATH=$OLD_NOTATION_DIR/notation
    mkdir -p $OLD_NOTATION_DIR

    echo "Old notation binary path doesn't exist."
    echo "Try to use old notation binary at $NOTATION_E2E_OLD_BINARY_PATH"

    if [ ! -f $NOTATION_E2E_OLD_BINARY_PATH ]; then
        TAG=1.0.0-rc.1 # without 'v'
        echo "Didn't find old notation binary locally. Try to download notation v$TAG."

        TAR_NAME=notation_${TAG}_linux_amd64.tar.gz
        URL=https://github.com/notaryproject/notation/releases/download/v${TAG}/$TAR_NAME
        wget $URL -P $OLD_NOTATION_DIR
        tar -xf $OLD_NOTATION_DIR/$TAR_NAME -C $OLD_NOTATION_DIR

        if [ ! -f $NOTATION_E2E_OLD_BINARY_PATH ]; then
            echo "Failed to download old notation binary for forward compatibility test."
            exit 1
        fi
        echo "Downloaded notation v$TAG at $NOTATION_E2E_OLD_BINARY_PATH"
    fi
fi

# install dependency
go install -mod=mod github.com/onsi/ginkgo/v2/ginkgo

# set environment variable for E2E testing
REG_HOST=localhost
REG_PORT=5000
ZOT_CONTAINER_NAME=zot

export NOTATION_E2E_REGISTRY_HOST=$REG_HOST:$REG_PORT
export NOTATION_E2E_REGISTRY_USERNAME=testuser
export NOTATION_E2E_REGISTRY_PASSWORD=testpassword
export NOTATION_E2E_KEY_PATH=`pwd`/testdata/config/localkeys/e2e.key
export NOTATION_E2E_CERT_PATH=`pwd`/testdata/config/localkeys/e2e.crt
export NOTATION_E2E_CONFIG_PATH=`pwd`/testdata/config
export NOTATION_E2E_OCI_LAYOUT_PATH=`pwd`/testdata/registry/oci_layout
export NOTATION_E2E_TEST_REPO=e2e
export NOTATION_E2E_TEST_TAG=v1
export REGISTRY_STORAGE_PATH=/tmp/zot-registry

# create temperory directory for Zot storage
mkdir -p /tmp/zot-registry && echo "Zot storage path: $REGISTRY_STORAGE_PATH created"

# start zot
docker run -d -p $REG_PORT:$REG_PORT -it --name $ZOT_CONTAINER_NAME \
    --mount type=bind,source=`pwd`/testdata/registry/zot/,target=/etc/zot \
    --mount type=bind,source=$REGISTRY_STORAGE_PATH,target=/var/lib/registry \
    --rm ghcr.io/project-zot/zot-minimal-linux-amd64:latest

# stop container and clean zot storage directory when exit
function cleanup {
    docker container stop $ZOT_CONTAINER_NAME 1>/dev/null && echo "Zot stopped"
    rm -rf $REGISTRY_STORAGE_PATH && echo "Zot storage path: $REGISTRY_STORAGE_PATH deleted"
}
trap cleanup EXIT

# run tests
ginkgo -r -p -v
