#!/bin/bash -xe

export HOST=imslp-mcp.exe.xyz
export GOOS=linux GOARCH=amd64
go build -v -o /tmp/imslpcli --tags release
export VER=`git rev-parse --short HEAD`
export TARGET=imslpcli-$(date +%Y%m%d-%H%M)-$VER
scp /tmp/imslpcli $HOST:$TARGET
ssh $HOST ln -sf $TARGET imslpcli
ssh $HOST 'bash -lc "systemctl --user restart imslp-mcp"'
