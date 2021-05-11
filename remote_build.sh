#!/usr/bin/env bash
set -euo pipefail

# verify a valid build
cargo build || exit 1

ssh ianwahbe@chimera "rm -rf src/rdma-fuse"
mv target /tmp/target-rdma-folder 
scp -r ../rdma-fuse  ianwahbe@chimera:/home/ianwahbe/src/rdma-fuse
mv /tmp/target-rdma-folder target
ssh ianwahbe@chimera 
