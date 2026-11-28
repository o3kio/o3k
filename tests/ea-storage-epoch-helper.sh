#!/usr/bin/env bash
set -Eeuo pipefail
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
mkdir "$root/storage"
printf 'O3K_STORAGE_AGENT_EPOCH=old\n' > "$root/storage/o3k-storage.env"
printf 'O3K_STORAGE_AGENT_EPOCH=old\n' > "$root/o3kd.env"
chmod 600 "$root/storage/o3k-storage.env" "$root/o3kd.env"
O3K_EPOCH_HELPER_TEST=1 O3K_EPOCH_HELPER_ROOT="$root" bash packaging/o3k-sync-storage-epoch new-epoch
grep -qx 'O3K_STORAGE_AGENT_EPOCH=new-epoch' "$root/storage/o3k-storage.env"
grep -qx 'O3K_STORAGE_AGENT_EPOCH=new-epoch' "$root/o3kd.env"
! O3K_EPOCH_HELPER_TEST=1 O3K_EPOCH_HELPER_ROOT="$root" bash packaging/o3k-sync-storage-epoch 'bad;epoch'
echo 'EA storage epoch helper: PASS'
