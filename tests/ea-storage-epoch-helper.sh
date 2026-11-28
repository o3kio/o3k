#!/usr/bin/env bash
set -Eeuo pipefail
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
if [ "$(id -u)" -ne 0 ]; then echo 'SKIP: helper behavior test requires root'; exit 0; fi
mkdir "$root/storage"
printf 'O3K_STORAGE_AGENT_EPOCH=old\n' > "$root/storage/o3k-storage.env"
printf 'O3K_STORAGE_AGENT_EPOCH=old\n' > "$root/o3kd.env"
chmod 600 "$root/storage/o3k-storage.env" "$root/o3kd.env"
O3K_EPOCH_HELPER_TEST=1 O3K_EPOCH_HELPER_ROOT="$root" bash packaging/o3k-sync-storage-epoch new-epoch
grep -qx 'O3K_STORAGE_AGENT_EPOCH=new-epoch' "$root/storage/o3k-storage.env"
grep -qx 'O3K_STORAGE_AGENT_EPOCH=new-epoch' "$root/o3kd.env"
! O3K_EPOCH_HELPER_TEST=1 O3K_EPOCH_HELPER_ROOT="$root" bash packaging/o3k-sync-storage-epoch 'bad;epoch'
bin="$root/bin"; mkdir "$bin"; calls="$root/mv.calls"; : > "$calls"
cat > "$bin/mv" <<EOF
#!/bin/sh
n=\$(wc -l < "$calls")
echo x >> "$calls"
[ "\$n" -eq 1 ] && exec /bin/mv "\$@"
exit 1
EOF
cat > "$bin/systemctl" <<'EOF'
#!/bin/sh
echo restart >> "$O3K_HELPER_SYSTEMCTL_LOG"
EOF
chmod +x "$bin/mv" "$bin/systemctl"
: > "$calls"
O3K_HELPER_SYSTEMCTL_LOG="$root/systemctl.log" PATH="$bin:/usr/bin:/bin" O3K_EPOCH_HELPER_TEST=1 O3K_EPOCH_HELPER_ROOT="$root" bash packaging/o3k-sync-storage-epoch failed-epoch || true
[ "$(cat "$root/storage/o3k-storage.env")" = 'O3K_STORAGE_AGENT_EPOCH=failed-epoch' ]
[ "$(cat "$root/o3kd.env")" = 'O3K_STORAGE_AGENT_EPOCH=old' ]
[ ! -s "$root/systemctl.log" ]
PATH="$bin:/usr/bin:/bin" O3K_HELPER_SYSTEMCTL_LOG="$root/systemctl.log" O3K_EPOCH_HELPER_TEST=1 O3K_EPOCH_HELPER_ROOT="$root" bash packaging/o3k-sync-storage-epoch retry-epoch
[ "$(cat "$root/o3kd.env")" = 'O3K_STORAGE_AGENT_EPOCH=retry-epoch' ]
[ "$(wc -l < "$root/systemctl.log")" -eq 2 ]
echo 'EA storage epoch helper: PASS'
