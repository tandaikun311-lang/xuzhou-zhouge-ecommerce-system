#!/usr/bin/env bash
# Team13 上传付款凭证备份：完整 tar.gz + 归档 SHA256 + 归档内逐文件 SHA256。
# 默认由 root 运行；只读取 _uploads，不修改上传源。
set -euo pipefail

umask 077

UPLOAD_ROOT="${TEAM13_UPLOAD_ROOT:-/www/wwwroot/default-site/zb-t1365d2f4f3/_uploads}"
BACKUP_ROOT="${TEAM13_UPLOAD_BACKUP_ROOT:-/opt/team13-uploads-backup}"
RETAIN_DAYS="${TEAM13_UPLOAD_BACKUP_RETAIN_DAYS:-30}"
MAX_SOURCE_BYTES="${TEAM13_UPLOAD_BACKUP_MAX_SOURCE_BYTES:-21474836480}"
TEST_MODE="${TEAM13_TEST_MODE:-0}"
TEST_BASE="${TEAM13_TEST_BASE:-}"

die() {
  printf '[team13 uploads backup] ERROR: %s\n' "$*" >&2
  exit 1
}

is_uint() {
  [[ "$1" =~ ^[0-9]+$ ]]
}

canonical_existing() {
  readlink -f "$1"
}

validate_paths() {
  [[ -d "$UPLOAD_ROOT" ]] || die "upload root missing: $UPLOAD_ROOT"
  is_uint "$RETAIN_DAYS" || die "retain days must be an unsigned integer"
  is_uint "$MAX_SOURCE_BYTES" || die "max source bytes must be an unsigned integer"
  (( RETAIN_DAYS >= 1 && RETAIN_DAYS <= 3650 )) || die "retain days out of range"
  (( MAX_SOURCE_BYTES >= 1048576 )) || die "max source bytes too small"

  local upload_real
  upload_real="$(canonical_existing "$UPLOAD_ROOT")"

  if [[ "$TEST_MODE" == "1" ]]; then
    [[ -n "$TEST_BASE" && -d "$TEST_BASE" ]] || die "test mode requires an existing TEAM13_TEST_BASE"
    local test_real
    test_real="$(canonical_existing "$TEST_BASE")"
    case "$test_real" in
      /tmp/team13-ops-fixture.*|/private/tmp/team13-ops-fixture.*) ;;
      *) die "unsafe test base: $test_real" ;;
    esac
    case "$upload_real" in
      "$test_real"/*) ;;
      *) die "test upload root must be below test base" ;;
    esac
    case "$BACKUP_ROOT" in
      "$TEST_BASE"/*) ;;
      *) die "test backup root must be below test base" ;;
    esac
  else
    [[ "$upload_real" == "/www/wwwroot/default-site/zb-t1365d2f4f3/_uploads" ]] || \
      die "production upload root must be the fixed Team13 _uploads path"
    [[ "$BACKUP_ROOT" == "/opt/team13-uploads-backup" ]] || \
      die "production backup root must be /opt/team13-uploads-backup"
    [[ "$(id -u)" == "0" ]] || die "production backup must run as root"
  fi

  local unsafe_entry
  unsafe_entry="$(find "$upload_real" -xdev ! -type f ! -type d -print -quit 2>/dev/null || true)"
  [[ -z "$unsafe_entry" ]] || die "symlink or special file is not allowed: $unsafe_entry"
}

safe_cleanup_file() {
  local path="${1:-}"
  [[ -n "$path" ]] || return 0
  case "$path" in
    "$BACKUP_ROOT"/.team13_uploads_*.part.*) [[ ! -e "$path" ]] || unlink "$path" ;;
    *) printf '[team13 uploads backup] refuse unsafe cleanup: %s\n' "$path" >&2 ;;
  esac
}

validate_paths
mkdir -p "$BACKUP_ROOT"
chmod 700 "$BACKUP_ROOT"

UPLOAD_ROOT="$(canonical_existing "$UPLOAD_ROOT")"
BACKUP_ROOT="$(canonical_existing "$BACKUP_ROOT")"

source_bytes="$(python3 - "$UPLOAD_ROOT" <<'PY'
from __future__ import print_function
import os
import sys
total = 0
for base, dirs, files in os.walk(sys.argv[1]):
    for name in files:
        total += os.stat(os.path.join(base, name)).st_size
print(total)
PY
)"
is_uint "$source_bytes" || die "cannot determine source size"
(( source_bytes <= MAX_SOURCE_BYTES )) || die "source size $source_bytes exceeds limit $MAX_SOURCE_BYTES"

available_kb="$(df -Pk "$BACKUP_ROOT" | awk 'NR==2 {print $4}')"
is_uint "$available_kb" || die "cannot determine free disk space"
required_kb=$(( source_bytes / 1024 + 524288 ))
(( available_kb >= required_kb )) || die "insufficient free space for safe archive staging"

stamp="$(date +%Y%m%d_%H%M%S)"
base="uploads_${stamp}"
archive_final="$BACKUP_ROOT/${base}.tar.gz"
archive_sum_final="${archive_final}.sha256"
files_sum_final="$BACKUP_ROOT/${base}.files.sha256"

archive_tmp="$(mktemp "$BACKUP_ROOT/.team13_uploads_archive.part.XXXXXX")"
archive_sum_tmp="$(mktemp "$BACKUP_ROOT/.team13_uploads_archive_sum.part.XXXXXX")"
files_sum_tmp="$(mktemp "$BACKUP_ROOT/.team13_uploads_files_sum.part.XXXXXX")"

cleanup() {
  safe_cleanup_file "$archive_tmp"
  safe_cleanup_file "$archive_sum_tmp"
  safe_cleanup_file "$files_sum_tmp"
}
trap cleanup EXIT HUP INT TERM

parent="$(dirname "$UPLOAD_ROOT")"
leaf="$(basename "$UPLOAD_ROOT")"

# tar 读取期间如果文件发生变化会非零退出，临时文件不会被发布为有效备份。
tar -C "$parent" -czf "$archive_tmp" "$leaf"
gzip -t "$archive_tmp"

# 清单从归档内容计算，而不是从可能正在变化的源目录计算，确保清单与备份完全一致。
python3 - "$archive_tmp" > "$files_sum_tmp" <<'PY'
from __future__ import print_function
import hashlib
import posixpath
import sys
import tarfile

archive = sys.argv[1]
with tarfile.open(archive, "r:gz") as tf:
    members = sorted([m for m in tf.getmembers() if m.isfile()], key=lambda m: m.name)
    for member in members:
        name = posixpath.normpath(member.name)
        if name.startswith("../") or name.startswith("/") or name == "..":
            raise SystemExit("unsafe member path: %s" % member.name)
        fh = tf.extractfile(member)
        digest = hashlib.sha256()
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        print("%s  %s" % (digest.hexdigest(), name))
PY

archive_hash="$(sha256sum "$archive_tmp" | awk '{print $1}')"
printf '%s  %s\n' "$archive_hash" "$(basename "$archive_final")" > "$archive_sum_tmp"

chmod 600 "$archive_tmp" "$archive_sum_tmp" "$files_sum_tmp"
mv "$archive_tmp" "$archive_final"
mv "$archive_sum_tmp" "$archive_sum_final"
mv "$files_sum_tmp" "$files_sum_final"

# 只清理固定目录第一层、固定命名的普通文件；不递归删除目录，不使用 rm -rf。
find "$BACKUP_ROOT" -maxdepth 1 -type f \
  \( -name 'uploads_*.tar.gz' -o -name 'uploads_*.tar.gz.sha256' -o -name 'uploads_*.files.sha256' \) \
  -mtime "+$RETAIN_DAYS" -delete

file_count="$(wc -l < "$files_sum_final" | tr -d ' ')"
printf '[team13 uploads backup] %s ok archive=%s source_bytes=%s files=%s retain_days=%s\n' \
  "$(date -u +%FT%TZ)" "$archive_final" "$source_bytes" "$file_count" "$RETAIN_DAYS"

trap - EXIT HUP INT TERM
