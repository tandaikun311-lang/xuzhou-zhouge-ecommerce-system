#!/usr/bin/env bash
# Team13 小时级 SQLite 备份：时间戳文件、事务一致 .backup、quick_check、gzip、SHA256。
set -euo pipefail

umask 077

DB="${TEAM13_DB_PATH:-/opt/your-app-dir/board.db}"
BACKUP_ROOT="${TEAM13_DB_HOURLY_BACKUP_ROOT:-/opt/your-app-dir-hourly-backup}"
STAGE_ROOT="${TEAM13_DB_BACKUP_STAGE_ROOT:-/opt/your-app-dir/.backup-stage}"
LOCK_DIR="${TEAM13_DB_BACKUP_LOCK_DIR:-/run/lock/team13-board-hourly-backup.lock}"
RUN_AS="${TEAM13_DB_BACKUP_RUN_AS:-tanboard}"
RETAIN_DAYS="${TEAM13_DB_HOURLY_RETAIN_DAYS:-14}"
MAX_SOURCE_BYTES="${TEAM13_DB_BACKUP_MAX_SOURCE_BYTES:-21474836480}"
SQLITE_BIN="${TEAM13_SQLITE_BIN:-sqlite3}"

die() { printf '[team13 hourly db backup] ERROR: %s\n' "$*" >&2; exit 1; }

[[ "$RETAIN_DAYS" =~ ^[0-9]+$ ]] && (( RETAIN_DAYS >= 2 && RETAIN_DAYS <= 90 )) || die "retain days must be 2..90"
[[ "$MAX_SOURCE_BYTES" =~ ^[0-9]+$ ]] && (( MAX_SOURCE_BYTES >= 1048576 )) || die "invalid source size limit"
command -v "$SQLITE_BIN" >/dev/null 2>&1 || die "sqlite3 not found"
command -v gzip >/dev/null 2>&1 || die "gzip not found"

canonical_existing() {
  python3 - "$1" <<'PY'
from __future__ import print_function
import os, sys
print(os.path.realpath(sys.argv[1]))
PY
}

case "$DB$BACKUP_ROOT$STAGE_ROOT$LOCK_DIR" in
  *"'"*|*$'\n'*) die "unsafe path character" ;;
esac

if [[ "${TEAM13_TEST_MODE:-0}" == "1" ]]; then
  [[ -n "${TEAM13_TEST_BASE:-}" ]] || die "TEAM13_TEST_BASE required"
  test_base="$(canonical_existing "$TEAM13_TEST_BASE")"
  case "$(canonical_existing "$DB")" in "$test_base"/*) ;; *) die "test db escapes base" ;; esac
  case "$(canonical_existing "$BACKUP_ROOT")" in "$test_base"/*) ;; *) die "test backup root escapes base" ;; esac
  case "$(canonical_existing "$STAGE_ROOT")" in "$test_base"/*) ;; *) die "test stage root escapes base" ;; esac
  case "$(canonical_existing "$(dirname "$LOCK_DIR")")" in "$test_base"/*|"$test_base") ;; *) die "test lock escapes base" ;; esac
else
  [[ "$(canonical_existing "$DB")" == "/opt/your-app-dir/board.db" ]] || die "production db path rejected"
  [[ "$BACKUP_ROOT" == "/opt/your-app-dir-hourly-backup" ]] || die "production backup root rejected"
  [[ "$STAGE_ROOT" == "/opt/your-app-dir/.backup-stage" ]] || die "production stage root rejected"
  [[ "$LOCK_DIR" == "/run/lock/team13-board-hourly-backup.lock" ]] || die "production lock path rejected"
  [[ "$(id -u)" == "0" ]] || die "production backup must run as root"
fi

[[ -f "$DB" ]] || die "source database missing"
source_bytes="$(wc -c < "$DB" | tr -d ' ')"
(( source_bytes <= MAX_SOURCE_BYTES )) || die "source database exceeds safety limit"

mkdir -p "$(dirname "$LOCK_DIR")"
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  owner="$(sed -n '1p' "$LOCK_DIR/owner" 2>/dev/null || true)"
  die "another backup is running or stale lock exists${owner:+: $owner}"
fi
printf 'pid=%s started=%s\n' "$$" "$(date -u +%FT%TZ)" > "$LOCK_DIR/owner"
chmod 700 "$LOCK_DIR"

stage_db=""
archive_tmp=""
sum_tmp=""
meta_tmp=""
cleanup() {
  for path in "$stage_db" "$archive_tmp" "$sum_tmp" "$meta_tmp"; do
    [[ -z "$path" || ! -e "$path" ]] || unlink "$path"
  done
  case "$LOCK_DIR" in
    /run/lock/team13-board-hourly-backup.lock|"${TEAM13_TEST_BASE:-/nonexistent}"/*)
      [[ ! -f "$LOCK_DIR/owner" ]] || unlink "$LOCK_DIR/owner"
      rmdir "$LOCK_DIR" 2>/dev/null || true
      ;;
  esac
}
trap cleanup EXIT HUP INT TERM

day="$(date -u +%F)"
stamp="$(date -u +%Y%m%d_%H%M%S)"
dest_dir="$BACKUP_ROOT/$day"
mkdir -p "$dest_dir" "$STAGE_ROOT"
chmod 700 "$BACKUP_ROOT" "$dest_dir" "$STAGE_ROOT"
if [[ -n "$RUN_AS" && "$(id -u)" == "0" ]]; then
  chown "$RUN_AS":"$RUN_AS" "$STAGE_ROOT"
fi

stage_db="$(mktemp "$STAGE_ROOT/.board_backup.part.XXXXXX")"
if [[ -n "$RUN_AS" && "$(id -u)" == "0" ]]; then
  chown "$RUN_AS":"$RUN_AS" "$stage_db"
  printf '.timeout 10000\n.backup %s\n' "$stage_db" | sudo -u "$RUN_AS" "$SQLITE_BIN" "$DB"
else
  printf '.timeout 10000\n.backup %s\n' "$stage_db" | "$SQLITE_BIN" "$DB"
fi

quick="$($SQLITE_BIN "file:$stage_db?mode=ro" "pragma quick_check;")"
[[ "$quick" == "ok" ]] || die "quick_check failed: $quick"

schema_version=0
has_migrations="$($SQLITE_BIN "file:$stage_db?mode=ro" "select count(*) from sqlite_master where type='table' and name='team13_schema_migrations';")"
if [[ "$has_migrations" == "1" ]]; then
  schema_version="$($SQLITE_BIN "file:$stage_db?mode=ro" "select coalesce(max(version),0) from team13_schema_migrations;")"
fi

archive="$dest_dir/board_${stamp}.db.gz"
archive_sum="$archive.sha256"
archive_meta="$archive.meta"
[[ ! -e "$archive" && ! -e "$archive_sum" && ! -e "$archive_meta" ]] || die "timestamp collision"

archive_tmp="$(mktemp "$dest_dir/.board_archive.part.XXXXXX")"
sum_tmp="$(mktemp "$dest_dir/.board_sum.part.XXXXXX")"
meta_tmp="$(mktemp "$dest_dir/.board_meta.part.XXXXXX")"
gzip -c "$stage_db" > "$archive_tmp"
gzip -t "$archive_tmp"

if command -v sha256sum >/dev/null 2>&1; then
  digest="$(sha256sum "$archive_tmp" | awk '{print $1}')"
else
  digest="$(shasum -a 256 "$archive_tmp" | awk '{print $1}')"
fi
printf '%s  %s\n' "$digest" "$(basename "$archive")" > "$sum_tmp"
printf 'created_at=%s\nsource=%s\nsource_bytes=%s\nschema_version=%s\nquick_check=ok\n' \
  "$(date -u +%FT%TZ)" "$DB" "$source_bytes" "$schema_version" > "$meta_tmp"
chmod 600 "$archive_tmp" "$sum_tmp" "$meta_tmp"
mv "$archive_tmp" "$archive"
mv "$sum_tmp" "$archive_sum"
mv "$meta_tmp" "$archive_meta"
unlink "$stage_db"
stage_db=""; archive_tmp=""; sum_tmp=""; meta_tmp=""

# 只删除固定根目录下、固定时间戳命名且超过保留期的备份三件套。
find "$BACKUP_ROOT" -mindepth 2 -maxdepth 2 -type f -name 'board_????????_??????.db.gz' -mtime "+$RETAIN_DAYS" -print |
while IFS= read -r old; do
  case "$old" in "$BACKUP_ROOT"/*/board_????????_??????.db.gz) ;; *) die "unsafe retention target" ;; esac
  [[ ! -e "$old.sha256" ]] || unlink "$old.sha256"
  [[ ! -e "$old.meta" ]] || unlink "$old.meta"
  unlink "$old"
done
find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -empty -delete

printf '[team13 hourly db backup] %s ok archive=%s source_bytes=%s schema_version=%s retain_days=%s\n' \
  "$(date -u +%FT%TZ)" "$archive" "$source_bytes" "$schema_version" "$RETAIN_DAYS"

trap - EXIT HUP INT TERM
cleanup
