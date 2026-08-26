#!/usr/bin/env bash
# Team13 单进程版本化迁移门禁。默认只检查；写迁移要求服务已停止、备份 SHA 已验证、独占锁成功。
set -euo pipefail

umask 077

MODE="check"
DB="${TEAM13_DB_PATH:-/opt/team13-board/board.db}"
MIGRATIONS="${TEAM13_MIGRATIONS_DIR:-/opt/team13-board/ops/migrations}"
TARGET="${TEAM13_SCHEMA_TARGET:-3}"
SERVICE="${TEAM13_SERVICE:-team13-board.service}"
LOCK_DIR="${TEAM13_MIGRATION_LOCK_DIR:-/run/lock/team13-board-migrate.lock}"
RUN_AS="${TEAM13_MIGRATION_RUN_AS:-tanboard}"
BACKUP_SHA=""

usage() {
  printf '%s\n' \
    'Usage:' \
    '  run_migration_v3.sh --check [--target 3]' \
    '  run_migration_v3.sh --apply --backup-sha /opt/team13-board-hourly-backup/YYYY-MM-DD/board_*.db.gz.sha256' \
    '' \
    '写迁移不会自行 stop/start 服务；操作人必须先停服务，脚本会复核。'
}

die() { printf '[team13 migration] ERROR: %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --check) MODE="check"; shift ;;
    --apply) MODE="apply"; shift ;;
    --db) [[ $# -ge 2 ]] || die "--db requires path"; DB="$2"; shift 2 ;;
    --migrations) [[ $# -ge 2 ]] || die "--migrations requires path"; MIGRATIONS="$2"; shift 2 ;;
    --target) [[ $# -ge 2 ]] || die "--target requires number"; TARGET="$2"; shift 2 ;;
    --service) [[ $# -ge 2 ]] || die "--service requires name or none"; SERVICE="$2"; shift 2 ;;
    --lock-dir) [[ $# -ge 2 ]] || die "--lock-dir requires path"; LOCK_DIR="$2"; shift 2 ;;
    --run-as) [[ $# -ge 2 ]] || die "--run-as requires user or empty"; RUN_AS="$2"; shift 2 ;;
    --backup-sha) [[ $# -ge 2 ]] || die "--backup-sha requires path"; BACKUP_SHA="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ "$TARGET" =~ ^[0-9]+$ ]] && (( TARGET >= 1 && TARGET <= 9999 )) || die "target must be 1..9999"
[[ -f "$DB" ]] || die "database missing"
[[ -d "$MIGRATIONS" ]] || die "migrations directory missing"
case "$DB$MIGRATIONS$LOCK_DIR$BACKUP_SHA" in *"'"*|*$'\n'*) die "unsafe path character" ;; esac

realpath_py() {
  python3 - "$1" <<'PY'
from __future__ import print_function
import os, sys
print(os.path.realpath(sys.argv[1]))
PY
}

if [[ "${TEAM13_TEST_MODE:-0}" == "1" ]]; then
  [[ -n "${TEAM13_TEST_BASE:-}" ]] || die "TEAM13_TEST_BASE required"
  test_base="$(realpath_py "$TEAM13_TEST_BASE")"
  for path in "$DB" "$MIGRATIONS" "$(dirname "$LOCK_DIR")"; do
    case "$(realpath_py "$path")" in "$test_base"|"$test_base"/*) ;; *) die "test path escapes base: $path" ;; esac
  done
else
  [[ "$(realpath_py "$DB")" == "/opt/team13-board/board.db" ]] || die "production db path rejected"
  [[ "$(realpath_py "$MIGRATIONS")" == "/opt/team13-board/ops/migrations" ]] || die "production migrations path rejected"
  [[ "$LOCK_DIR" == "/run/lock/team13-board-migrate.lock" ]] || die "production lock path rejected"
  [[ "$SERVICE" == "team13-board.service" ]] || die "production service name rejected"
  [[ "$(id -u)" == "0" ]] || die "production migration gate must run as root"
fi

if [[ "$MODE" == "apply" ]]; then
  [[ -n "$BACKUP_SHA" && -f "$BACKUP_SHA" ]] || die "--apply requires an existing backup .sha256"
  artifact="${BACKUP_SHA%.sha256}"
  [[ -f "$artifact" ]] || die "backup artifact missing: $artifact"
  if [[ "${TEAM13_TEST_MODE:-0}" != "1" ]]; then
    case "$(realpath_py "$BACKUP_SHA")" in /opt/team13-board-hourly-backup/*/*.db.gz.sha256) ;; *) die "backup proof path rejected" ;; esac
  fi
  expected="$(awk 'NR==1{print $1}' "$BACKUP_SHA")"
  [[ "$expected" =~ ^[0-9a-fA-F]{64}$ ]] || die "invalid backup checksum"
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$artifact" | awk '{print $1}')"
  else
    actual="$(shasum -a 256 "$artifact" | awk '{print $1}')"
  fi
  actual="$(printf '%s' "$actual" | tr 'A-F' 'a-f')"
  expected="$(printf '%s' "$expected" | tr 'A-F' 'a-f')"
  [[ "$actual" == "$expected" ]] || die "backup checksum mismatch"
  gzip -t "$artifact"
  if [[ "$SERVICE" != "none" ]]; then
    state="$(systemctl is-active "$SERVICE" 2>/dev/null || true)"
    [[ "$state" != "active" && "$state" != "activating" ]] || die "service must be stopped before migration"
  fi
fi

mkdir -p "$(dirname "$LOCK_DIR")"
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  owner="$(sed -n '1p' "$LOCK_DIR/owner" 2>/dev/null || true)"
  die "migration lock is busy or stale${owner:+: $owner}"
fi
printf 'pid=%s mode=%s started=%s\n' "$$" "$MODE" "$(date -u +%FT%TZ)" > "$LOCK_DIR/owner"
chmod 700 "$LOCK_DIR"

cleanup() {
  case "$LOCK_DIR" in
    /run/lock/team13-board-migrate.lock|"${TEAM13_TEST_BASE:-/nonexistent}"/*)
      [[ ! -f "$LOCK_DIR/owner" ]] || unlink "$LOCK_DIR/owner"
      rmdir "$LOCK_DIR" 2>/dev/null || true
      ;;
  esac
}
trap cleanup EXIT HUP INT TERM

python_cmd=(python3 - "$MODE" "$DB" "$MIGRATIONS" "$TARGET")
if [[ "$MODE" == "apply" && -n "$RUN_AS" && "$(id -u)" == "0" ]]; then
  python_cmd=(sudo -u "$RUN_AS" python3 - "$MODE" "$DB" "$MIGRATIONS" "$TARGET")
fi

"${python_cmd[@]}" <<'PY'
from __future__ import print_function
import datetime
import hashlib
import os
import re
import sqlite3
import sys

mode, db_path, migration_dir, target_raw = sys.argv[1:5]
target = int(target_raw)
pattern = re.compile(r"^(\d{4})_([A-Za-z0-9_-]+)\.sql$")
migrations = []
seen = set()
for name in sorted(os.listdir(migration_dir)):
    match = pattern.match(name)
    if not match:
        if name.endswith(".sql"):
            raise SystemExit("invalid migration filename: %s" % name)
        continue
    version = int(match.group(1))
    if version in seen:
        raise SystemExit("duplicate migration version: %d" % version)
    seen.add(version)
    if version <= target:
        path = os.path.join(migration_dir, name)
        raw = open(path, "rb").read()
        migrations.append((version, name, hashlib.sha256(raw).hexdigest(), raw.decode("utf-8")))
if target not in seen:
    raise SystemExit("target migration file missing: %04d" % target)

uri = "file:%s?mode=%s" % (db_path, "ro" if mode == "check" else "rw")
conn = sqlite3.connect(uri, uri=True, timeout=30)
try:
    table_exists = conn.execute("select count(*) from sqlite_master where type='table' and name='team13_schema_migrations'").fetchone()[0]
    applied = {}
    if table_exists:
        for row in conn.execute("select version,name,checksum from team13_schema_migrations"):
            applied[int(row[0])] = (row[1], row[2])
    missing_applied = sorted(v for v in applied if v <= target and v not in seen)
    if missing_applied:
        raise SystemExit("applied migration file missing: %s" %
                         ",".join("%04d" % v for v in missing_applied))
    for version, name, checksum, _ in migrations:
        if version in applied and applied[version][1] != checksum:
            raise SystemExit("applied migration checksum changed: %04d" % version)
    pending = [m for m in migrations if m[0] not in applied]
    current = max(applied.keys()) if applied else 0
    if mode == "check":
        print("mode=check current=%d target=%d pending=%s" %
              (current, target, ",".join("%04d" % x[0] for x in pending) or "none"))
        raise SystemExit(0 if current == target and not pending else 3)

    conn.execute("begin immediate")
    conn.execute("""create table if not exists team13_schema_migrations(
        version integer primary key, name text not null, checksum text not null,
        applied_at text not null)""")
    conn.commit()
    for version, name, checksum, sql in pending:
        lowered = re.sub(r"--[^\n]*", "", sql).lower()
        if re.search(r"\b(begin|commit|rollback|vacuum|attach|detach)\b|writable_schema|journal_mode", lowered):
            raise SystemExit("forbidden transaction or database-control statement: %s" % name)
        statements = []
        buf = ""
        for line in sql.splitlines(True):
            buf += line
            if sqlite3.complete_statement(buf):
                if buf.strip():
                    statements.append(buf)
                buf = ""
        if buf.strip():
            raise SystemExit("incomplete SQL statement: %s" % name)
        try:
            conn.execute("begin immediate")
            for statement in statements:
                conn.execute(statement)
            conn.execute("insert into team13_schema_migrations(version,name,checksum,applied_at) values(?,?,?,?)",
                         (version, name, checksum, datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"))
            conn.commit()
            print("applied=%04d name=%s" % (version, name))
        except Exception:
            conn.rollback()
            raise
    quick = conn.execute("pragma quick_check").fetchone()[0]
    final = conn.execute("select coalesce(max(version),0) from team13_schema_migrations").fetchone()[0]
    if quick != "ok" or int(final) != target:
        raise SystemExit("post-migration gate failed: quick=%s version=%s target=%s" % (quick, final, target))
    print("mode=apply schema=%s quick_check=ok" % final)
finally:
    conn.close()
PY

trap - EXIT HUP INT TERM
cleanup
