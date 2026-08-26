#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Team13 徐州舟格电商运营系统每日健康巡检。

只检查运维链路，不读取或修改业务明细：
health、systemd、SQLite quick/integrity、schema/关键约束、数据库/上传备份新鲜度、
磁盘、TLS 证书和近 24 小时 5xx。

兼容 Python 3.6，仅使用标准库。配置来源：
1. /opt/team13-board/private/runtime.env（TEAM13_* 键）；
2. /opt/team13-board/private/health.conf（JSON，同名配置覆盖 runtime.env）。

退出码：0=全部正常，1=有警告，2=有故障。
"""

from __future__ import print_function

import argparse
import datetime
import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


DEFAULT_RUNTIME = "/opt/team13-board/private/runtime.env"
DEFAULT_HEALTH_CONF = "/opt/team13-board/private/health.conf"

DEFAULTS = {
    "service": "team13-board.service",
    "service_user": "tanboard",
    "health_url": "https://tandaikun.com/board13/api/health",
    "db_path": "/opt/team13-board/board.db",
    "db_backup_root": "/opt/team13-board-hourly-backup",
    "db_backup_glob": "*/*.db.gz",
    "db_backup_max_hours": 2,
    "db_backup_require_sha256": True,
    "expected_schema_version": 3,
    "uploads_backup_root": "/opt/team13-uploads-backup",
    "uploads_backup_glob": "uploads_*.tar.gz",
    "uploads_backup_max_hours": 28,
    "disk_path": "/",
    "disk_warn_percent": 75,
    "disk_bad_percent": 88,
    "disk_min_free_gb": 5,
    "cert_path": "/etc/letsencrypt/live/tandaikun.com/cert.pem",
    "cert_warn_days": 21,
    "cert_bad_days": 7,
    "nginx_access_log": "/var/log/nginx/access.log",
    "site_match": "board13/api|zb-t1365d2f4f3",
    "five_xx_warn": 1,
    "five_xx_bad": 10,
    "history_dir": "/opt/team13-board/health_history_v2",
    "notify_webhook": "",
    "serverchan_sendkey": "",
    "notify_on_ok": False,
    "http_timeout_seconds": 12,
    "command_timeout_seconds": 120,
}

ENV_MAP = {
    "TEAM13_SERVICE": "service",
    "TEAM13_SERVICE_USER": "service_user",
    "TEAM13_HEALTH_URL": "health_url",
    "TEAM13_DB_PATH": "db_path",
    "TEAM13_DB_BACKUP_ROOT": "db_backup_root",
    "TEAM13_DB_BACKUP_GLOB": "db_backup_glob",
    "TEAM13_DB_BACKUP_MAX_HOURS": "db_backup_max_hours",
    "TEAM13_DB_BACKUP_REQUIRE_SHA256": "db_backup_require_sha256",
    "TEAM13_EXPECTED_SCHEMA_VERSION": "expected_schema_version",
    "TEAM13_UPLOADS_BACKUP_ROOT": "uploads_backup_root",
    "TEAM13_UPLOADS_BACKUP_GLOB": "uploads_backup_glob",
    "TEAM13_UPLOADS_BACKUP_MAX_HOURS": "uploads_backup_max_hours",
    "TEAM13_DISK_PATH": "disk_path",
    "TEAM13_DISK_WARN_PERCENT": "disk_warn_percent",
    "TEAM13_DISK_BAD_PERCENT": "disk_bad_percent",
    "TEAM13_DISK_MIN_FREE_GB": "disk_min_free_gb",
    "TEAM13_CERT_PATH": "cert_path",
    "TEAM13_CERT_WARN_DAYS": "cert_warn_days",
    "TEAM13_CERT_BAD_DAYS": "cert_bad_days",
    "TEAM13_NGINX_ACCESS_LOG": "nginx_access_log",
    "TEAM13_SITE_MATCH": "site_match",
    "TEAM13_FIVE_XX_WARN": "five_xx_warn",
    "TEAM13_FIVE_XX_BAD": "five_xx_bad",
    "TEAM13_HISTORY_DIR": "history_dir",
    "TEAM13_NOTIFY_WEBHOOK": "notify_webhook",
    "TEAM13_SERVERCHAN_SENDKEY": "serverchan_sendkey",
    "TEAM13_NOTIFY_ON_OK": "notify_on_ok",
    "TEAM13_HTTP_TIMEOUT_SECONDS": "http_timeout_seconds",
    "TEAM13_COMMAND_TIMEOUT_SECONDS": "command_timeout_seconds",
}

INT_KEYS = set([
    "db_backup_max_hours", "expected_schema_version", "uploads_backup_max_hours", "disk_warn_percent",
    "disk_bad_percent", "disk_min_free_gb", "cert_warn_days", "cert_bad_days",
    "five_xx_warn", "five_xx_bad", "http_timeout_seconds",
    "command_timeout_seconds",
])
BOOL_KEYS = set(["notify_on_ok", "db_backup_require_sha256"])
LEVEL_SCORE = {"ok": 0, "warn": 1, "bad": 2}


def redact(value):
    """避免口令、sendkey 或 webhook query 出现在日志。"""
    text = str(value or "")
    text = re.sub(r"(?i)(password|secret|sendkey|token|key)=([^&\s]+)", r"\1=<redacted>", text)
    return text


def load_env(path):
    out = {}
    try:
        with open(path, "r") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                out[key.strip()] = value.strip()
    except IOError:
        pass
    return out


def load_json(path):
    try:
        with open(path, "r") as fh:
            value = json.load(fh)
        return value if isinstance(value, dict) else {}
    except (IOError, ValueError):
        return {}


def as_bool(value):
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def convert_value(key, value):
    if key in INT_KEYS:
        return int(value)
    if key in BOOL_KEYS:
        return as_bool(value)
    return value


def load_config(runtime_path, health_path):
    cfg = dict(DEFAULTS)
    env = load_env(runtime_path)
    for env_key, cfg_key in ENV_MAP.items():
        if env_key in env:
            cfg[cfg_key] = convert_value(cfg_key, env[env_key])
    overrides = load_json(health_path)
    for key in DEFAULTS:
        if key in overrides:
            cfg[key] = convert_value(key, overrides[key])
    return cfg


def run_command(argv, timeout):
    try:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out, _ = proc.communicate(timeout=timeout)
        return proc.returncode, out.decode("utf-8", "replace").strip()
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
            proc.communicate()
        except Exception:
            pass
        return 124, "command timeout"
    except Exception as exc:
        return 127, "command failed: %s" % redact(repr(exc))


def item(level, title, detail, metrics=None):
    return {
        "level": level,
        "title": title,
        "detail": redact(detail),
        "metrics": metrics or {},
    }


def check_health(cfg):
    started = time.time()
    try:
        req = urllib.request.Request(cfg["health_url"], headers={"User-Agent": "team13-health-v2/1.0"})
        resp = urllib.request.urlopen(req, timeout=int(cfg["http_timeout_seconds"]))
        body = resp.read(4096).decode("utf-8", "replace")
        code = int(resp.getcode())
        parsed = json.loads(body)
        elapsed_ms = int((time.time() - started) * 1000)
        if code == 200 and parsed.get("ok") is True:
            return item("ok", "健康接口", "HTTP 200，ok=true，%dms" % elapsed_ms,
                        {"status": code, "elapsed_ms": elapsed_ms})
        return item("bad", "健康接口", "响应异常：HTTP %d，ok=%r" % (code, parsed.get("ok")))
    except Exception as exc:
        return item("bad", "健康接口", "访问失败：%s" % repr(exc))


def check_service(cfg):
    service = str(cfg["service"])
    if not re.match(r"^[A-Za-z0-9_.@-]+$", service):
        return item("bad", "systemd 服务", "service 配置不安全")
    rc1, active = run_command(["systemctl", "is-active", service], int(cfg["command_timeout_seconds"]))
    rc2, enabled = run_command(["systemctl", "is-enabled", service], int(cfg["command_timeout_seconds"]))
    if rc1 == 0 and active.strip() == "active":
        level = "ok" if rc2 == 0 and enabled.strip() in ("enabled", "static") else "warn"
        return item(level, "systemd 服务", "active=%s，enabled=%s" % (active.strip(), enabled.strip()),
                    {"active": active.strip(), "enabled": enabled.strip()})
    return item("bad", "systemd 服务", "active=%s，enabled=%s" % (active.strip(), enabled.strip()))


def check_database(cfg):
    db_path = os.path.realpath(str(cfg["db_path"]))
    if db_path != "/opt/team13-board/board.db" or not os.path.isfile(db_path):
        return item("bad", "SQLite 完整性", "数据库路径不存在或不是 Team13 固定路径")
    uri = "file:%s?mode=ro" % db_path
    sql = "PRAGMA quick_check; PRAGMA integrity_check;"
    argv = ["sudo", "-u", str(cfg["service_user"]), "sqlite3", uri, sql]
    rc, output = run_command(argv, int(cfg["command_timeout_seconds"]))
    lines = [x.strip().lower() for x in output.splitlines() if x.strip()]
    if rc == 0 and len(lines) >= 2 and all(x == "ok" for x in lines):
        return item("ok", "SQLite 完整性", "quick_check=ok，integrity_check=ok")
    return item("bad", "SQLite 完整性", "检查失败 rc=%d，结果=%s" % (rc, output[:500]))


def sqlite_ro_query(cfg, sql):
    """用服务账号只读查询固定生产库，避免 root 打开 WAL/SHM。"""
    db_path = os.path.realpath(str(cfg["db_path"]))
    if db_path != "/opt/team13-board/board.db" or not os.path.isfile(db_path):
        return 2, "database path rejected"
    argv = ["sudo", "-u", str(cfg["service_user"]), "sqlite3",
            "file:%s?mode=ro" % db_path, sql]
    return run_command(argv, int(cfg["command_timeout_seconds"]))


def check_schema_contract(cfg):
    """检查版本化迁移、规范化唯一键和报销引用完整性。"""
    expected = int(cfg["expected_schema_version"])
    rc, has_table = sqlite_ro_query(cfg, "select count(*) from sqlite_master where type='table' and name='team13_schema_migrations';")
    if rc != 0:
        return item("bad", "Schema 与关键约束", "无法读取迁移表：%s" % has_table[:300])
    current = 0
    if has_table.strip() == "1":
        rc, value = sqlite_ro_query(cfg, "select coalesce(max(version),0) from team13_schema_migrations;")
        if rc != 0 or not re.match(r"^\d+$", value.strip()):
            return item("bad", "Schema 与关键约束", "迁移版本不可读：%s" % value[:300])
        current = int(value.strip())

    rc1, unique_count = sqlite_ro_query(cfg, """select count(*) from sqlite_master
        where type='index' and name='idx_v2_account_normalized_unique'
        and lower(coalesce(sql,'')) like 'create unique index%';""")
    rc2, index_info = sqlite_ro_query(cfg, "pragma index_info('idx_v2_account_normalized_unique');")
    rc3, duplicate_count = sqlite_ro_query(cfg, """select count(*) from (
        select account_key,platform_key from ecom_v2_accounts
        group by account_key,platform_key having count(*)>1);""")
    rc4, orphan_events = sqlite_ro_query(cfg, """select count(*) from ecom_v2_reimbursement_events e
        left join ecom_v2_purchases p on p.id=e.purchase_id
        left join ecom_v2_reports r on r.id=e.report_id
        where p.id is null or r.id is null or p.report_id<>e.report_id;""")
    rc5, orphan_purchases = sqlite_ro_query(cfg, """select count(*) from ecom_v2_purchases p
        left join ecom_v2_reports r on r.id=p.report_id where r.id is null;""")
    if any(x != 0 for x in (rc1, rc2, rc3, rc4, rc5)):
        return item("bad", "Schema 与关键约束", "关键约束查询失败")

    columns = []
    for line in index_info.splitlines():
        parts = line.split("|")
        if len(parts) >= 3:
            columns.append(parts[-1].strip())
    values = [unique_count, duplicate_count, orphan_events, orphan_purchases]
    if any(not re.match(r"^\d+$", x.strip()) for x in values):
        return item("bad", "Schema 与关键约束", "关键约束结果格式异常")
    unique_ok = int(unique_count.strip()) == 1 and columns == ["account_key", "platform_key"]
    duplicates = int(duplicate_count.strip())
    event_orphans = int(orphan_events.strip())
    purchase_orphans = int(orphan_purchases.strip())

    problems = []
    if current < expected:
        problems.append("schema=%d<%d" % (current, expected))
    if not unique_ok:
        problems.append("规范化唯一索引缺失或列不符")
    if duplicates:
        problems.append("规范化重复=%d" % duplicates)
    if event_orphans or purchase_orphans:
        problems.append("孤儿报销事件=%d，孤儿买号=%d" % (event_orphans, purchase_orphans))
    if problems:
        return item("bad", "Schema 与关键约束", "；".join(problems),
                    {"schema_version": current, "expected": expected,
                     "normalized_duplicates": duplicates,
                     "orphan_reimbursements": event_orphans,
                     "orphan_purchases": purchase_orphans})
    level = "warn" if current > expected else "ok"
    return item(level, "Schema 与关键约束",
                "schema=%d，规范化唯一索引=ok，孤儿报销=0" % current,
                {"schema_version": current, "expected": expected})


def newest_file(root, pattern):
    if not os.path.isdir(root):
        return None
    matches = [p for p in glob.glob(os.path.join(root, pattern)) if os.path.isfile(p)]
    return max(matches, key=os.path.getmtime) if matches else None


def file_age_hours(path, now=None):
    now = time.time() if now is None else now
    return max(0.0, (now - os.path.getmtime(path)) / 3600.0)


def check_db_backup(cfg, now=None):
    latest = newest_file(str(cfg["db_backup_root"]), str(cfg["db_backup_glob"]))
    if not latest:
        return item("bad", "数据库备份", "未找到 board.db.gz")
    age = file_age_hours(latest, now)
    rc, output = run_command(["gzip", "-t", latest], int(cfg["command_timeout_seconds"]))
    if rc != 0:
        return item("bad", "数据库备份", "最新备份 gzip 校验失败：%s" % output[:300])
    hash_ok = True
    checksum_path = latest + ".sha256"
    if as_bool(cfg.get("db_backup_require_sha256")):
        try:
            with open(checksum_path, "r") as checksum_fh:
                expected = checksum_fh.readline().split()[0].lower()
            digest = hashlib.sha256()
            with open(latest, "rb") as fh:
                while True:
                    chunk = fh.read(1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
            hash_ok = bool(re.match(r"^[0-9a-f]{64}$", expected)) and digest.hexdigest() == expected
        except (IOError, IndexError):
            hash_ok = False
        if not hash_ok:
            return item("bad", "数据库备份", "最新备份缺少或未通过 SHA256")
    max_hours = int(cfg["db_backup_max_hours"])
    level = "ok" if age <= max_hours else "bad"
    return item(level, "数据库备份", "最新=%s，%.1f 小时前，gzip/sha256=ok" %
                (os.path.basename(latest), age), {"age_hours": round(age, 2), "path": latest})


def check_uploads_backup(cfg, now=None):
    latest = newest_file(str(cfg["uploads_backup_root"]), str(cfg["uploads_backup_glob"]))
    if not latest:
        return item("bad", "上传凭证备份", "未找到 uploads_*.tar.gz")
    age = file_age_hours(latest, now)
    archive_sum = latest + ".sha256"
    files_sum = latest[:-7] + ".files.sha256" if latest.endswith(".tar.gz") else latest + ".files.sha256"
    missing = [p for p in (archive_sum, files_sum) if not os.path.isfile(p)]
    if missing:
        return item("bad", "上传凭证备份", "最新归档缺少校验清单：%s" %
                    ", ".join(os.path.basename(x) for x in missing))
    rc1, out1 = run_command(["gzip", "-t", latest], int(cfg["command_timeout_seconds"]))
    try:
        with open(archive_sum, "r") as checksum_fh:
            expected = checksum_fh.readline().split()[0].lower()
        digest = hashlib.sha256()
        with open(latest, "rb") as fh:
            while True:
                chunk = fh.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        hash_ok = bool(re.match(r"^[0-9a-f]{64}$", expected)) and digest.hexdigest() == expected
    except (IOError, IndexError):
        hash_ok = False
    if rc1 != 0 or not hash_ok:
        return item("bad", "上传凭证备份", "归档/哈希校验失败：gzip=%s，sha256=%s" %
                    (out1[:200], "ok" if hash_ok else "bad"))
    max_hours = int(cfg["uploads_backup_max_hours"])
    level = "ok" if age <= max_hours else "bad"
    return item(level, "上传凭证备份", "最新=%s，%.1f 小时前，gzip/sha256=ok" %
                (os.path.basename(latest), age), {"age_hours": round(age, 2), "path": latest})


def check_disk(cfg):
    path = str(cfg["disk_path"])
    try:
        usage = shutil.disk_usage(path)
    except OSError as exc:
        return item("bad", "磁盘", "读取失败：%s" % repr(exc))
    used_pct = int(round(100.0 * usage.used / usage.total)) if usage.total else 100
    free_gb = usage.free / float(1024 ** 3)
    if used_pct >= int(cfg["disk_bad_percent"]) or free_gb < int(cfg["disk_min_free_gb"]):
        level = "bad"
    elif used_pct >= int(cfg["disk_warn_percent"]):
        level = "warn"
    else:
        level = "ok"
    return item(level, "磁盘", "已用 %d%%，可用 %.1fGB" % (used_pct, free_gb),
                {"used_percent": used_pct, "free_gb": round(free_gb, 2)})


def check_certificate(cfg):
    path = str(cfg["cert_path"])
    if not os.path.isfile(path):
        return item("bad", "TLS 证书", "证书文件不存在")
    rc, output = run_command(["openssl", "x509", "-in", path, "-noout", "-enddate"],
                             int(cfg["command_timeout_seconds"]))
    if rc != 0 or "=" not in output:
        return item("bad", "TLS 证书", "无法读取到期时间：%s" % output[:300])
    raw = output.split("=", 1)[1].strip()
    try:
        expiry = datetime.datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z")
        days = int((expiry - datetime.datetime.utcnow()).total_seconds() // 86400)
    except ValueError:
        return item("bad", "TLS 证书", "无法解析到期时间：%s" % raw)
    if days < int(cfg["cert_bad_days"]):
        level = "bad"
    elif days < int(cfg["cert_warn_days"]):
        level = "warn"
    else:
        level = "ok"
    return item(level, "TLS 证书", "%s 到期，剩余 %d 天" % (expiry.date().isoformat(), days),
                {"days_remaining": days})


NGINX_TIME = re.compile(r"\[([^\]]+)\]")
NGINX_STATUS = re.compile(r'"\s+(5\d\d)\s+')


def count_nginx_5xx(path, scope_pattern, now=None):
    if not os.path.isfile(path):
        return None
    now = datetime.datetime.now(datetime.timezone.utc) if now is None else now
    cutoff = now - datetime.timedelta(hours=24)
    scope = re.compile(scope_pattern)
    count = 0
    with open(path, "r", errors="replace") as fh:
        for line in fh:
            if not scope.search(line):
                continue
            sm = NGINX_STATUS.search(line)
            tm = NGINX_TIME.search(line)
            if not sm or not tm:
                continue
            try:
                stamp = datetime.datetime.strptime(tm.group(1), "%d/%b/%Y:%H:%M:%S %z")
            except ValueError:
                continue
            if stamp >= cutoff:
                count += 1
    return count


def check_five_xx(cfg):
    access_count = count_nginx_5xx(str(cfg["nginx_access_log"]), str(cfg["site_match"]))
    rc, journal = run_command([
        "journalctl", "-u", str(cfg["service"]), "--since", "24 hours ago", "--no-pager"
    ], int(cfg["command_timeout_seconds"]))
    if rc == 0:
        journal_count = len(re.findall(r"Exception on |\bHTTP/[^ ]+\s+5\d\d\b", journal))
    else:
        journal_count = None
    if access_count is None and journal_count is None:
        return item("warn", "近 24 小时 5xx", "Nginx access log 与 journal 均不可读")
    # 同一次 500 通常同时出现在 Nginx access log 和应用 journal，取两者较大值避免重复计数。
    effective = max(access_count or 0, journal_count or 0)
    if effective >= int(cfg["five_xx_bad"]):
        level = "bad"
    elif effective >= int(cfg["five_xx_warn"]):
        level = "warn"
    else:
        level = "ok"
    detail = "Nginx=%s，应用异常=%s，去重评估值=%d" % (
        "不可读" if access_count is None else access_count,
        "不可读" if journal_count is None else journal_count,
        effective,
    )
    return item(level, "近 24 小时 5xx", detail,
                {"nginx": access_count, "journal": journal_count, "effective": effective})


def worst_level(items):
    score = max([LEVEL_SCORE.get(x.get("level"), 2) for x in items] or [0])
    return ("ok", "warn", "bad")[score]


def render_text(report):
    icons = {"ok": "OK", "warn": "WARN", "bad": "BAD"}
    lines = ["Team13 健康巡检 %s worst=%s" % (report["generated_at"], report["worst"])]
    for row in report["items"]:
        lines.append("[%s] %s：%s" % (icons.get(row["level"], "BAD"), row["title"], row["detail"]))
    return "\n".join(lines)


def post_form(url, values, timeout):
    data = urllib.parse.urlencode(values).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"User-Agent": "team13-health-v2/1.0"})
    resp = urllib.request.urlopen(req, timeout=timeout)
    return int(resp.getcode()), resp.read(4096).decode("utf-8", "replace")


def send_notification(cfg, report):
    body = render_text(report)
    webhook = str(cfg.get("notify_webhook") or "").strip()
    sendkey = str(cfg.get("serverchan_sendkey") or "").strip()
    try:
        if webhook:
            code, _ = post_form(webhook, {"title": "Team13 健康巡检 %s" % report["worst"], "text": body},
                                int(cfg["http_timeout_seconds"]))
        elif sendkey:
            url = "https://sctapi.ftqq.com/%s.send" % urllib.parse.quote(sendkey, safe="")
            code, _ = post_form(url, {"title": "Team13 健康巡检 %s" % report["worst"], "desp": body},
                                int(cfg["http_timeout_seconds"]))
        else:
            return False, "通知渠道未配置"
        if 200 <= code < 300:
            return True, "通知已提交，HTTP %d" % code
        return False, "通知失败，HTTP %d" % code
    except Exception as exc:
        return False, "通知失败：%s" % repr(exc)


def write_report(cfg, report):
    root = str(cfg["history_dir"])
    if not root.startswith("/opt/team13-board/"):
        raise ValueError("history_dir 必须位于 /opt/team13-board/ 下")
    if not os.path.isdir(root):
        os.makedirs(root, 0o750)
    stamp = datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")
    final = os.path.join(root, "%s.json" % stamp)
    temp = final + ".tmp.%d" % os.getpid()
    with open(temp, "w") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2, sort_keys=True)
        fh.write("\n")
    os.chmod(temp, 0o640)
    os.rename(temp, final)
    return final


def run_checks(cfg, now=None):
    rows = [
        check_health(cfg),
        check_service(cfg),
        check_database(cfg),
        check_schema_contract(cfg),
        check_db_backup(cfg, now),
        check_uploads_backup(cfg, now),
        check_disk(cfg),
        check_certificate(cfg),
        check_five_xx(cfg),
    ]
    if not (str(cfg.get("notify_webhook") or "").strip() or
            str(cfg.get("serverchan_sendkey") or "").strip()):
        rows.append(item("warn", "通知渠道", "未配置 notify_webhook 或 serverchan_sendkey，异常只能写日志"))
    else:
        rows.append(item("ok", "通知渠道", "已配置（敏感值不输出）"))
    return rows


def main(argv=None):
    parser = argparse.ArgumentParser(description="Team13 health check v2")
    parser.add_argument("--runtime", default=DEFAULT_RUNTIME)
    parser.add_argument("--config", default=DEFAULT_HEALTH_CONF)
    parser.add_argument("--no-write", action="store_true", help="只输出，不写 history 文件")
    parser.add_argument("--no-notify", action="store_true", help="演练模式：不发送外部通知")
    args = parser.parse_args(argv)
    try:
        cfg = load_config(args.runtime, args.config)
    except Exception as exc:
        print("配置读取失败：%s" % redact(repr(exc)))
        return 2

    rows = run_checks(cfg)
    report = {
        "schema": 2,
        "generated_at": datetime.datetime.now().isoformat(),
        "items": rows,
        "worst": worst_level(rows),
    }

    should_notify = report["worst"] != "ok" or as_bool(cfg.get("notify_on_ok"))
    if (not args.no_notify and should_notify and
            (cfg.get("notify_webhook") or cfg.get("serverchan_sendkey"))):
        sent, detail = send_notification(cfg, report)
        rows.append(item("ok" if sent else "bad", "通知发送", detail))
        report["worst"] = worst_level(rows)

    if not args.no_write:
        try:
            report["report_path"] = write_report(cfg, report)
        except Exception as exc:
            rows.append(item("bad", "巡检报告落盘", "写入失败：%s" % repr(exc)))
            report["worst"] = worst_level(rows)

    print(render_text(report))
    return LEVEL_SCORE.get(report["worst"], 2)


if __name__ == "__main__":
    sys.exit(main())
