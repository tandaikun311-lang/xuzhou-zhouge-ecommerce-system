# Team13 徐州舟格｜部署、备份与故障恢复手册

适用实例：`team13-board.service`、`127.0.0.1:8312`、`/board13/api/`、`zb-t1365d2f4f3`。

本目录是可部署源文件，不代表已上线。任何生产安装、cron 替换、服务 reload/restart 或恢复切换都必须单独审批，并先生成当前版本回滚包。

## 1. 文件职责

- `daily_health_v2.py`：Team13 专用只读巡检；只检查当前电商运营系统的服务、数据库、备份与资源状态。
- `backup_uploads.sh`：备份 `_uploads` 中的付款凭证、原图和缩略图；输出 tar.gz、归档 SHA256 和逐文件 SHA256。
- `hourly_backup_db.sh`：小时级 SQLite `.backup`，输出时间戳 gzip、SHA256、meta，并在发布前做 `quick_check`。
- `run_migration_v3.sh`：服务停机、备份校验和独占锁保护下的版本化迁移门禁。
- `MIGRATION_RUNBOOK.md`：迁移部署和回滚步骤。
- `systemd/team13-board-hardening.conf`：候选 hardening drop-in，仅限预发布验证后安装。
- `build_release_bundle.sh`：把 implementation 和只读导出的 Nginx/systemd 模板封装为不含数据/密钥的版本包。
- `health.conf.example`：巡检配置样例。
- `logrotate/team13-board`：四个 Team13 cron 日志的轮转样例。

## 2. 建议 RPO/RTO

试运行阶段建议：

- 数据库 RPO：不超过 1 小时。
- 上传付款凭证 RPO：不超过 24 小时；若当天付款凭证不可重传，则也应缩短到 1 小时。
- 整体 RTO：不超过 2 小时。

以上只是建议值。正式启用前由老板确认“最多能丢多少数据、最多能停多久”，再确定备份频率和异地存储成本。

## 3. 上线前只读导出配置模板

在本机建立专用导出目录，不把输出放进 implementation：

```bash
EXPORT_DIR="/Users/apple/Downloads/codex/任务输出/徐州舟格第二轮10智能体复盘_20260823/ops_exports"
mkdir -p "$EXPORT_DIR"

ssh root@tandaikun.com 'systemctl cat team13-board.service --no-pager' \
  > "$EXPORT_DIR/team13-board.service"

ssh root@tandaikun.com \
  "sed -n '/# ==== 十三团作战包/,/# ---- 作战包分享缩略图/p' /etc/nginx/conf.d/openclaw.conf" \
  > "$EXPORT_DIR/nginx-team13.conf"
```

人工检查导出文件：

1. systemd 指向 `/opt/team13-board`、8312、`team13-board`，只引用 `EnvironmentFile`，不出现任何密钥值。
2. Nginx 只包含 Team13 的 `board13`、`zb-t1365d2f4f3`、8312 规则，不夹带相邻团队规则。
3. 导出操作是只读的，不需要 reload/restart。

## 4. 构建不可变发布包

```bash
OPS="/Users/apple/Downloads/codex/任务输出/徐州舟格运营数据系统_20260822/implementation/ops"
EXPORT_DIR="/Users/apple/Downloads/codex/任务输出/徐州舟格第二轮10智能体复盘_20260823/ops_exports"
RELEASE_DIR="/Users/apple/Downloads/codex/交付物/徐州舟格电商运营管理系统/发布包"
mkdir -p "$RELEASE_DIR"

"$OPS/build_release_bundle.sh" \
  --nginx "$EXPORT_DIR/nginx-team13.conf" \
  --systemd "$EXPORT_DIR/team13-board.service" \
  --output "$RELEASE_DIR" \
  --note "第二轮10智能体优化"
```

验证发布包：

```bash
cd "$RELEASE_DIR"
sha256sum -c team13_release_YYYYMMDD_HHMMSS.tar.gz.sha256
tar -tzf team13_release_YYYYMMDD_HHMMSS.tar.gz | sed -n '1,120p'
```

发布包必须不含：`runtime.env`、`health.conf` 实际通知密钥、`board.db`、`private/`、`_uploads/`、登录信息或人员数据。

## 5. 安装运维文件的建议步骤（需另行授权）

以下是部署步骤，不在本次本地实施中执行：

1. 先运行现有数据库一致性备份，并把当前后端、静态站点、systemd unit、Nginx Team13 片段做成上线前回滚包。
2. 将 `daily_health_v2.py` 和 `backup_uploads.sh` staging 到服务器临时路径，核对 SHA256 后再安装到 `/opt/team13-board/`。
3. `daily_health_v2.py`、`backup_uploads.sh` 设为 root 所有、755；巡检配置放在 private 目录并设为 600。
4. 新建 `/opt/team13-uploads-backup`，设为 `700 root:root`。
5. 根据服务器真实 access log 路径修改 `nginx_access_log`；配置通知渠道，但不要把 sendkey 写入普通日志、Git 或发布包。
6. 先运行巡检演练：

   ```bash
   python3 /opt/team13-board/daily_health_v2.py --no-write --no-notify
   ```

7. 首次手工运行上传备份，验证 tar、归档 SHA256、逐文件清单，再增加 cron。
8. 安装 logrotate 样例前先运行 `logrotate -d`，确认只匹配 Team13 四个日志。
9. 新巡检连续通过并收到一次测试告警后，才移除旧 `daily_health.py` 的 cron；旧脚本文件先保留在非执行状态作为审计证据。

建议调度，避开现有数据库备份和站点快照：

```cron
43 3 * * * /opt/team13-board/backup_db.sh >> /var/log/team13-board-backup.log 2>&1
17 * * * * /opt/team13-board/ops/hourly_backup_db.sh >> /var/log/team13-board-hourly-backup.log 2>&1
48 3 * * * /opt/team13-board/backup_uploads.sh >> /var/log/team13-board-uploads-backup.log 2>&1
53 3 * * * /opt/team13-board/snapshot_site.sh >> /var/log/team13-board-snapshot.log 2>&1
13 9 * * * /usr/bin/python3 /opt/team13-board/daily_health_v2.py >> /var/log/team13-board-health-v2.log 2>&1
```

数据库 RPO 若确定为 1 小时，需要把数据库备份改为小时级并使用“时间戳文件名/目录”，不能沿用同一天只保留一个文件的现有策略。

## 6. health.conf 配置规则

复制 `health.conf.example` 到 private 目录后按生产事实修改。脚本只读取白名单键；旧 `admin_pw`、`emp_pw` 即使仍存在也不会使用或输出。

通知二选一：

- `notify_webhook`：接受表单字段 `title`、`text` 的 HTTPS webhook。
- `serverchan_sendkey`：Server 酱 SendKey。

没有配置通知时，巡检会明确返回 WARN，而不是假装全部正常。

`site_match` 用于过滤 Nginx access log，只统计 Team13 路径。建议值：`board13/api|zb-t1365d2f4f3`。

## 7. 上传备份验证与恢复

### 7.1 验证归档

```bash
BACKUP_DIR=/opt/team13-uploads-backup
cd "$BACKUP_DIR"
sha256sum -c uploads_YYYYMMDD_HHMMSS.tar.gz.sha256
gzip -t uploads_YYYYMMDD_HHMMSS.tar.gz
tar -tzf uploads_YYYYMMDD_HHMMSS.tar.gz | sed -n '1,120p'
```

### 7.2 安全恢复到隔离目录

不要直接解压覆盖生产 `_uploads`。先在隔离主机或隔离目录验证成员路径和哈希：

```bash
RESTORE_ROOT=/opt/team13-restore-drill/uploads
install -d -m 700 "$RESTORE_ROOT"

python3 - /opt/team13-uploads-backup/uploads_YYYYMMDD_HHMMSS.tar.gz <<'PY'
from __future__ import print_function
import posixpath, sys, tarfile
p = sys.argv[1]
with tarfile.open(p, "r:gz") as tf:
    for m in tf.getmembers():
        n = posixpath.normpath(m.name)
        if n.startswith("../") or n.startswith("/") or n == ".." or m.issym() or m.islnk():
            raise SystemExit("unsafe member: %s" % m.name)
print("archive member paths safe")
PY

tar -C "$RESTORE_ROOT" -xzf /opt/team13-uploads-backup/uploads_YYYYMMDD_HHMMSS.tar.gz
cd "$RESTORE_ROOT"
sha256sum -c /opt/team13-uploads-backup/uploads_YYYYMMDD_HHMMSS.files.sha256
```

之后从恢复数据库提取凭证 URL，逐个核对 `_uploads` 文件存在。数据库汇总正确但凭证缺失，仍应判定恢复失败。

## 8. 数据库恢复演练

1. 在隔离目录解压指定 `board.db.gz`，不得覆盖生产库。
2. 以应用用户、只读 URI 执行：

   ```bash
   sudo -u tanboard sqlite3 'file:/隔离目录/board.db?mode=ro' \
     'PRAGMA quick_check; PRAGMA integrity_check;'
   ```

3. 核对成员、日报、充值、买号、账号、账号历史、审核和审计记录数量。
4. 用恢复发布包启动独立端口（建议 18312），Cookie 名和数据库路径必须与生产隔离，不注册公网路由。
5. 验证 health、登录、老板后台、主管本组、员工本人、核账、账号台账、CSV 和凭证读取。
6. 记录恢复开始时间、可用时间、恢复点时间，计算真实 RTO/RPO。

## 9. 故障恢复决策

### 代码/页面故障，数据库未损坏

优先回滚代码和静态文件，绝不顺手回滚数据库。使用上线前发布包核对 manifest 后原子切换，再做三个角色 smoke test。

### 数据库损坏

1. 冻结写入，保留故障现场库和 WAL/SHM（若存在）。
2. 在隔离实例恢复最新一致性备份并核对关键行数、汇总和审计链。
3. 确认 RPO 可接受后才切换生产。
4. 不直接把 gzip 文件覆盖为运行库，不在服务运行时替换 `board.db`。

### 上传凭证误删

1. 冻结上传目录写入。
2. 从最近上传归档恢复到隔离目录，通过 archive/file 两层 SHA256。
3. 与数据库凭证 URL 做差异清单，只回补缺失文件。
4. 保留误删现场、恢复来源和操作审计。

### 整机丢失

必须使用异地的数据库、上传备份和发布包。若三者都只在原机同一磁盘，则不能宣称具备整机灾备。

## 10. 每次上线检查表

### 上线前

- [ ] 数据库 quick/integrity 均为 ok。
- [ ] 数据库备份和上传备份已生成并验证。
- [ ] 当前版本回滚包、Nginx 片段、systemd unit 已保存。
- [ ] 新发布包 archive SHA 和 MANIFEST 全部通过。
- [ ] 生产 Python 3.6 AST/导入/API 回归通过；完成平台迁移前不得跳过。
- [ ] 明确 RPO、RTO、上线负责人、回滚负责人。

### 切换时

- [ ] staging 后核对哈希，再原子切换。
- [ ] `nginx -t` 成功才允许 reload。
- [ ] service active、8312 仅监听本机、health 200。
- [ ] 老板、主管、员工、财务和凭证读取 smoke test 通过。
- [ ] journal/Nginx 无新增 500、Traceback、锁库错误。

### 上线后

- [ ] 立即生成当前版本发布包和站点快照，不等夜间 cron。
- [ ] 立即生成数据库/上传备份并同步异地。
- [ ] 巡检报告为 ok，通知渠道实际收到测试消息。
- [ ] 观察 30—60 分钟并记录结果。

## 11. 当前平台迁移提醒

生产仍是 CentOS 7、Python 3.6、SQLite 3.7.17 等旧运行时。运维脚本保持 Python 3.6 兼容只是短期止血，不代表建议长期保留。应在新受支持系统上平行恢复真实发布包、数据库和上传备份，完成全角色回归后再切流；不要在当前在线主机原地做大版本升级。
