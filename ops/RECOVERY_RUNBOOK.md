# 徐州舟格系统备份与恢复手册

默认实例：`team13-board.service`、`127.0.0.1:8312`、`/board13/api/`、`/zb-t1365d2f4f3/`。

复制成新实例时，必须同时更换服务名、端口、数据库路径、上传目录、API/静态路径、Cookie 隔离策略和全部密钥。

## 建议目标

- 数据库 RPO：不超过 1 小时。
- 付款凭证 RPO：不超过 24 小时；不能补传时缩短到 1 小时。
- 整体 RTO：不超过 2 小时。

正式启用前由业务负责人确认“最多能丢多少数据、最多能停多久”，再决定备份频率和异地存储成本。

## 文件职责

- `hourly_backup_db.sh`：SQLite 一致性备份、`quick_check`、gzip 和 SHA-256。
- `backup_uploads.sh`：付款凭证及缩略图归档、文件清单和 SHA-256。
- `daily_health_v2.py`：服务、数据库、备份、磁盘、TLS 与错误日志只读巡检。
- `health.conf.example`：巡检配置模板；真实通知密钥只能放在私有目录。
- `run_migration_v3.sh`：现有 v3 实例的版本化迁移门禁，不用于替代全新数据库的单进程初始化。
- `MIGRATION_RUNBOOK.md`：迁移顺序和回滚原则。

## 每次上线前

1. `PRAGMA quick_check` 和 `PRAGMA integrity_check` 均为 `ok`。
2. 生成并验证数据库备份、上传凭证备份和当前代码版本。
3. 保存当前 systemd unit 和 Nginx 本实例配置片段。
4. 确认发布内容不含 `runtime.env`、数据库、上传凭证、人员资料或登录信息。
5. 明确上线负责人、验证负责人和回滚负责人。

## 数据库备份

生产默认以 root 执行，脚本会切换到应用用户完成 SQLite `.backup`：

```bash
sudo /opt/team13-board/ops/hourly_backup_db.sh
```

验证最新归档：

```bash
gzip -t /opt/team13-board-hourly-backup/YYYY-MM-DD/board_*.db.gz
sha256sum -c /opt/team13-board-hourly-backup/YYYY-MM-DD/board_*.db.gz.sha256
```

备份完成后还应复制到不同服务器或对象存储。同一服务器、同一磁盘上的备份不能应对整机丢失。

## 上传凭证备份

```bash
sudo /opt/team13-board/ops/backup_uploads.sh
```

验证 tar.gz、归档 SHA-256 和逐文件 SHA-256。上传凭证包含付款信息，异地存储必须使用私有桶、最小权限和加密传输。

## 数据库隔离恢复

禁止直接覆盖运行中的 `board.db`。

1. 停止隔离测试实例，不停止生产实例。
2. 将选定的 `.db.gz` 解压到专用恢复目录。
3. 执行：

   ```bash
   sqlite3 'file:/隔离目录/board.db?mode=ro' \
     'PRAGMA quick_check; PRAGMA integrity_check;'
   ```

4. 核对人员、日报、充值、买号、账号、账号历史、报销、结算和审计记录数量。
5. 使用不同数据库路径、端口和 Cookie 名启动隔离实例，不注册生产公网路由。
6. 验证老板、组长、员工、核账、报销、结算、CSV 和凭证读取。
7. 记录恢复点、开始时间和可用时间，计算实际 RPO/RTO。

## 上传归档隔离恢复

不要直接解压覆盖生产 `_uploads`。先检查归档成员，拒绝绝对路径、`..`、符号链接和硬链接，再解压到隔离目录并核对逐文件 SHA-256。

恢复数据库中的凭证 URL 必须逐个对应到真实文件；数据库汇总正确但凭证缺失，仍判定恢复失败。

## 故障处理

### 代码或页面故障

数据库未损坏时只回滚代码和静态文件，不回滚数据库。切换后检查健康接口、三个角色、Nginx/journal 新错误和凭证读取。

### 数据库损坏

冻结写入并保存故障库及 WAL/SHM；在隔离实例恢复最新一致性备份。确认数据行数、审计链和 RPO 可接受后才切换生产。

### 付款凭证误删

冻结上传目录，恢复到隔离目录，与数据库凭证 URL 生成差异清单，只回补缺失文件，并保留恢复来源和操作记录。

### 整机丢失

使用异地数据库备份、异地上传备份和 GitHub 发布版本重建。三类资产都只在原机时，不能宣称具备整机灾备。

## 上线后

- 服务为 active，8312 只监听本机，`/health` 返回 `schema_version=3`。
- 管理员、组长、员工最小链路通过。
- 数据库与上传备份立即生成并同步异地。
- 告警渠道收到一次真实测试消息。
- 观察 30—60 分钟，确认没有新增 500、Traceback 或锁库错误。
