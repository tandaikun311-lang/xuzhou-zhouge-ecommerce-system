# Team13 版本化迁移与单进程执行门禁

本流程解决“5 个 Gunicorn worker 同时执行建表/回填”的风险。业务进程只运行已经完成的 schema；写迁移由独立脚本执行，不能依赖应用导入时碰运气完成。

## 设计

1. 文件命名：`NNNN_description.sql`，版本号全局唯一，已执行文件禁止修改。
2. 记录表：`team13_schema_migrations(version,name,checksum,applied_at)`；同版本 checksum 变化立即失败。
3. 单进程：原子 `mkdir /run/lock/team13-board-migrate.lock`；锁存在时拒绝第二个执行者。异常退出由 trap 清理；kill -9 后只能在确认 owner PID 不存在、服务未运行后人工清锁。
4. 单迁移事务：每个 SQL 文件使用 `BEGIN IMMEDIATE`；失败回滚该版本，已经完成的旧版本保留，可修正新文件后继续。
5. 写门禁：必须验证最新小时备份 gzip/SHA256，必须确认 `team13-board.service` 非 active，迁移后必须 `quick_check=ok` 且版本等于目标。
6. SQL 禁止自己写 `BEGIN/COMMIT/ROLLBACK`，禁止 `VACUUM/ATTACH/DETACH/journal_mode/writable_schema`。

## 建议部署顺序

以下是操作手册，不代表已在生产执行：

```bash
# 1. 当前版本只读预检；有 pending 时返回 3
/opt/your-app-dir/ops/run_migration_v3.sh --check --target 3

# 2. 先生成小时备份并记录输出路径
/opt/your-app-dir/ops/hourly_backup_db.sh

# 3. 核对备份三件套和源库
gzip -t /opt/your-app-dir-hourly-backup/YYYY-MM-DD/board_*.db.gz
sha256sum -c /opt/your-app-dir-hourly-backup/YYYY-MM-DD/board_*.db.gz.sha256
sudo -u tanboard sqlite3 'file:/opt/your-app-dir/board.db?mode=ro' 'pragma quick_check;'

# 4. 冻结写入并停止服务；确认进程和 8312 已退出
systemctl stop team13-board.service
systemctl is-active team13-board.service
ss -lntp | grep ':8312' && exit 1 || true

# 5. 使用刚生成的备份凭证执行迁移
/opt/your-app-dir/ops/run_migration_v3.sh --apply --target 3 \
  --backup-sha /opt/your-app-dir-hourly-backup/YYYY-MM-DD/board_YYYYMMDD_HHMMSS.db.gz.sha256

# 6. 再做只读预检，必须 current=target、pending=none
/opt/your-app-dir/ops/run_migration_v3.sh --check --target 3

# 7. 启动后验证 health、登录和三岗位链路
systemctl start team13-board.service
systemctl is-active team13-board.service
curl -fsS http://127.0.0.1:8312/health
```

回滚原则：应用/页面故障优先回滚代码，不回滚数据库。只有迁移破坏 schema/数据且新代码无法兼容时，才在隔离实例验证备份后恢复数据库；禁止直接把 gzip 覆盖运行库。
