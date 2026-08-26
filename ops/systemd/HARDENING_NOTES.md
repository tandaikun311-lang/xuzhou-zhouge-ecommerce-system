# Team13 systemd hardening 验收说明

此 drop-in 是候选配置，未部署。当前文件刻意只采用 CentOS 7 / systemd 219 可用的基础指令，没有使用较新版本才支持的 `ProtectKernelTunables`、`ProtectControlGroups`、`TasksMax`、`MemoryMax` 等。仍必须先用相同版本预发布验证，不能直接上生产。

## 为什么仍开放 `/opt/team13-board`

应用把 SQLite 固定在 `/opt/team13-board/board.db`。SQLite DELETE/WAL 模式都可能在同目录创建或删除 sidecar 文件，只把 `board.db` 标记为可写会造成运行时锁库失败。候选配置因此开放父目录，再把 `app.py`、`private`、`ops`、发布包等具体路径重新设为只读。

更彻底的长期方案是让应用支持 `TAN_BOARD_DB=/var/lib/team13-board/board.db`，把代码部署到 root 所有的只读版本目录，仅开放 `/var/lib/team13-board` 和 `_uploads`。这需要业务代码支持新 DB 路径，不在本轮 ops-only 修改范围内。

## 预发布门禁

```bash
systemd-analyze verify /etc/systemd/system/team13-board.service
systemctl daemon-reload
systemctl restart team13-board.service
systemctl show team13-board.service -p NoNewPrivileges -p PrivateTmp -p ProtectSystem -p ReadWritePaths -p ReadOnlyPaths -p MemoryLimit
```

随后必须验证：

1. `/health`、登录、日报保存、凭证上传、审核、报销、结算均成功。
2. SQLite 能创建/清理 journal/WAL/SHM，无 `readonly database` 或 `permission denied`。
3. 以 `tanboard` 身份不能改 `app.py`、`runtime.env`、ops 脚本和发布包。
4. 上传只能写 `_uploads`，不能写站点 HTML/theme。
5. 运行 30—60 分钟无 worker 重启、OOM、TasksMax 或 NOFILE 告警。
