# 全新 Linux 服务器快速部署

本说明按仓库默认路径部署“徐州舟格电商运营管理系统”。执行者需要具备 Linux、Nginx、HTTPS 和 systemd 的基础运维能力。生产数据上线前请先在测试服务器演练。

## 1. 准备依赖

需要：Git、Python 3.10+、Python venv、SQLite 3、Nginx、systemd，以及一个已经配置 HTTPS 的域名。

Ubuntu/Debian 示例：

```bash
sudo apt-get update
sudo apt-get install -y git python3 python3-venv python3-pip sqlite3 nginx openssl
```

Rocky/AlmaLinux 示例：

```bash
sudo dnf install -y git python3 python3-pip sqlite nginx openssl
```

安装后先确认 `python3 --version` 不低于 3.10。

## 2. 获取代码并创建独立用户

```bash
git clone https://github.com/tandaikun311-lang/xuzhou-zhouge-ecommerce-system.git
cd xuzhou-zhouge-ecommerce-system

if ! getent passwd tanboard >/dev/null; then
  sudo useradd --system --home /opt/your-app-dir --shell /usr/sbin/nologin tanboard
fi
id tanboard
sudo install -d -o tanboard -g tanboard -m 750 /opt/your-app-dir
sudo install -d -o tanboard -g tanboard -m 700 /opt/your-app-dir/private
sudo install -d -o tanboard -g tanboard -m 2750 /www/wwwroot/default-site/YOUR_HIDDEN_PREFIX/_uploads
```

如果系统的 `nologin` 路径不同，请使用本机实际路径；不要重复创建已经存在的业务用户。

确认 Nginx worker 的运行用户（常见为 `www-data` 或 `nginx`），将它加入只读共享组：

```bash
grep -E '^user ' /etc/nginx/nginx.conf
sudo usermod -aG tanboard www-data
```

如果第一条命令显示的是 `nginx`，则把第二条命令的 `www-data` 改为 `nginx`。加入组后需要重启 Nginx worker 才能取得新组权限。

## 3. 安装代码和 Python 环境

```bash
sudo install -o root -g tanboard -m 640 backend/app.py /opt/your-app-dir/app.py
sudo install -o root -g tanboard -m 640 requirements.txt /opt/your-app-dir/requirements.txt
sudo cp -a ops /opt/your-app-dir/ops
sudo chown -R root:tanboard /opt/your-app-dir/ops
sudo find /opt/your-app-dir/ops -type f -name '*.sh' -exec chmod 750 {} \;

sudo -u tanboard python3 -m venv /opt/your-app-dir/.venv
sudo -u tanboard /opt/your-app-dir/.venv/bin/pip install --upgrade pip
sudo -u tanboard /opt/your-app-dir/.venv/bin/pip install -r /opt/your-app-dir/requirements.txt

sudo cp -a site/. /www/wwwroot/default-site/YOUR_HIDDEN_PREFIX/
sudo chown -R root:tanboard /www/wwwroot/default-site/YOUR_HIDDEN_PREFIX
sudo chown -R tanboard:tanboard /www/wwwroot/default-site/YOUR_HIDDEN_PREFIX/_uploads
sudo find /www/wwwroot/default-site/YOUR_HIDDEN_PREFIX/_uploads -type d -exec chmod 2750 {} \;
sudo find /www/wwwroot/default-site/YOUR_HIDDEN_PREFIX/_uploads -type f -exec chmod 640 {} \;
```

## 4. 生成私有配置

```bash
sudo install -o root -g tanboard -m 640 config/runtime.env.example \
  /opt/your-app-dir/private/runtime.env
sudoedit /opt/your-app-dir/private/runtime.env
```

必须修改：

- `TAN_ADMIN_KEY`：老板/管理员登录密码；
- `TAN_EMP_KEY`、`TAN_VISITOR_KEY`、`TAN_PII_KEY`：分别生成不同的随机值；
- `TAN_SESSION_SECRET`：至少 32 字节随机值；
- `TEAM13_ALLOWED_ORIGINS`：改成实际 HTTPS 域名；
- 如果复制成新的独立实例，同时修改数据库路径、上传目录、URL 前缀、Nginx 路径、API 路径、端口和 Cookie 隔离策略。

生成随机值可以使用：

```bash
openssl rand -hex 32
```

不要把修改后的 `runtime.env` 放回 Git 仓库。

## 5. 单进程初始化数据库

不要直接用多 worker Gunicorn 执行建表。先运行一次单进程初始化：

```bash
cd /opt/your-app-dir
sudo -u tanboard env \
  TAN_BOARD_ENV_FILE=/opt/your-app-dir/private/runtime.env \
  TEAM13_ALLOW_SCHEMA_MIGRATION=1 \
  /opt/your-app-dir/.venv/bin/python -c 'import app'
```

确认数据库权限和结构：

```bash
sudo -u tanboard sqlite3 /opt/your-app-dir/board.db 'PRAGMA quick_check;'
sudo -u tanboard sqlite3 /opt/your-app-dir/board.db \
  'SELECT MAX(version) FROM ecom_v2_schema_version;'
```

预期分别返回 `ok` 和 `3`。`runtime.env` 中的 `TEAM13_ALLOW_SCHEMA_MIGRATION` 必须继续保持 `0`。

## 6. 安装 systemd 与 Nginx

```bash
sudo install -o root -g root -m 644 config/team13-board.service \
  /etc/systemd/system/team13-board.service
sudo systemctl daemon-reload
sudo systemctl enable --now team13-board.service
sudo systemctl is-active team13-board.service
curl -fsS http://127.0.0.1:8312/health
```

`config/nginx-team13.conf` 是 HTTPS `server` 块内部的配置片段，不是完整的 Nginx 配置文件。将它放入实际站点配置的 `server { ... }` 内，并确保该 `server` 的静态根目录是 `/www/wwwroot/default-site`。然后执行：

```bash
sudo nginx -t
sudo systemctl restart nginx
```

这里使用 `restart` 是为了让 Nginx worker 取得新加入的 `tanboard` 组权限。后续普通配置变更仍优先使用 `reload`。

公开健康检查和登录页：

```bash
curl -fsS https://你的域名/board/api/health
curl -I https://你的域名/YOUR_HIDDEN_PREFIX/login.html
```

## 7. 上线前验收

1. 管理员登录并创建一个测试员工和组长；
2. 员工提交一份日报；
3. 组长只能查看和核账本组普通员工；
4. 老板完成退回、重报、核账、报销和结算预检；
5. 桌面端和 390px 手机端检查无横向溢出；
6. 清理测试数据后，再开始录入正式数据；
7. 配置数据库、上传凭证异地备份和异常告警。

正式切换前建议选一个小组与原 Excel 并行运行 3–7 天。
