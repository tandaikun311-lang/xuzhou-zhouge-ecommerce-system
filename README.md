# 徐州舟格电商运营管理系统

徐州舟格电商运营团队的独立经营数据系统。员工每天填报基础数据，组长管理本组，老板查看全公司经营、账号、报销、核账、结算与员工绩效。

## 主要功能

- 每日填报：支付 GMV、退款、广告实际消耗、充值资金流、买号费用、出单账号和账号状态
- 三级看板：公司、小组、员工的当天、近 7 天和本月汇总
- 人员权限：老板/管理员、运营员工，以及运营员工上的组长附加权限
- 财务核账：待核账、退回重报、已核账、并发版本保护
- 账号资产：账号采购、状态变化、归属、凭证和历史记录
- 买号报销：付款凭证、状态流转、冲正与重复请求保护
- 期间结算：结算预检、漏报提示、结算快照、关闭与重新打开
- 绩效输出：员工贡献利润排名、分组投入产出比和 PNG 经营战报

## 财务口径

- 退款后净 GMV = 支付 GMV - 退款
- 阶段贡献利润 = 退款后净 GMV - 广告实际消耗 - 账号采购成本
- 充值金额属于资金流，不直接作为成本再次扣除

阶段贡献利润不含工资、提成、税费、平台扣点及其他经营费用，不等于公司最终净利润。

## 目录

```text
backend/              Flask + SQLite 后端
site/                 中文管理页面与移动端页面
config/               Nginx、systemd 和私有环境变量模板
ops/                  数据库迁移、备份、健康巡检与恢复手册
requirements.txt      Python 运行依赖
```

## 运行环境

- Linux 服务器
- Python 3.10+
- SQLite 3
- Nginx
- systemd

## 直接获取

```bash
git clone https://github.com/tandaikun311-lang/xuzhou-zhouge-ecommerce-system.git
cd xuzhou-zhouge-ecommerce-system
```

克隆后必须先按照 `config/runtime.env.example` 生成自己的独立密钥和管理员密码，不要使用任何演示或其他团队的生产配置。

生产约定路径：

```text
/opt/team13-board/app.py
/opt/team13-board/board.db
/opt/team13-board/private/runtime.env
/www/wwwroot/default-site/zb-t1365d2f4f3/
```

## 部署概要

1. 创建 Python 虚拟环境并安装 `requirements.txt`。
2. 将 `backend/app.py` 放到 `/opt/team13-board/app.py`。
3. 从 `config/runtime.env.example` 创建 `/opt/team13-board/private/runtime.env`，为每个密钥生成独立随机值。
4. 首次启动设置 `TEAM13_ALLOW_SCHEMA_MIGRATION=1`，初始化后通过 `/health` 确认 `schema_version=3`，再改回 `0`。
5. 将 `site/` 内容部署到 `/www/wwwroot/default-site/zb-t1365d2f4f3/`。
6. 安装 `config/team13-board.service`，并将 `config/nginx-team13.conf` 作为现有 HTTPS `server` 块内的配置片段。
7. 执行 Nginx 配置检查、服务健康检查和空库验收后再录入正式数据。

详细迁移、备份和恢复步骤见 `ops/` 目录。

## 安全说明

- 本仓库不含生产数据库、员工资料、付款凭证、管理员密码、Cookie 或服务器私钥。
- `runtime.env` 必须位于公网目录外并保持最小读取权限。
- 上传凭证仅允许 JPEG、PNG、GIF，并在服务端完成文件头和图片解码校验。
- 新部署必须更换全部密钥，不要复制其他团队或测试环境的登录配置。

## 验收状态

当前发布版本完成 10 个角色智能体的连续 7 天模拟，以及老板、组长、员工、财务、账号报销、异常、性能和桌面/390px 手机端验收。最终生产链路验收 74/74 通过；测试数据已清理。

建议正式使用前先选一个小组与原 Excel 并行运行 3–7 天，再决定是否全公司切换。
