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
docs/                 全新服务器快速部署说明
tests/                初始化与核心角色链路烟雾测试
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
/opt/your-app-dir/app.py
/opt/your-app-dir/board.db
/opt/your-app-dir/private/runtime.env
/www/wwwroot/default-site/YOUR_HIDDEN_PREFIX/
```

## 部署概要

全新服务器请按照 [`docs/QUICKSTART.md`](docs/QUICKSTART.md) 执行。关键原则：数据库只能用单进程初始化，常驻 Gunicorn 启动时 `TEAM13_ALLOW_SCHEMA_MIGRATION` 必须为 `0`。

详细迁移、备份和恢复步骤见 `ops/` 目录。

本地代码验证：

```bash
python -m unittest discover -s tests -v
python -m py_compile backend/app.py ops/daily_health_v2.py
```

## 安全说明

- 本仓库不含生产数据库、员工资料、付款凭证、管理员密码、Cookie 或服务器私钥。
- `runtime.env` 必须位于公网目录外并保持最小读取权限。
- 上传凭证仅允许 JPEG、PNG、GIF，并在服务端完成文件头和图片解码校验。
- 新部署必须更换全部密钥，不要复制其他团队或测试环境的登录配置。

## 验收状态

当前发布版本完成 10 个角色智能体的连续 7 天模拟，以及老板、组长、员工、财务、账号报销、异常、性能和桌面/390px 手机端验收。最终生产链路验收 74/74 通过；测试数据已清理。

建议正式使用前先选一个小组与原 Excel 并行运行 3–7 天，再决定是否全公司切换。

## 开源许可

本项目采用 [MIT License](LICENSE)。可以使用、修改和再发布，但必须保留原版权与许可声明。软件按现状提供，部署者需自行完成安全配置、备份和业务口径确认。
