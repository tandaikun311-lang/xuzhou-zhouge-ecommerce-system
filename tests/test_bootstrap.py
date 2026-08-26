import datetime
import importlib.util
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class BootstrapFlowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="zhouge-test-")
        base = pathlib.Path(cls.tmp.name)
        cls.env_before = dict(os.environ)
        os.environ.update({
            "TAN_BOARD_ENV_FILE": str(base / "missing-runtime.env"),
            "TAN_ADMIN_KEY": "test-admin-password",
            "TAN_EMP_KEY": "test-internal-employee-key",
            "TAN_VISITOR_KEY": "test-disabled-visitor-key",
            "TAN_PII_KEY": "test-separate-pii-key",
            "TAN_SESSION_SECRET": "test-session-secret-at-least-32-bytes",
            "TEAM13_ALLOWED_ORIGINS": "https://example.test",
            "TEAM13_DB_PATH": str(base / "board.db"),
            "TEAM13_UPLOAD_DIR": str(base / "uploads"),
            "TEAM13_UPLOAD_URL_PREFIX": "/zhouge/_uploads",
            "TEAM13_ALLOW_SCHEMA_MIGRATION": "1",
        })
        spec = importlib.util.spec_from_file_location("zhouge_test_app", ROOT / "backend" / "app.py")
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    @classmethod
    def tearDownClass(cls):
        os.environ.clear()
        os.environ.update(cls.env_before)
        cls.tmp.cleanup()

    def test_bootstrap_role_report_reconcile_dashboard(self):
        health = self.module.app.test_client().get("/health")
        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.get_json()["schema_version"], 3)
        conn = self.module.db()
        self.assertEqual(conn.execute("select max(version) from team13_schema_migrations").fetchone()[0], 3)
        conn.close()

        admin = self.module.app.test_client()
        login = admin.post("/login", json={"password": "test-admin-password"})
        self.assertEqual(login.status_code, 200)
        self.assertEqual(login.get_json()["role"], "admin")

        member = admin.post("/ecom/v2/member/save", json={
            "name": "测试员工",
            "phone": "13800000000",
            "group_no": 1,
            "is_leader": False,
            "active": True,
            "login_password": "employee-pass",
        })
        self.assertEqual(member.status_code, 200, member.get_json())

        employee = self.module.app.test_client()
        emp_login = employee.post("/login", json={
            "name": "测试员工", "phone": "13800000000", "password": "employee-pass"
        })
        self.assertEqual(emp_login.status_code, 200, emp_login.get_json())

        day = datetime.date.today().isoformat()
        saved = employee.post("/ecom/v2/report/save", json={
            "biz_date": day,
            "gmv": "1000.00",
            "refund": "10.00",
            "ad_spend": "100.00",
            "recharges": [{"type": "广告充值", "amount": "120.00", "note": "测试"}],
            "purchases": [],
            "account_updates": [],
            "expected_revision": 0,
            "note": "公开仓库自动化烟雾测试",
        })
        self.assertEqual(saved.status_code, 200, saved.get_json())
        report = saved.get_json()["report"]

        reconciled = admin.post("/ecom/v2/reconcile", json={
            "id": report["id"],
            "expected_revision": report["revision"],
            "status": "confirmed",
            "note": "自动化核账通过",
        })
        self.assertEqual(reconciled.status_code, 200, reconciled.get_json())

        dashboard = admin.get("/ecom/v2/dashboard", query_string={
            "start": day, "end": day, "group": 0
        })
        self.assertEqual(dashboard.status_code, 200, dashboard.get_json())
        company = dashboard.get_json()["company"]
        self.assertEqual(company["gross_gmv"], 1000.0)
        self.assertEqual(company["gmv"], 990.0)
        self.assertEqual(company["ad_spend"], 100.0)
        self.assertEqual(company["profit"], 890.0)

    def test_unlisted_origin_is_rejected(self):
        client = self.module.app.test_client()
        blocked = client.post("/login", json={"password": "wrong"}, headers={
            "Origin": "https://evil.example"
        })
        self.assertEqual(blocked.status_code, 403)
        self.assertIn("已配置", blocked.get_json()["err"])

    def test_report_status_is_filtered_before_pagination(self):
        today = datetime.date.today()
        yesterday = today - datetime.timedelta(days=1)
        now = int(datetime.datetime.now().timestamp())
        conn = self.module.db()
        for i in range(100):
            conn.execute("""insert into ecom_v2_reports(
                biz_date,group_no,employee_name,gmv_cents,refund_cents,ad_spend_cents,
                note,reconcile_status,ip,created,updated)
                values(?,?,?,?,?,?,?,'confirmed','test',?,?)""",
                (today.isoformat(), 1, "分页已核账%03d" % i, 10000, 0, 1000, "", now, now))
        conn.execute("""insert into ecom_v2_reports(
            biz_date,group_no,employee_name,gmv_cents,refund_cents,ad_spend_cents,
            note,reconcile_status,ip,created,updated)
            values(?,?,?,?,?,?,?,'pending','test',?,?)""",
            (yesterday.isoformat(), 1, "最老待核账", 10000, 0, 1000, "", now, now))
        conn.commit()
        conn.close()

        admin = self.module.app.test_client()
        self.assertEqual(admin.post("/login", json={"password": "test-admin-password"}).status_code, 200)
        response = admin.get("/ecom/v2/dashboard", query_string={
            "start": yesterday.isoformat(),
            "end": today.isoformat(),
            "group": 0,
            "include": "reports",
            "report_status": "pending",
            "report_limit": 100,
            "report_offset": 0,
        })
        self.assertEqual(response.status_code, 200, response.get_json())
        payload = response.get_json()
        self.assertEqual(payload["reports_meta"]["total"], 1)
        self.assertEqual(len(payload["reports"]), 1)
        self.assertEqual(payload["reports"][0]["employee_name"], "最老待核账")
        self.assertEqual(payload["reports"][0]["status"], "pending")

    def test_group_leader_is_forced_to_own_group(self):
        admin = self.module.app.test_client()
        self.assertEqual(admin.post("/login", json={"password": "test-admin-password"}).status_code, 200)
        for member in (
            {"name": "一组组长", "phone": "13800000001", "group_no": 1, "is_leader": True},
            {"name": "二组员工", "phone": "13800000002", "group_no": 2, "is_leader": False},
        ):
            payload = dict(member, active=True, login_password="employee-pass")
            response = admin.post("/ecom/v2/member/save", json=payload)
            self.assertEqual(response.status_code, 200, response.get_json())

        leader = self.module.app.test_client()
        login = leader.post("/login", json={
            "name": "一组组长", "phone": "13800000001", "password": "employee-pass"
        })
        self.assertEqual(login.status_code, 200, login.get_json())
        day = datetime.date.today().isoformat()
        dashboard = leader.get("/ecom/v2/dashboard", query_string={
            "start": day, "end": day, "group": 2
        })
        self.assertEqual(dashboard.status_code, 200, dashboard.get_json())
        self.assertEqual(dashboard.get_json()["scope_group"], 1)
        self.assertEqual(leader.get("/ecom/v2/members").status_code, 403)

    def test_migration_ledger_matches_schema_version(self):
        base = pathlib.Path(self.tmp.name)
        migrations = base / "migrations"
        if migrations.exists():
            shutil.rmtree(migrations)
        shutil.copytree(ROOT / "ops" / "migrations", migrations)
        env = dict(os.environ)
        env.update({
            "TEAM13_TEST_MODE": "1",
            "TEAM13_TEST_BASE": str(base),
            "TEAM13_DB_PATH": str(base / "board.db"),
            "TEAM13_MIGRATIONS_DIR": str(migrations),
            "TEAM13_MIGRATION_LOCK_DIR": str(base / "migration.lock"),
            "TEAM13_SERVICE": "none",
            "TEAM13_MIGRATION_RUN_AS": "",
        })
        completed = subprocess.run(
            [str(ROOT / "ops" / "run_migration_v3.sh"), "--check", "--target", "3"],
            env=env, text=True, capture_output=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("current=3", completed.stdout)
        self.assertIn("pending=none", completed.stdout)


if __name__ == "__main__":
    unittest.main()
