# -*- coding: utf-8 -*-
# 徐州舟格电商运营管理系统后端（Flask + SQLite，独立服务端口 8312）
# 生产业务入口统一使用 /ecom/v2/*；迁移前旧接口由请求守卫返回 404。
import sqlite3, os, time, json, secrets, re, hmac, hashlib, datetime, urllib.parse, unicodedata
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from flask import Flask, request, jsonify, Response

ENV_FILE = os.environ.get("TAN_BOARD_ENV_FILE", "/opt/team13-board/private/runtime.env")

def _load_private_env(path):
    """读取公网目录外的私有配置。systemd 和定时巡检都可使用同一份,密钥不再写进代码。"""
    try:
        with open(path, "r") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip(); value = value.strip()
                if key and key not in os.environ:
                    os.environ[key] = value
    except IOError:
        pass

def _required_env(name):
    value = (os.environ.get(name) or "").strip()
    if not value:
        raise RuntimeError("缺少服务器私有配置: %s" % name)
    return value

_load_private_env(ENV_FILE)
DB = (os.environ.get("TEAM13_DB_PATH") or "/opt/team13-board/board.db").strip()
SCHEMA_MIGRATION_MODE = (os.environ.get("TEAM13_ALLOW_SCHEMA_MIGRATION") or "").strip() == "1"
ADMIN_KEY = _required_env("TAN_ADMIN_KEY")
EMP_KEY = _required_env("TAN_EMP_KEY")
VISITOR_KEY = _required_env("TAN_VISITOR_KEY")
# 名单/发薪等含银行卡、身份证、薪资的敏感接口专用密钥。
PII_KEY = _required_env("TAN_PII_KEY")

# 登录会话签名密钥只存私有配置;更换后所有人需重新登录。
SESSION_SECRET = _required_env("TAN_SESSION_SECRET")
SESSION_TTL = 30 * 86400
# 三档密码(从前端源码搬到服务器:现在只有服务器认识密码,网页里不再出现)
LOGIN_PW = {VISITOR_KEY: "visitor", EMP_KEY: "employee", ADMIN_KEY: "admin"}
ALLOWED_ORIGINS = tuple(x.strip().rstrip("/") for x in
    (os.environ.get("TEAM13_ALLOWED_ORIGINS") or
     "https://tandaikun.com,https://www.tandaikun.com").split(",") if x.strip())

def _sess_sign(role, exp, name="", auth_version=0):
    # 实名登录(2026-07-27):员工token带姓名。姓名里不会有|,防注入先去掉。
    name = (name or "").replace("|", "")
    msg = "%s|%d|%s|%d" % (role, exp, name, int(auth_version or 0))
    sig = hmac.new(SESSION_SECRET.encode(), msg.encode(), hashlib.sha256).hexdigest()
    return "%s|%s" % (msg, sig)

def _sess_parse(tok):
    # 新token role|exp|name|sig;旧token role|exp|sig 改版前发的仍认(无姓名,我的页会要求重登)
    try:
        parts = (tok or "").split("|")
        auth_version = None
        if len(parts) == 5:
            role, exp, name, auth_version, sig = parts
            auth_version = int(auth_version)
        elif len(parts) == 4:
            role, exp, name, sig = parts
        elif len(parts) == 3:
            role, exp, sig = parts; name = ""
        else:
            return None, ""
        expi = int(exp)
    except Exception:
        return None, ""
    msg = "|".join(parts[:-1])
    good = hmac.new(SESSION_SECRET.encode(), msg.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(good, sig):
        return None, ""
    if expi < int(time.time()):
        return None, ""
    # 退出后撤销当前服务端会话；员工改密码后 auth_version 变化，旧 Cookie 自动失效。
    try:
        token_hash = hashlib.sha256((tok or "").encode("utf-8")).hexdigest()
        c = db()
        revoked = c.execute("select 1 from ecom_v2_revoked_sessions where token_hash=? and expires>?",
                            (token_hash, int(time.time()))).fetchone()
        if revoked:
            c.close(); return None, ""
        if role == "employee" and name:
            if auth_version is None:
                c.close(); return None, ""
            member = c.execute("select auth_version,active from ecom_v2_members where name=?", (name,)).fetchone()
            if not member or not member["active"] or int(member["auth_version"] or 1) != int(auth_version):
                c.close(); return None, ""
        c.close()
    except sqlite3.OperationalError as exc:
        # 只在应用首次迁移、表尚未创建时兼容；其他数据库异常按会话无效处理。
        if "no such table" not in str(exc).lower():
            return None, ""
    except Exception:
        return None, ""
    return role, name

def _sess_verify(tok):
    return _sess_parse(tok)[0]

def emp_ok(d):
    # 浏览器只认服务端签名会话,不再接受 localStorage 里的明文密码。
    if _sess_verify(request.cookies.get("zb13sess", "")) in ("employee", "admin"):
        return True
    # 无代理头的本机巡检仍允许用内部密钥,不影响定时任务。
    return _internal_key_ok(d, (EMP_KEY, ADMIN_KEY))
CATS = ["经验交流", "提问求助", "资源分享", "公告通知"]
UPLOAD_DIR = (os.environ.get("TEAM13_UPLOAD_DIR") or
              "/www/wwwroot/default-site/zb-t1365d2f4f3/_uploads").rstrip("/")
URL_PREFIX = (os.environ.get("TEAM13_UPLOAD_URL_PREFIX") or
              "/zb-t1365d2f4f3/_uploads").rstrip("/")
VOUCHER_URL_RE = re.compile(r"^" + re.escape(URL_PREFIX) +
    r"/[A-Za-z0-9_.-]+\.(jpg|jpeg|png|gif)$", re.I)
IMG_EXT = {"jpg", "jpeg", "png", "gif"}
# webp 已下架:服务器 Pillow 8.4.0 的 libwebp 解码有 CVE-2023-4863(堆溢出可执行代码),
# 而上传的图必过 Pillow 生成缩略图。等 Pillow 升到 10.3+ 再考虑放回来。
# 光看扩展名不够——Pillow 按文件内容识别格式,改名成 .jpg 的 webp 照样走 webp 解码器,
# 所以下面按文件头(magic bytes)校验真实格式,并把 Image.open 限制在白名单格式内。
IMG_MAGIC = [(b"\xff\xd8\xff", "jpg"), (b"\x89PNG\r\n\x1a\n", "png"),
             (b"GIF87a", "gif"), (b"GIF89a", "gif")]
PIL_FORMATS = ["JPEG", "PNG", "GIF"]

def sniff_image(path):
    """返回文件头识别出的真实图片格式;不在白名单内返回 None。"""
    try:
        with open(path, "rb") as fh:
            head = fh.read(16)
    except Exception:
        return None
    for sig, kind in IMG_MAGIC:
        if head.startswith(sig):
            return kind
    return None

def verify_image_file(path, expected_ext=""):
    """完整解码图片，拒绝只有魔数的伪图、截断图和扩展名错配。"""
    try:
        from PIL import Image
        Image.MAX_IMAGE_PIXELS = 100000000
        expected = {"jpg": "JPEG", "jpeg": "JPEG", "png": "PNG", "gif": "GIF"}.get(
            (expected_ext or "").lower())
        im = Image.open(path, formats=PIL_FORMATS)
        actual = im.format
        im.verify()
        if expected and actual != expected:
            return False
        im = Image.open(path, formats=PIL_FORMATS); im.seek(0); im.load()
        return im.width > 0 and im.height > 0 and (im.width * im.height) <= 100000000
    except Exception:
        return False

def sniff_video(path):
    """按文件头校验视频，防止把任意文件改名为 mp4/webm 上传。"""
    try:
        with open(path, "rb") as fh:
            head = fh.read(16)
    except Exception:
        return None
    if len(head) >= 12 and head[4:8] == b"ftyp":
        return "iso-media"
    if head.startswith(b"\x1a\x45\xdf\xa3"):
        return "webm"
    return None
VID_EXT = {"mp4", "mov", "webm", "m4v"}
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 135 * 1024 * 1024  # 135MB

@app.before_request
def _same_site_write_guard():
    # Team13 已正式切换为徐州舟格电商运营系统。迁移前旧业务接口及 V1
    # 组级接口仅保留为兼容归档，不再对生产会话开放。
    path = request.path or ""
    legacy_prefixes = ("/material/", "/messages", "/topics", "/topic/", "/admin/",
        "/quiz/", "/report/", "/anchor/", "/rank/", "/morning", "/staff/",
        "/shift/", "/comm/", "/my/", "/pay/", "/org/", "/selfcheck")
    if path.startswith(legacy_prefixes) or (path.startswith("/ecom/") and not path.startswith("/ecom/v2/")):
        return jsonify(err="该旧业务接口已停用"), 404
    # 浏览器发起的写操作必须来自舟格正式站点；无 Origin 的服务端巡检仍可用。
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        origin = (request.headers.get("Origin") or "").rstrip("/")
        if origin and origin not in ALLOWED_ORIGINS:
            return jsonify(err="请从已配置的正式页面操作"), 403

@app.after_request
def _security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    return resp

def _sqlite_operational_response(exc):
    """SQLite 竞争统一返回可重试的 JSON，其他库错误不泄露细节。"""
    if "locked" in str(exc).lower() or "busy" in str(exc).lower():
        resp = jsonify(err="系统正在处理其他数据，请稍后重试", retryable=True)
        resp.status_code = 503
        resp.headers["Retry-After"] = "2"
        return resp
    return jsonify(err="数据库服务异常，请联系管理员"), 500

@app.errorhandler(sqlite3.OperationalError)
def _sqlite_operational_error(exc):
    return _sqlite_operational_response(exc)

def db():
    c = sqlite3.connect(DB, timeout=10)
    c.row_factory = sqlite3.Row
    # SQLite 的外键开关是“每连接”生效；旧库没有 V2 外键约束也不会
    # 因此在启动时失败，但新表/已有外键从此会真正受保护。
    c.execute("pragma foreign_keys=on")
    c.execute("pragma busy_timeout=10000")
    return c

def ensure_cols(cur, table, cols):
    have = [r[1] for r in cur.execute("pragma table_info(%s)" % table).fetchall()]
    for name, typ in cols:
        if name not in have:
            cur.execute("alter table %s add column %s %s" % (table, name, typ))

def init():
    c = db(); cur = c.cursor()
    cur.execute("create table if not exists messages(id integer primary key autoincrement,name text,body text,ip text,created integer)")
    cur.execute("create table if not exists topics(id integer primary key autoincrement,cat text,title text,name text,body text,ip text,created integer,updated integer,rc integer default 0)")
    cur.execute("create table if not exists replies(id integer primary key autoincrement,tid integer,name text,body text,ip text,created integer)")
    ensure_cols(cur, "topics", [("pinned", "integer default 0"), ("featured", "integer default 0"), ("media", "text")])
    ensure_cols(cur, "messages", [("media", "text")])
    ensure_cols(cur, "replies", [("media", "text")])
    cur.execute("create table if not exists quiz_results(id integer primary key autoincrement,name text,paper text,score integer,total integer,cats text,wrong text,ip text,created integer)")
    cur.execute("create table if not exists live_sessions(id integer primary key autoincrement,filler text,d text,t1 text,t2 text,dur integer,anchor text,zk text,kouzi text,consult text,cost real,gmv real,ban text,ip text,created integer)")
    ensure_cols(cur, "live_sessions", [("room", "text"), ("orders", "integer"), ("media", "text"), ("assist", "text"), ("touliu", "text")])
    cur.execute("create table if not exists daily_reports(id integer primary key autoincrement,filler text,d text,add_wx integer,leads integer,invite integer,arrive integer,verify_amt real,upsell_amt real,wx_total integer,ip text,created integer)")
    ensure_cols(cur, "daily_reports", [("anchor", "text"), ("tmr_invite", "integer"), ("media", "text")])
    cur.execute("create table if not exists shifts(id integer primary key autoincrement,room text,tslot text,anchor text,assist text,zk text,kouzi text,touliu text,sort integer,created integer)")
    ensure_cols(cur, "shifts", [("wangzi", "text"), ("day", "text"), ("extras", "text")])
    cur.execute("create table if not exists staff(id integer primary key autoincrement,name text,phone text,position text,join_date text,bank_card text,ip text,created integer)")
    ensure_cols(cur, "staff", [("salary", "real"), ("note", "text")])
    cur.execute("create table if not exists comm_rule(role text primary key,base text,tiers text,updated integer)")
    cur.execute("create table if not exists comm_exempt(name text primary key,added integer)")
    cur.execute("create table if not exists staff_hidden(name text primary key,created integer)")
    cur.execute("create table if not exists role_off(role text primary key,created integer)")
    cur.execute("create table if not exists materials(id integer primary key autoincrement,cat text,caption text,url text,type text,uploader text,ip text,created integer)")
    cur.execute("create table if not exists staff_card_log(id integer primary key autoincrement,name text,old4 text,new4 text,ip text,ts integer,applied integer)")
    cur.execute("create table if not exists authfail(ip text,ts integer)")
    cur.execute("create table if not exists uploadlog(ip text,ts integer)")
    # 发薪快照:锁定某个月后,该月发薪表永远读这里,不再随提成规则变动重算(月底对账凭据)。
    cur.execute("create table if not exists pay_snapshot(id integer primary key autoincrement,month text,name text,position text,salary real,comm_total real,total real,detail_json text,rule_json text,locked_at integer,locked_by_ip text)")
    cur.execute("create index if not exists idx_pay_snapshot_month on pay_snapshot(month)")
    # 覆盖锁定(force)前,旧快照整月搬到这里,不直接丢。
    cur.execute("create table if not exists pay_snapshot_arch(id integer primary key autoincrement,month text,name text,position text,salary real,comm_total real,total real,detail_json text,rule_json text,locked_at integer,locked_by_ip text,archived_at integer)")
    # 付款台账与应发快照分开：快照记录“应发多少”，台账记录“已经发了多少”。
    cur.execute("create table if not exists pay_payment_record(id integer primary key autoincrement,month text,name text,paid_amount real,paid_at integer,note text,source text,created integer,updated integer)")
    cur.execute("create unique index if not exists idx_pay_payment_month_name on pay_payment_record(month,name)")
    c.commit(); c.close()

def _key_ok(d, expected):
    # 正确密钥永远放行(不受节流影响,修复"一人连错锁死所有管理员");错误密钥才计数节流
    if d.get("key") == expected:
        return True
    ipv = ipaddr(); now = int(time.time())
    c = db(); cur = c.cursor()
    cur.execute("delete from authfail where ts<?", (now - 300,))
    cnt = cur.execute("select count(*) from authfail where ip=? and ts>?", (ipv, now - 300)).fetchone()[0]
    if cnt >= 15:
        c.commit(); c.close(); return None
    cur.execute("insert into authfail(ip,ts) values(?,?)", (ipv, now)); c.commit(); c.close()
    return False

def _internal_request():
    remote = request.remote_addr or ""
    proxied = request.headers.get("X-Real-IP") or request.headers.get("X-Forwarded-For")
    return remote in ("127.0.0.1", "::1") and not proxied

def _internal_key_ok(d, expected):
    expected = expected if isinstance(expected, tuple) else (expected,)
    return _internal_request() and (d.get("key") in expected or d.get("lv") in expected)

def admin_ok(d):
    if _sess_verify(request.cookies.get("zb13sess", "")) == "admin":
        return True
    if _internal_key_ok(d, ADMIN_KEY):
        return True
    return False

def _guard(a):
    if a is None:
        return jsonify(err="尝试次数过多,请稍后再试"), 429
    if not a:
        return jsonify(err="密码不对,无权限"), 403
    return None

def admin_guard(d):
    return _guard(admin_ok(d))

def pii_guard(d):
    # 敏感数据(银行卡/身份证/薪资)专用:只认 PII_KEY,不使用普通管理员会话替代。
    return _guard(_key_ok(d, PII_KEY))

def digits(s):
    return "".join(ch for ch in (s or "") if ch.isdigit())
if SCHEMA_MIGRATION_MODE:
    # 只允许发布流程中的单进程迁移命令执行 DDL。Gunicorn 多 worker
    # 启动时保持只读校验，避免多个 worker 同时 ALTER TABLE。
    init()

def ipaddr():
    xf = request.headers.get("X-Real-IP") or request.remote_addr or ""
    return xf.strip()

def clean(s, mx):
    # API 字符串字段收到数组/对象/数字时按空值处理，交给业务校验返回 400，不抛 500。
    if not isinstance(s, str):
        return ""
    return s.strip()[:mx]

# 同一个人的多种写法(本名↔昵称)。老板2026-07-26确认:王萌=萌萌、刘苏帆=帆帆、王朔宁=夏夏。
# 填报时写哪个都算同一个人,防止"白名单只认昵称"导致漏发提成、发薪表分裂成两行。
# 王朔宁的花名册行已进 staff_hidden(名单只显示夏夏),别名兜底防手填本名。
NAME_ALIAS = {}  # 徐州舟格人员别名待确认

def norm_name(s):
    # 姓名规范化:去掉全部空白(含全角空格)+零宽字符,再做 NFKC 统一全半角。
    # 防"张 梦"和"张梦"、带零宽字符的同名被当成两个人导致提成算错、名单被污染。
    # 所有写入人名的接口(登记/场次填报/日报/排班)统一走这里。
    if not isinstance(s, str):
        return ""
    s = unicodedata.normalize("NFKC", s)
    s = re.sub(r"[\s　​‌‍﻿]+", "", s)[:24]
    return NAME_ALIAS.get(s, s)

def parse_media(v):
    try:
        m = json.loads(v) if v else []
    except Exception:
        m = []
    out = []
    if isinstance(m, list):
        for it in m[:9]:
            if isinstance(it, dict) and re.match(r"^/zb-t1365d2f4f3/_uploads/[A-Za-z0-9_.\-]+$", it.get("url", "") or "") and it.get("type") in ("image", "video"):
                out.append({"url": it["url"], "type": it["type"]})
    return out

def dump_media(d):
    return json.dumps(parse_media(json.dumps(d.get("media") or [])))

def row(d):
    d = dict(d)
    if "media" in d:
        d["media"] = parse_media(d.get("media"))
    return d

def too_fast(ipv):
    now = int(time.time())
    c = db()
    r = c.execute("select max(t) from (select created t from messages where ip=? union all select created from topics where ip=? union all select created from replies where ip=?)", (ipv, ipv, ipv)).fetchone()
    c.close()
    return bool(r and r[0] and now - r[0] < 2)

def upload_too_many(ipv, limit=40, window=60):
    now = int(time.time())
    c = db(); cur = c.cursor()
    cur.execute("delete from uploadlog where ts < ?", (now - window,))
    n = cur.execute("select count(*) from uploadlog where ip=? and ts > ?", (ipv, now - window)).fetchone()[0]
    if n >= limit:
        c.commit(); c.close(); return True
    cur.execute("insert into uploadlog(ip,ts) values(?,?)", (ipv, now))
    c.commit(); c.close(); return False

@app.get("/health")
def health():
    version = 0; database = "unknown"
    try:
        c = db(); database = c.execute("pragma quick_check").fetchone()[0]
        row = c.execute("select max(version) from ecom_v2_schema_version").fetchone()
        version = int(row[0] or 0) if row else 0; c.close()
    except Exception:
        database = "migration_required"
    return jsonify(ok=database == "ok", service="xuzhou-zhouge-ecommerce", schema_version=version,
                   database=database)

# ---------- 服务端登录(把密码从前端源码里拿掉;nginx 用 /authcheck 挡未登录访问) ----------
def _login_throttled():
    # 登录失败限流(密码错/姓名手机对不上都算):同IP 5分钟错15次锁
    ipv = ipaddr(); now = int(time.time())
    c = db(); cur = c.cursor()
    cur.execute("delete from authfail where ts<?", (now - 300,))
    cnt = cur.execute("select count(*) from authfail where ip=? and ts>?", (ipv, now - 300)).fetchone()[0]
    if cnt >= 15:
        c.commit(); c.close(); return True
    cur.execute("insert into authfail(ip,ts) values(?,?)", (ipv, now)); c.commit(); c.close()
    return False

def _login_blocked():
    """在校验密码前检查锁定；锁定期内正确密码也不能绕过。"""
    ipv = ipaddr(); now = int(time.time()); c = db(); cur = c.cursor()
    cur.execute("delete from authfail where ts<?", (now - 300,))
    cnt = cur.execute("select count(*) from authfail where ip=? and ts>?", (ipv, now - 300)).fetchone()[0]
    c.commit(); c.close(); return cnt >= 15

def _login_clear_failures():
    c = db(); c.execute("delete from authfail where ip=?", (ipaddr(),)); c.commit(); c.close()

@app.post("/login")
def login():
    d = request.get_json(force=True, silent=True) or {}
    if not isinstance(d, dict) or not isinstance(d.get("password"), str):
        return jsonify(err="密码格式不正确"), 400
    if _login_blocked():
        return jsonify(err="尝试次数过多,请5分钟后再试"), 429
    pw = d.get("password", "").strip()
    role = LOGIN_PW.get(pw)
    # 舟格员工启用个人登录密码后，不再允许共用员工密码冒用身份。
    # 管理员仍使用独立管理员密码；尚未迁入V2分组的旧员工维持原登录方式。
    v2_name = norm_name(d.get("name"))
    v2_hash = ""; v2_auth_version = 0
    try:
        vc = db()
        vr = vc.execute("select password_hash,auth_version from ecom_v2_members where name=? and active=1", (v2_name,)).fetchone()
        vc.close()
        v2_hash = vr["password_hash"] if vr else ""
        v2_auth_version = int(vr["auth_version"] or 1) if vr else 0
    except Exception:
        v2_hash = ""
    if v2_hash:
        if _v2_password_verify(pw, v2_hash): role = "employee"
        elif role == "employee": role = None
    if not role:
        if _login_throttled(): return jsonify(err="尝试次数过多,请稍后再试"), 429
        return jsonify(err="密码不对,请重试"), 403
    name = ""
    if role == "employee":
        # 实名登录(老板2026-07-27定):员工必须 真实姓名+手机号+员工密码。
        # 姓名对花名册(经norm_name,别名/空格写法都归一);手机号对登记手机;
        # 花名册没存手机号的人,第一次登录自动把填的手机号绑定进staff表。
        nm = norm_name(d.get("name"))
        ph = re.sub(r"\D", "", str(d.get("phone") or ""))[:15]
        if not nm or len(ph) < 6:
            return jsonify(err="员工登录需要填 真实姓名 和 手机号"), 400
        if nm in hidden_names():
            if _login_throttled(): return jsonify(err="尝试次数过多,请稍后再试"), 429
            return jsonify(err="名单里没有这个名字,请联系管理员登记"), 403
        c = db()
        r = c.execute("select id,phone from staff where name=?", (nm,)).fetchone()
        found = bool(r); tpl_phone = ""
        for t in template_staff():
            if t["name"] == nm:
                found = True
                tpl_phone = re.sub(r"\D", "", str(t.get("phone") or ""))
                break
        if not found:
            c.close()
            if _login_throttled(): return jsonify(err="尝试次数过多,请稍后再试"), 429
            return jsonify(err="名单里没有这个名字,写法要和花名册一致;确认没登记就找管理员"), 403
        db_phone = re.sub(r"\D", "", str(r["phone"] or "")) if r else ""
        reg_phone = db_phone or tpl_phone
        if reg_phone:
            if reg_phone != ph:
                c.close()
                if _login_throttled(): return jsonify(err="尝试次数过多,请稍后再试"), 429
                return jsonify(err="手机号和登记的对不上;忘了登记的是哪个号就找管理员查"), 403
        else:
            if r:
                c.execute("update staff set phone=? where id=?", (ph, r["id"]))
            else:
                c.execute("insert into staff(name,phone,note,created) values(?,?,?,?)",
                          (nm, ph, "实名登录首次绑定手机号", int(time.time())))
            c.commit()
        c.close()
        name = nm
    exp = int(time.time()) + SESSION_TTL
    _login_clear_failures()
    resp = jsonify(ok=True, role=role, name=name)
    resp.set_cookie("zb13sess", _sess_sign(role, exp, name, v2_auth_version), max_age=SESSION_TTL,
                    httponly=True, secure=True, samesite="Lax", path="/")
    return resp

@app.get("/whoami")
def whoami():
    # 我的页用:返回登录身份(角色+实名)。不含手机号等任何PII。
    role, name = _sess_parse(request.cookies.get("zb13sess", ""))
    return jsonify(role=role or "", name=name or "")

# 含敏感数据(银行卡/薪资/经营明细)的管理页:必须 admin 角色才放行。
# 其余页只要登录即可。非 admin 打开这些页,前端本就清 body 显示"仅管理员可见",
# 这里在 nginx 层再挡一道(纵深防御),避免连页面骨架都暴露。
ADMIN_ONLY_PAGES = {
    "后台.html", "人员分组.html", "结算中心.html", "我的.html",
    "发薪总表.html", "业绩提成.html", "岗位人员管理.html", "人员登记.html",
    "_renyuan_kanban_p3v9.html", "_baobiao_kanban_r7k3.html",
    "_kaohe_kanban_x8k2m.html", "_kanban_fleixe93k.html",
}

LEADER_PAGES = {"组内看板.html", "核账中心.html", "报销中心.html", "绩效海报.html", "账号台账.html"}

# 只对内的页(员工或管理员都能看,访客不行)。
EMP_ONLY_PAGES = {"首页.html", "0_直播间作战总览.html", "每日填报.html", "素材佐证库.html"}

@app.get("/authcheck")
def authcheck():
    # nginx auth_request 子请求调它:通行证有效返回200(放行),无效401(跳登录页),
    # 已登录但角色不够看 admin 页返回403(nginx 转 @noperm 引导去登录/切换)。
    role, session_name = _sess_parse(request.cookies.get("zb13sess", ""))
    if not role:
        return ("", 401)
    uri = request.headers.get("X-Original-URI", "")
    try:
        base = urllib.parse.unquote(uri.split("?", 1)[0]).rsplit("/", 1)[-1]
    except Exception:
        base = ""
    if base in ADMIN_ONLY_PAGES and role != "admin":
        return ("", 403)
    if base in LEADER_PAGES and role != "admin":
        if role != "employee" or not session_name:
            return ("", 403)
        c = db()
        leader = c.execute("select is_leader from ecom_v2_members where name=? and active=1",
                           (session_name,)).fetchone()
        c.close()
        if not leader or not int(leader["is_leader"] or 0):
            return ("", 403)
    if base in EMP_ONLY_PAGES and role not in ("employee", "admin"):
        return ("", 403)
    return ("", 200)

def speaker_name(d):
    # 发言实名(老板2026-07-27定):留言板/论坛自动用登录实名。
    # 员工会话带实名 → 强制用实名(页面传什么都不认,防冒名);
    # 管理员会话无姓名 → 用页面填的名,默认"管理员";
    # 改版前的旧员工token(无姓名)→ 退回页面填的名(他们重登后自动变实名)。
    role, nm = _sess_parse(request.cookies.get("zb13sess", ""))
    if role == "employee" and nm:
        return nm
    v = clean(d.get("name"), 24)
    if role == "admin":
        return v or "管理员"
    return v or "匿名"

@app.post("/logout")
def logout():
    tok = request.cookies.get("zb13sess", "")
    if tok:
        try:
            parts = tok.split("|"); expires = int(parts[1]) if len(parts) >= 3 else int(time.time()) + SESSION_TTL
            c = db(); c.execute("delete from ecom_v2_revoked_sessions where expires<=?", (int(time.time()),))
            c.execute("insert or replace into ecom_v2_revoked_sessions(token_hash,expires,created) values(?,?,?)",
                      (hashlib.sha256(tok.encode("utf-8")).hexdigest(), expires, int(time.time())))
            c.commit(); c.close()
        except Exception:
            pass
    resp = jsonify(ok=True)
    resp.set_cookie("zb13sess", "", max_age=0, path="/")
    return resp

# ---------- 上传 ----------
@app.post("/upload")
def upload():
    if not emp_ok({"lv": request.form.get("lv")}):
        return jsonify(err="上传需员工或管理员密码"), 403
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify(err="没有文件"), 400
    if upload_too_many(ipaddr()):
        return jsonify(err="上传太频繁了,请过一会儿再传(每分钟最多40个文件)"), 429
    if request.content_length and request.content_length > 10 * 1024 * 1024:
        return jsonify(err="付款凭证图片不能超过10MB"), 413
    ext = f.filename.rsplit(".", 1)[-1].lower() if "." in f.filename else ""
    if ext not in IMG_EXT:
        return jsonify(err="付款凭证只支持jpg/png/gif图片"), 400
    typ = "image"
    name = str(int(time.time())) + "_" + secrets.token_hex(6) + "." + ext
    fpath = os.path.join(UPLOAD_DIR, name)
    try:
        f.save(fpath)
    except Exception:
        return jsonify(err="保存失败"), 500
    if typ == "image":
        # 必须完整解码且真实格式和扩展名一致；只有JPEG魔数的伪文件也会被拒绝。
        if not verify_image_file(fpath, ext):
            try: os.remove(fpath)
            except Exception: pass
            return jsonify(err="图片损坏或格式与扩展名不一致，请重新保存后上传"), 400
        # 生成缩略图失败时视为整个上传失败，不能留下无法核验的付款凭证。
        try:
            from PIL import Image
            Image.MAX_IMAGE_PIXELS = 100000000
            td = os.path.join(UPLOAD_DIR, "_thumb")
            os.makedirs(td, exist_ok=True)
            im = Image.open(fpath, formats=PIL_FORMATS)
            im.seek(0)
            if im.mode not in ("RGB", "L"):
                im = im.convert("RGB")
            im.thumbnail((240, 240))
            im.save(os.path.join(td, name + ".jpg"), "JPEG", quality=72, optimize=True)
        except Exception:
            try: os.remove(fpath)
            except Exception: pass
            return jsonify(err="图片处理失败，请重新导出后上传"), 400
    return jsonify(url=URL_PREFIX + "/" + name, type=typ)

# ---------- 素材佐证库(团队上传,自动入库自动配文) ----------
MAT_CATS = ["团队风采", "直播现场", "经营战报", "客户案例", "成交记录"]
MAT_AUTO = {
    "团队风采": "团队风采·日常实拍",
    "直播现场": "直播现场·团队作战实拍",
    "经营战报": "经营战报·后台数据实录",
    "客户案例": "客户案例·真实记录",
    "成交记录": "成交记录·实时成交数据",
}

@app.get("/material/list")
def material_list():
    # 素材含客户案例/成交记录等不宜外泄的实拍:只给员工/管理员(密码或已登录会话)。
    if not emp_ok({"lv": request.args.get("lv", "")}):
        return jsonify(err="素材库仅员工或管理员可见"), 403
    c = db(); rows = c.execute("select id,cat,caption,url,type,uploader,created from materials order by id desc limit 500").fetchall(); c.close()
    return jsonify([dict(x) for x in rows])

@app.post("/material/add")
def material_add():
    d = request.get_json(force=True, silent=True) or {}
    if not emp_ok(d): return jsonify(err="上传需员工或管理员密码"), 403
    cat = d.get("cat") if d.get("cat") in MAT_CATS else MAT_CATS[0]
    caption = clean(d.get("caption"), 80)
    uploader = clean(d.get("uploader"), 24) or "匿名"
    media = parse_media(json.dumps(d.get("media") or []))
    if not media:
        return jsonify(err="没有可入库的文件"), 400
    ts = int(time.time())
    day = time.strftime("%m-%d", time.localtime(ts))
    c = db(); cur = c.cursor()
    for m in media:
        cap = caption or (MAT_AUTO[cat] + " · " + day)
        cur.execute("insert into materials(cat,caption,url,type,uploader,ip,created) values(?,?,?,?,?,?,?)",
                    (cat, cap, m["url"], m["type"], uploader, ipaddr(), ts))
    c.commit(); c.close()
    return jsonify(ok=True, n=len(media))

@app.post("/material/del")
def material_del():
    d = request.get_json(force=True, silent=True) or {}
    g = admin_guard(d)
    if g: return g
    c = db(); c.execute("delete from materials where id=?", (numi(d.get("id")),)); c.commit(); c.close()
    return jsonify(ok=True)

# ---------- 留言板 ----------
@app.get("/messages")
def get_messages():
    c = db(); rows = c.execute("select id,name,body,media,created from messages order by id desc limit 300").fetchall(); c.close()
    return jsonify([row(x) for x in rows])

@app.post("/messages")
def post_message():
    d = request.get_json(force=True, silent=True) or {}
    if not emp_ok(d): return jsonify(err="发言需员工或管理员密码(访客只读)"), 403
    name = speaker_name(d)
    body = clean(d.get("body"), 1000)
    media = dump_media(d)
    if not body and media == "[]":
        return jsonify(err="写点字或传张图吧"), 400
    ipv = ipaddr()
    if too_fast(ipv):
        return jsonify(err="发得太快了,歇口气再发~"), 429
    c = db(); c.execute("insert into messages(name,body,media,ip,created) values(?,?,?,?,?)", (name, body, media, ipv, int(time.time()))); c.commit(); c.close()
    return jsonify(ok=True)

# ---------- 论坛 ----------
@app.get("/topics")
def get_topics():
    cat = request.args.get("cat", "")
    feat = request.args.get("featured", "")
    cond = []; args = []
    if cat and cat in CATS:
        cond.append("cat=?"); args.append(cat)
    if feat == "1":
        cond.append("featured=1")
    q = "select id,cat,title,name,media,created,updated,rc,pinned,featured from topics"
    if cond:
        q += " where " + " and ".join(cond)
    q += " order by pinned desc, updated desc limit 300"
    c = db(); rows = c.execute(q, tuple(args)).fetchall(); c.close()
    return jsonify([row(x) for x in rows])

@app.post("/topics")
def post_topic():
    d = request.get_json(force=True, silent=True) or {}
    if not emp_ok(d): return jsonify(err="发帖需员工或管理员密码(访客只读)"), 403
    cat = d.get("cat") if d.get("cat") in CATS else CATS[0]
    title = clean(d.get("title"), 60)
    body = clean(d.get("body"), 5000)
    name = speaker_name(d)
    media = dump_media(d)
    if not title:
        return jsonify(err="标题要填哦"), 400
    if not body and media == "[]":
        return jsonify(err="正文写点字或传个图/视频"), 400
    ipv = ipaddr()
    if too_fast(ipv):
        return jsonify(err="发得太快了,歇口气再发~"), 429
    now = int(time.time())
    c = db(); cur = c.cursor()
    cur.execute("insert into topics(cat,title,name,body,media,ip,created,updated,rc) values(?,?,?,?,?,?,?,?,0)", (cat, title, name, body, media, ipv, now, now))
    c.commit(); tid = cur.lastrowid; c.close()
    return jsonify(ok=True, id=tid)

@app.get("/topic/<int:tid>")
def get_topic(tid):
    c = db()
    t = c.execute("select id,cat,title,name,body,media,created,rc,pinned,featured from topics where id=?", (tid,)).fetchone()
    if not t:
        c.close(); return jsonify(err="帖子不存在或已删除"), 404
    rs = c.execute("select id,name,body,media,created from replies where tid=? order by id asc", (tid,)).fetchall()
    c.close()
    return jsonify(topic=row(t), replies=[row(x) for x in rs])

@app.post("/topic/<int:tid>/reply")
def post_reply(tid):
    d = request.get_json(force=True, silent=True) or {}
    if not emp_ok(d): return jsonify(err="回复需员工或管理员密码(访客只读)"), 403
    body = clean(d.get("body"), 3000)
    name = speaker_name(d)
    media = dump_media(d)
    if not body and media == "[]":
        return jsonify(err="回复写点字或传个图吧"), 400
    ipv = ipaddr()
    if too_fast(ipv):
        return jsonify(err="发得太快了,歇口气再发~"), 429
    now = int(time.time())
    c = db(); cur = c.cursor()
    if not cur.execute("select id from topics where id=?", (tid,)).fetchone():
        c.close(); return jsonify(err="帖子不存在或已删除"), 404
    cur.execute("insert into replies(tid,name,body,media,ip,created) values(?,?,?,?,?,?)", (tid, name, body, media, ipv, now))
    cur.execute("update topics set rc=rc+1,updated=? where id=?", (now, tid))
    c.commit(); c.close()
    return jsonify(ok=True)

# ---------- 管理 ----------
@app.post("/admin/del")
def admin_del():
    d = request.get_json(force=True, silent=True) or {}
    g = admin_guard(d)
    if g: return g
    kind = d.get("kind"); id_ = numi(d.get("id"))
    c = db(); cur = c.cursor()
    if kind == "message":
        cur.execute("delete from messages where id=?", (id_,))
    elif kind == "topic":
        cur.execute("delete from topics where id=?", (id_,)); cur.execute("delete from replies where tid=?", (id_,))
    elif kind == "reply":
        r = cur.execute("select tid from replies where id=?", (id_,)).fetchone()
        cur.execute("delete from replies where id=?", (id_,))
        if r:
            cur.execute("update topics set rc=max(0,rc-1) where id=?", (r[0],))
    else:
        c.close(); return jsonify(err="类型错误"), 400
    c.commit(); c.close()
    return jsonify(ok=True)

@app.post("/admin/flag")
def admin_flag():
    d = request.get_json(force=True, silent=True) or {}
    g = admin_guard(d)
    if g: return g
    field = d.get("field")
    if field not in ("pinned", "featured"):
        return jsonify(err="字段错误"), 400
    val = 1 if d.get("val") else 0
    c = db(); c.execute("update topics set %s=? where id=?" % field, (val, numi(d.get("id")))); c.commit(); c.close()
    return jsonify(ok=True)

# ---------- 考核测评 ----------
@app.post("/quiz/submit")
def quiz_submit():
    d = request.get_json(force=True, silent=True) or {}
    if not emp_ok(d): return jsonify(err="做题需员工或管理员密码"), 403
    name = norm_name(clean(d.get("name"), 24)) or "匿名"
    # 名单锁死(2026-07-27):考核成绩也只认名单内的名字,防假名混进成绩看板;匿名练手仍允许
    if name != "匿名" and name not in known_names():
        return jsonify(err="「%s」不在人员名单里,成绩没法记到人头上。新人请先让管理员在「人员登记」录入。" % name), 400
    paper = clean(d.get("paper"), 40)
    try:
        score = int(d.get("score") or 0); total = int(d.get("total") or 0)
    except Exception:
        score, total = 0, 0
    if total < 0: total = 0
    if score < 0: score = 0
    if score > total: score = total
    cats = json.dumps(d.get("cats") or [], ensure_ascii=False)[:4000]
    wrong = json.dumps(d.get("wrong") or [], ensure_ascii=False)[:4000]
    c = db(); c.execute("insert into quiz_results(name,paper,score,total,cats,wrong,ip,created) values(?,?,?,?,?,?,?,?)",
                        (name, paper, score, total, cats, wrong, ipaddr(), int(time.time()))); c.commit(); c.close()
    return jsonify(ok=True)

@app.post("/quiz/results")
def quiz_results():
    d = request.get_json(force=True, silent=True) or {}
    g = admin_guard(d)
    if g: return g
    c = db(); rows = c.execute("select id,name,paper,score,total,cats,wrong,created from quiz_results order by id desc limit 800").fetchall(); c.close()
    out = []
    for x in rows:
        r = dict(x)
        try: r["cats"] = json.loads(r.get("cats") or "[]")
        except Exception: r["cats"] = []
        try: r["wrong"] = json.loads(r.get("wrong") or "[]")
        except Exception: r["wrong"] = []
        out.append(r)
    return jsonify(out)

@app.post("/quiz/mine")
def quiz_mine():
    """员工查自己名下的考核成绩(按传入姓名过滤;员工共用密码,与 /report/mine 同一信任模型)。不返回 wrong 题目详情。"""
    d = request.get_json(force=True, silent=True) or {}
    if not emp_ok(d): return jsonify(err="需员工或管理员密码"), 403
    names = d.get("names")
    if not isinstance(names, list): names = [d.get("name")]
    keys = set()
    for n in names[:4]:
        n = norm_name(clean(n if isinstance(n, str) else "", 24))
        if n: keys.add(n)
    if not keys: return jsonify([])
    c = db(); rows = c.execute("select id,name,paper,score,total,cats,created from quiz_results order by id desc limit 2000").fetchall(); c.close()
    out = []
    for x in rows:
        if norm_name(x["name"]) not in keys: continue
        r = {"id": x["id"], "name": x["name"], "paper": x["paper"], "score": x["score"], "total": x["total"], "created": x["created"]}
        try: r["cats"] = json.loads(x["cats"] or "[]")
        except Exception: r["cats"] = []
        out.append(r)
        if len(out) >= 200: break
    return jsonify(out)

# ---------- 每日填报 ----------
def numf(v):
    try: return float(v)
    except Exception: return 0.0
def numi(v):
    try: return int(float(v))
    except Exception: return 0
def valid_date(x):
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", x or ""): return False
    try:
        import datetime; y,m,dd=[int(t) for t in x.split("-")]; datetime.date(y,m,dd); return True
    except Exception: return False

def biz_normalize(dstr):
    """营业日兜底:凌晨0~3点提交且日期=自然日今天 -> 归前一天(团队干到凌晨3点)"""
    now = datetime.datetime.now()
    if now.hour < 3 and dstr == now.strftime("%Y-%m-%d"):
        return (now.date() - datetime.timedelta(days=1)).isoformat()
    return dstr

# 场次填报里的人名岗位,用于"同一个人不能同时占两个岗位"的源头校验。
LIVE_POS_LABEL = [("anchor", "主播"), ("assist", "助播"), ("zk", "中控"),
                  ("kouzi", "扣字小助理"), ("touliu", "投手"), ("consult", "现场咨询师")]

def _truthy(v):
    return v is True or v == 1 or (isinstance(v, str) and v.strip().lower() in ("1", "true", "yes"))

def _hhmm(s):
    """'HH:MM' -> 分钟数;解析不了返回 None。"""
    try:
        h, m = (s or "").strip().split(":")[:2]
        return int(h) * 60 + int(m)
    except Exception:
        return None

def _overlap(a1, a2, b1, b2):
    """两个 'HH:MM' 时间段是否重叠。结束<=开始视为跨零点(+24h)。
    同一直播间的两场直播物理上不可能重叠——重叠即同一场(老板2026-08-01定)。"""
    x1, x2, y1, y2 = _hhmm(a1), _hhmm(a2), _hhmm(b1), _hhmm(b2)
    if None in (x1, x2, y1, y2):
        return False
    if x2 <= x1: x2 += 1440
    if y2 <= y1: y2 += 1440
    return x1 < y2 and y1 < x2

def confirmed(d, *names):
    """前端二次确认标志。每种警告认自己的参数名(老板2026-07-27定的口径,前端 build-dropdown 已按此实现):
       同人兼多岗 -> confirm_multi_role / 同场次重复 -> confirm_dup / 到店>邀约 -> confirm_arrive
    一个确认只放行它自己那一项,不会顺手把另一种警告也吞掉。
    通用 confirm=true 放行全部(给脚本/补录工具留的口子);旧别名继续收,避免已上线前端断掉。"""
    keys = list(names) + ["confirm", "confirm_warn", "confirm_over"]
    return any(_truthy(d.get(k)) for k in keys)

def dup_person_in_session(d):
    """同一条场次记录里同一个人被填在两个岗位 -> 返回 (人名, 岗位1, 岗位2, 是否硬拦);没有返回 None。
    分级口径(老板2026-07-27拍板,前端 build-dropdown 同口径实现,两边必须一致):
      ① 主播+助播 同人 = 硬拦 400:物理上不可能,必然填错,而且白名单里的人会被算两遍 1%
         (live_sessions id38 就是这个情况)。
      ② 其它任意组合(主播兼中控、中控兼投手…)= 软拦 409:小团队一人兼多职是真实业务
         (库里 32 场有 4 场如此),只给二次确认,带 confirm_multi_role 放行。
    ③ 咨询日报 filler(网咨本人)和 anchor(当天配合的主播)重名不在这里管,也不拦不警告——
      夏夏是"主播、网咨"双岗,她既当主播又交日报是正常业务,拦了全是噪音。"""
    seen = {}
    soft = None
    for key, label in LIVE_POS_LABEL:
        nm = norm_name(d.get(key))
        if not nm or nm in NOT_A_PERSON:
            continue
        if nm in seen:
            k0 = seen[nm][0]
            if set((k0, key)) == set(("anchor", "assist")):
                return (nm, seen[nm][1], label, True)
            if soft is None:
                soft = (nm, seen[nm][1], label, False)
            continue
        seen[nm] = (key, label)
    return soft

@app.post("/report/live")
def report_live():
    d = request.get_json(force=True, silent=True) or {}
    if not emp_ok(d): return jsonify(err="填报需员工或管理员密码"), 403
    date = clean(d.get("d"), 20)
    zk = norm_name(d.get("zk"))
    if not date or not zk:
        return jsonify(err="日期和中控必填"), 400
    if not valid_date(date):
        return jsonify(err="日期格式不对(应 2026-07-21)"), 400
    date = biz_normalize(date)
    bad = reject_unknown_names(d, ("zk", "anchor", "assist", "kouzi", "consult", "touliu"))
    if bad: return bad
    room = clean(d.get("room"), 16)
    if room and room not in ("一号直播间", "二号直播间"):
        return jsonify(err="直播间只能选一号或二号"), 400
    cost = numf(d.get("cost")); gmv = numf(d.get("gmv")); orders = numi(d.get("orders"))
    if cost < 0 or gmv < 0 or orders < 0:
        return jsonify(err="消耗/业绩/订单不能为负数"), 400
    if cost > 1e8 or gmv > 1e8 or orders > 100000:
        return jsonify(err="数值过大请核对(消耗/业绩上限1亿·订单上限10万)"), 400
    # ① 同一场同一个人占了两个岗位。主播+助播硬拦(提成会算两遍),其它组合给二次确认。
    dp = dup_person_in_session(d)
    if dp and dp[3]:
        return jsonify(err="「%s」同时填在了「%s」和「%s」。同一场里主播和助播不可能是同一个人,这样提成会算两遍。请改成实际在岗的人,没有的岗位填「无」。" % dp[:3],
                       dup_person=dp[0], dup_pos=[dp[1], dp[2]]), 400
    if dp and not confirmed(d, "confirm_multi_role", "confirm_dup"):
        return jsonify(err="「%s」同时填在了「%s」和「%s」两个岗位。确认这场他一个人兼两职再提交,填错了请改回来。" % dp[:3],
                       dup_person=dp[0], dup_pos=[dp[1], dp[2]],
                       multi_role=True, warn_multi_role=True,
                       need_confirm=True, confirm_field="confirm_multi_role"), 409
    # ② 同一天+同一直播间+同一时段已填过 = 上一场填错了,这次直接覆盖更正(老板2026-07-31定)。
    # 同房间同时段不可能有两场直播,存两条会把业绩/提成算两遍。要补录别的场请填不同时段。
    t1 = clean(d.get("t1"), 10); t2 = clean(d.get("t2"), 10)
    if room or t1 or t2:
        c = db()
        cand = c.execute("select id,t1,t2,media from live_sessions where d=? and ifnull(room,'')=? order by id desc",
                         (date, room)).fetchall()
        ex = None
        for r in cand:
            if (r["t1"] or "") == t1 and (r["t2"] or "") == t2:
                ex = r; break
        if not ex and t1 and t2:
            # 时间填错几分钟也属于「更正同一场」:同一直播间两场直播时间不可能重叠
            for r in cand:
                if _overlap(t1, t2, r["t1"] or "", r["t2"] or ""):
                    ex = r; break
        if ex:
            media = dump_media(d) if "media" in d else (ex["media"] or "[]")
            c.execute("update live_sessions set filler=?,t1=?,t2=?,dur=?,anchor=?,assist=?,zk=?,kouzi=?,consult=?,touliu=?,cost=?,gmv=?,orders=?,ban=?,media=?,ip=?,created=? where id=?",
                (zk, t1, t2, numi(d.get("dur")), norm_name(d.get("anchor")), norm_name(d.get("assist")), zk,
                 norm_name(d.get("kouzi")), norm_name(d.get("consult")), norm_name(d.get("touliu")),
                 cost, gmv, orders, clean(d.get("ban"), 200) or "无", media, ipaddr(), int(time.time()), ex["id"]))
            c.commit(); c.close()
            return jsonify(ok=True, updated=True, corrected=ex["id"])
        c.close()
    c = db(); c.execute("insert into live_sessions(filler,d,room,t1,t2,dur,anchor,assist,zk,kouzi,consult,touliu,cost,gmv,orders,ban,media,ip,created) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (zk, date, room, clean(d.get("t1"),10), clean(d.get("t2"),10), numi(d.get("dur")), norm_name(d.get("anchor")), norm_name(d.get("assist")), zk,
         norm_name(d.get("kouzi")), norm_name(d.get("consult")), norm_name(d.get("touliu")), cost, gmv, orders, clean(d.get("ban"),200) or "无",
         dump_media(d), ipaddr(), int(time.time()))); c.commit(); c.close()
    return jsonify(ok=True)

@app.post("/report/consult")
def report_consult():
    d = request.get_json(force=True, silent=True) or {}
    if not emp_ok(d): return jsonify(err="填报需员工或管理员密码"), 403
    date = clean(d.get("d"), 20)
    filler = norm_name(d.get("filler"))
    if not date or not filler:
        return jsonify(err="日期和填报人必填"), 400
    if not valid_date(date):
        return jsonify(err="日期格式不对(应 2026-07-21)"), 400
    date = biz_normalize(date)
    bad = reject_unknown_names(d, ("filler", "anchor"))
    if bad: return bad
    # 随时填·自动累加(老板2026-08-01定):加了客资/约了人/有客户到店,都可随时提交一笔,
    # 客资/邀约/到店 按次累加进当天总数;主播、明天邀约 取最新一次;佐证图片累加保留(上限9张)。
    # 注意:filler(网咨本人)和 anchor(当天配合的主播)重名是正常的(夏夏双岗),
    # 老板2026-07-27明确不拦不警告,别在这里加"重名检查"。
    c = db(); cur = c.cursor()
    ex = cur.execute("select id,anchor,leads,invite,arrive,tmr_invite,media from daily_reports where d=? and filler=?", (date, filler)).fetchone()
    if ex:
        anchor = norm_name(d.get("anchor")) or (ex["anchor"] or "")
        leads = numi(ex["leads"]) + numi(d.get("leads"))
        invite = numi(ex["invite"]) + numi(d.get("invite"))
        arrive = numi(ex["arrive"]) + numi(d.get("arrive"))
        tmr = numi(d.get("tmr_invite")) if "tmr_invite" in d else numi(ex["tmr_invite"])
        try: old_media = json.loads(ex["media"] or "[]")
        except Exception: old_media = []
        try: new_media = json.loads(dump_media(d))
        except Exception: new_media = []
        media = json.dumps((old_media + new_media)[:9], ensure_ascii=False)
    else:
        anchor = norm_name(d.get("anchor")); leads = numi(d.get("leads")); invite = numi(d.get("invite"))
        arrive = numi(d.get("arrive")); tmr = numi(d.get("tmr_invite")); media = dump_media(d)
    # 自动追平(老板2026-07-30定):按当天累计数判断,累计到店>累计邀约时邀约自动追平到店。
    # 到店是真实发生的人头(提成按它发),邀约低于到店只可能是邀约漏填,以到店为准。
    invite_autofixed = False
    if arrive > invite:
        invite = arrive
        invite_autofixed = True
    # 快照:提交前存上一状态,供「撤销上一笔」恢复(老板2026-08-01定)
    cur.execute("create table if not exists daily_reports_undo(id integer primary key autoincrement,report_id integer,filler text,d text,existed integer,prev_anchor text,prev_leads integer,prev_invite integer,prev_arrive integer,prev_tmr integer,prev_media text,ip text,created integer)")
    if ex:
        cur.execute("insert into daily_reports_undo(report_id,filler,d,existed,prev_anchor,prev_leads,prev_invite,prev_arrive,prev_tmr,prev_media,ip,created) values(?,?,?,1,?,?,?,?,?,?,?,?)",
            (ex["id"], filler, date, ex["anchor"] or "", numi(ex["leads"]), numi(ex["invite"]), numi(ex["arrive"]), numi(ex["tmr_invite"]), ex["media"] or "[]", ipaddr(), int(time.time())))
    else:
        cur.execute("insert into daily_reports_undo(report_id,filler,d,existed,prev_anchor,prev_leads,prev_invite,prev_arrive,prev_tmr,prev_media,ip,created) values(0,?,?,0,'',0,0,0,0,'[]',?,?)",
            (filler, date, ipaddr(), int(time.time())))
    if ex:
        cur.execute("update daily_reports set anchor=?,leads=?,invite=?,arrive=?,tmr_invite=?,media=? where id=?",
                    (anchor, leads, invite, arrive, tmr, media, ex["id"]))
    else:
        cur.execute("insert into daily_reports(filler,d,anchor,leads,invite,arrive,tmr_invite,media,add_wx,verify_amt,upsell_amt,wx_total,ip,created) values(?,?,?,?,?,?,?,?,0,0,0,0,?,?)",
            (filler, date, anchor, leads, invite, arrive, tmr, media, ipaddr(), int(time.time())))
    c.commit(); c.close()
    return jsonify(ok=True, updated=bool(ex), invite_autofixed=invite_autofixed,
                   totals={"leads": leads, "invite": invite, "arrive": arrive, "tmr_invite": tmr})

@app.post("/report/consult/undo")
def report_consult_undo():
    """撤销上一笔(老板2026-08-01定):按快照把当天累计恢复到上一次提交之前;
    撤销当天的第一笔 = 删掉当天整条。可连续撤销,一笔一笔往回退。"""
    d = request.get_json(force=True, silent=True) or {}
    if not emp_ok(d): return jsonify(err="需员工或管理员密码"), 403
    date = clean(d.get("d"), 20)
    filler = norm_name(d.get("filler"))
    if not date or not filler:
        return jsonify(err="日期和填报人必填"), 400
    date = biz_normalize(date)
    c = db(); cur = c.cursor()
    cur.execute("create table if not exists daily_reports_undo(id integer primary key autoincrement,report_id integer,filler text,d text,existed integer,prev_anchor text,prev_leads integer,prev_invite integer,prev_arrive integer,prev_tmr integer,prev_media text,ip text,created integer)")
    u = cur.execute("select * from daily_reports_undo where filler=? and d=? order by id desc limit 1",
                    (filler, date)).fetchone()
    if not u:
        c.close()
        return jsonify(err="这一天没有可撤销的提交记录"), 404
    if u["existed"]:
        cur.execute("update daily_reports set anchor=?,leads=?,invite=?,arrive=?,tmr_invite=?,media=? where id=?",
                    (u["prev_anchor"], u["prev_leads"], u["prev_invite"], u["prev_arrive"], u["prev_tmr"], u["prev_media"], u["report_id"]))
        totals = {"leads": u["prev_leads"], "invite": u["prev_invite"],
                  "arrive": u["prev_arrive"], "tmr_invite": u["prev_tmr"]}
    else:
        cur.execute("delete from daily_reports where d=? and filler=?", (date, filler))
        totals = {"leads": 0, "invite": 0, "arrive": 0, "tmr_invite": 0}
    cur.execute("delete from daily_reports_undo where id=?", (u["id"],))
    c.commit(); c.close()
    return jsonify(ok=True, totals=totals, removed=not bool(u["existed"]))

@app.post("/report/list")
def report_list():
    d = request.get_json(force=True, silent=True) or {}
    g = admin_guard(d)
    if g: return g
    kind = d.get("kind")
    c = db()
    if kind == "live":
        rows = c.execute("select * from live_sessions order by id desc limit 500").fetchall()
    elif kind == "consult":
        rows = c.execute("select * from daily_reports order by id desc limit 500").fetchall()
    else:
        c.close(); return jsonify(err="类型错误"), 400
    c.close()
    out = []
    for x in rows:
        r = dict(x)
        if "media" in r:
            r["media"] = parse_media(r.get("media"))
        out.append(r)
    return jsonify(out)

@app.post("/report/mine")
def report_mine():
    """员工查看某个填报人名下的历史场次(自己的填报记录 + 可回看战报/海报)。
    员工共用一个密码,无法在服务端区分身份,故按传入姓名过滤;与本站既有信任模型一致。"""
    d = request.get_json(force=True, silent=True) or {}
    if not emp_ok(d): return jsonify(err="需员工或管理员密码"), 403
    who = clean(d.get("filler"), 40)
    if not who:
        return jsonify(err="请选择本人姓名后再查看记录"), 400
    lim = numi(d.get("limit")) or 200
    if lim < 1 or lim > 500: lim = 200
    kind = d.get("kind") or "live"
    c = db()
    if kind == "consult":
        # 咨询日报:填报人就是网咨本人
        if who:
            rows = c.execute(
                "select * from daily_reports where filler=? order by id desc limit ?",
                (who, lim)).fetchall()
        else:
            rows = c.execute(
                "select * from daily_reports order by id desc limit ?", (lim,)).fetchall()
    elif who:
        rows = c.execute(
            "select * from live_sessions where filler=? or zk=? order by id desc limit ?",
            (who, who, lim)).fetchall()
    else:
        rows = c.execute(
            "select * from live_sessions order by id desc limit ?", (lim,)).fetchall()
    c.close()
    out = []
    for x in rows:
        r = dict(x)
        if "media" in r:
            r["media"] = parse_media(r.get("media"))
        out.append(r)
    return jsonify(out)

@app.post("/anchor/mine")
def anchor_mine():
    """员工在「我的」页看自己的战绩与工作历史:主播/助播=GMV/客资/邀约到店;中控=自己控场的场次;
    投手=自己投流的消耗与产出;扣字=自己在场的场次;网资=自己日报的客资数据。
    每个岗位给 total/today/d7/d30 四档聚合(老板2026-07-27定:全员可看自己历史+出今日/7天/30天海报),
    另回 hist(仅本人相关场次的明细,最多30条)。信任模型同 /report/mine:员工共用密码按姓名过滤,不含别人数据。"""
    d = request.get_json(force=True, silent=True) or {}
    if not emp_ok(d): return jsonify(err="需员工或管理员密码"), 403
    who = norm_name(d.get("name"))
    if not who: return jsonify(err="缺姓名"), 400
    day = clean(d.get("d"), 20) or ""
    c = db()
    live = c.execute("select d,room,t1,t2,dur,gmv,cost,orders,anchor,assist,zk,kouzi,touliu from live_sessions order by d desc,id desc").fetchall()
    con = c.execute("select d,leads,invite,arrive,tmr_invite,anchor,filler from daily_reports order by d desc,id desc").fetchall()
    c.close()
    def agg(rows):
        return {"sessions": len(rows), "gmv": sum(x["gmv"] or 0 for x in rows),
                "cost": sum(x["cost"] or 0 for x in rows),
                "orders": sum(numi(x["orders"]) for x in rows),
                "dur": sum(numi(x["dur"]) for x in rows)}
    def czb(rows):
        return {"days": len(rows), "leads": sum(numi(x["leads"]) for x in rows),
                "invite": sum(numi(x["invite"]) for x in rows),
                "arrive": sum(numi(x["arrive"]) for x in rows)}
    an = [x for x in live if who in (x["anchor"], x["assist"])]
    zk = [x for x in live if x["zk"] == who]
    tl = [x for x in live if x["touliu"] == who]
    kz = [x for x in live if x["kouzi"] == who]
    conA = [x for x in con if norm_name(x["anchor"]) == who]   # 主播视角的客资(日报按主播归属)
    conF = [x for x in con if norm_name(x["filler"]) == who]   # 网资本人的日报
    out = {"anchor": {"total": agg(an)}, "zk": {"total": agg(zk)}, "touliu": {"total": agg(tl)},
           "kouzi": {"total": agg(kz)}, "wz": {"total": czb(conA)}, "wzself": {"total": czb(conF)}}
    if day:
        def dayset(n):
            try:
                t = datetime.date(*[int(x) for x in day.split("-")])
            except Exception:
                return None
            return set((t - datetime.timedelta(days=i)).isoformat() for i in range(n))
        s7 = dayset(7); s30 = dayset(30)
        for key, rows, fn in (("anchor", an, agg), ("zk", zk, agg), ("touliu", tl, agg),
                              ("kouzi", kz, agg), ("wz", conA, czb), ("wzself", conF, czb)):
            out[key]["today"] = fn([x for x in rows if x["d"] == day])
            if s7: out[key]["d7"] = fn([x for x in rows if x["d"] in s7])
            if s30: out[key]["d30"] = fn([x for x in rows if x["d"] in s30])
    def hrows(rows, n=30):
        return [{"d": x["d"], "room": x["room"] or "", "t1": x["t1"] or "", "t2": x["t2"] or "",
                 "dur": numi(x["dur"]), "anchor": x["anchor"] or "", "gmv": x["gmv"] or 0,
                 "cost": x["cost"] or 0, "orders": numi(x["orders"])} for x in rows[:n]]
    out["hist"] = {"anchor": hrows(an), "zk": hrows(zk), "touliu": hrows(tl), "kouzi": hrows(kz),
                   "wz": [{"d": x["d"], "leads": numi(x["leads"]), "invite": numi(x["invite"]),
                           "arrive": numi(x["arrive"]), "tmr": numi(x["tmr_invite"]),
                           "anchor": x["anchor"] or ""} for x in conF[:30]]}
    return jsonify(out)

@app.post("/report/today")
def report_today():
    d = request.get_json(force=True, silent=True) or {}
    if not emp_ok(d): return jsonify(err="需员工或管理员密码"), 403
    day = clean(d.get("d"), 20)
    if not day: return jsonify(err="缺日期"), 400
    # days: 统计区间天数(1=仅当天,7=近7天,30=近30天),终点为 d(营业日口径由前端减3小时)
    try:
        days = max(1, min(31, int(d.get("days") or 1)))
    except Exception:
        days = 1
    d0 = day
    if days > 1:
        try:
            t = datetime.date(*[int(x) for x in day.split("-")])
            d0 = (t - datetime.timedelta(days=days - 1)).isoformat()
        except Exception:
            return jsonify(err="日期格式错误"), 400
    # d0: 显式起始日(优先于 days)。用于"本月/全部"等非固定天数区间,前端算好传来。
    d0v = clean(d.get("d0"), 20)
    if d0v:
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", d0v) or d0v > day or d0v < "2020-01-01":
            return jsonify(err="起始日期不合法"), 400
        d0 = d0v
    c = db()
    live = c.execute("select room,cost,gmv,orders,ban,anchor,assist,zk,kouzi,consult,touliu from live_sessions where d>=? and d<=?", (d0, day)).fetchall()
    con = c.execute("select leads,invite,arrive,tmr_invite,filler,anchor from daily_reports where d>=? and d<=?", (d0, day)).fetchall()
    c.close()
    r1 = r2 = 0; cost = gmv = 0.0; orders = ban = 0
    for x in live:
        rm = x["room"] or ""
        if rm == "二号直播间": r2 += 1
        elif rm == "一号直播间": r1 += 1
        cost += x["cost"] or 0; gmv += x["gmv"] or 0; orders += numi(x["orders"])
        b = (x["ban"] or "").strip()
        if b and b not in ("无", "没有", "无。", "沒有") and "正常" not in b and "自然" not in b: ban += 1
    leads = invite = arrive = tmr = 0
    for x in con:
        leads += numi(x["leads"]); invite += numi(x["invite"]); arrive += numi(x["arrive"]); tmr += numi(x["tmr_invite"])
    roi = round(gmv / cost, 2) if cost else 0
    def _nm(v):
        v = (v or "").strip()
        return "" if (not v or v in ("无", "没有", "无。", "沒有", "-", "/")) else v
    lt = {"anchor": [], "assist": [], "zk": [], "kouzi": [], "consult": [], "touliu": []}
    for x in live:
        for k in lt:
            n = _nm(x[k])
            if n and n not in lt[k]: lt[k].append(n)
    ct = {"filler": [], "anchor": []}
    for x in con:
        for k in ct:
            n = _nm(x[k])
            if n and n not in ct[k]: ct[k].append(n)
    return jsonify(date=day, d0=d0, days=days,
                   live={"count": len(live), "r1": r1, "r2": r2, "cost": cost, "gmv": gmv, "orders": orders, "ban": ban, "roi": roi, "team": lt},
                   consult={"count": len(con), "leads": leads, "invite": invite, "arrive": arrive, "tmr": tmr, "team": ct})

@app.post("/rank/board")
def rank_board():
    """团队排行榜(老板2026-07-27要的):①主播业绩榜=live_sessions 按主播(anchor)聚 GMV;
    ②网资邀约榜=daily_reports 按填报人(filler)聚 客资/邀约/到店。
    emp_ok:管理员后台和员工「我的」页同步展示,全员可见(只有姓名+业绩数字,无薪酬无PII)。
    d=营业日终点(前端按凌晨3点分界减3小时算好传来),返回 today/d7/d30 三档。
    人名统一 norm_name(别名/空格归一);过滤 NOT_A_PERSON(填「无」等)和已删除人员(staff_hidden)。"""
    d = request.get_json(force=True, silent=True) or {}
    if not emp_ok(d): return jsonify(err="需员工或管理员密码"), 403
    day = clean(d.get("d"), 20)
    if not valid_date(day): return jsonify(err="缺日期或日期格式不对"), 400
    t = datetime.date(*[int(x) for x in day.split("-")])
    d7 = (t - datetime.timedelta(days=6)).isoformat()
    d30 = (t - datetime.timedelta(days=29)).isoformat()
    gone = hidden_names()
    c = db()
    live = c.execute("select d,anchor,gmv,orders from live_sessions where d>=? and d<=?", (d30, day)).fetchall()
    con = c.execute("select d,filler,leads,invite,arrive from daily_reports where d>=? and d<=?", (d30, day)).fetchall()
    c.close()
    def person_ok(nm):
        return nm and nm not in NOT_A_PERSON and nm not in gone
    def rank_anchor(rows):
        m = {}
        for x in rows:
            nm = norm_name(x["anchor"])
            if not person_ok(nm): continue
            r = m.setdefault(nm, {"name": nm, "gmv": 0.0, "sessions": 0, "orders": 0})
            r["gmv"] += x["gmv"] or 0; r["sessions"] += 1; r["orders"] += numi(x["orders"])
        return sorted(m.values(), key=lambda r: (-r["gmv"], -r["sessions"], r["name"]))
    def rank_wz(rows):
        m = {}
        for x in rows:
            nm = norm_name(x["filler"])
            if not person_ok(nm): continue
            r = m.setdefault(nm, {"name": nm, "leads": 0, "invite": 0, "arrive": 0, "days": 0})
            r["leads"] += numi(x["leads"]); r["invite"] += numi(x["invite"])
            r["arrive"] += numi(x["arrive"]); r["days"] += 1
        return sorted(m.values(), key=lambda r: (-r["invite"], -r["arrive"], -r["leads"], r["name"]))
    out = {}
    for key, dd in (("today", day), ("d7", d7), ("d30", d30)):
        out[key] = {"anchor": rank_anchor([x for x in live if x["d"] >= dd]),
                    "wz": rank_wz([x for x in con if x["d"] >= dd])}
    return jsonify(date=day, d7=d7, d30=d30, ranges=out)

@app.post("/report/del")
def report_del():
    d = request.get_json(force=True, silent=True) or {}
    g = admin_guard(d)
    if g: return g
    kind = d.get("kind"); idv = numi(d.get("id"))
    c = db()
    if kind == "live":
        c.execute("delete from live_sessions where id=?", (idv,))
    elif kind == "consult":
        c.execute("delete from daily_reports where id=?", (idv,))
    else:
        c.close(); return jsonify(err="类型错误"), 400
    c.commit(); c.close()
    return jsonify(ok=True)

@app.post("/morning")
def morning():
    """晨会一屏(仅管理员):今天谁排班 / 昨天排了班却没填场次 / 昨天网咨谁没交日报 / 考核待补课名单。
    排班↔填报按 天+直播间 对账:昨天该直播间排了 N 班,场次填报少于 N 条即视为缺填。"""
    d = request.get_json(force=True, silent=True) or {}
    g = admin_guard(d)
    if g: return g
    day = clean(d.get("d"), 20)
    if not valid_date(day): return jsonify(err="缺今天日期(YYYY-MM-DD)"), 400
    t = datetime.date(*[int(x) for x in day.split("-")])
    yday = (t - datetime.timedelta(days=1)).isoformat()
    # 每周日全员休息(与排班页 isSun 口径一致):休息日不催排班、不做排班对账。
    today_sun = t.weekday() == 6
    yday_sun = (t - datetime.timedelta(days=1)).weekday() == 6
    c = db()
    ts = [dict(x) for x in c.execute("select id,room,tslot,anchor,assist,zk,kouzi,touliu,wangzi from shifts where day=? order by id asc", (day,)).fetchall()]
    ys = [dict(x) for x in c.execute("select id,room,tslot,anchor,zk,wangzi from shifts where day=? order by id asc", (yday,)).fetchall()]
    quota = {}
    for x in c.execute("select room,count(*) n from live_sessions where d=? group by room", (yday,)).fetchall():
        quota[x["room"] or ""] = x["n"]
    y_live_cnt = sum(quota.values())
    miss = []
    for s in ys:
        rm = s.get("room") or ""
        if quota.get(rm, 0) > 0:
            quota[rm] -= 1
        else:
            miss.append({"room": rm or "未定直播间", "tslot": s.get("tslot") or "", "anchor": s.get("anchor") or "", "zk": s.get("zk") or ""})
    wz_filed = set(r[0] for r in c.execute("select distinct filler from daily_reports where d=?", (yday,)).fetchall())
    gone = hidden_names()
    wz_miss = sorted(set(s.get("wangzi") for s in ys if s.get("wangzi") and s.get("wangzi") not in NOT_A_PERSON) - wz_filed - gone)
    y_con_cnt = c.execute("select count(*) from daily_reports where d=?", (yday,)).fetchone()[0]
    t_live = c.execute("select count(*) from live_sessions where d=?", (day,)).fetchone()[0]
    t_con = c.execute("select count(*) from daily_reports where d=?", (day,)).fetchone()[0]
    rows = c.execute("select name,paper,max(score*100.0/total) best from quiz_results where total>0 group by name,paper").fetchall()
    c.close()
    buke = sorted([{"name": r["name"], "paper": r["paper"], "best": int(round(r["best"]))} for r in rows
                   if r["best"] < 60 and r["name"] not in gone], key=lambda x: x["best"])[:20]
    return jsonify(date=day, yday=yday, today_sun=today_sun, yday_sun=yday_sun,
                   today={"shifts": ts, "live_filled": t_live, "consult_filled": t_con},
                   ycheck={"shift_cnt": len(ys), "live_cnt": y_live_cnt, "consult_cnt": y_con_cnt,
                           "missing": miss, "wz_missing": wz_miss},
                   buke=buke)

# ---------- 直播间排班(按日期) ----------
@app.post("/staff/names")
def staff_names():
    d = request.get_json(force=True, silent=True) or {}
    if not emp_ok(d): return jsonify(err="需员工或管理员密码"), 403
    c = db(); rows = c.execute("select name,position from staff").fetchall(); c.close()
    gone = hidden_names()
    rows = [r for r in rows if r["name"] not in gone]
    dbpos = {}
    for r in rows:
        nm = r["name"]
        if nm and nm not in dbpos and (r["position"] or "").strip():
            dbpos[nm] = (r["position"] or "").strip()
    out = []; seen = set()
    for t in template_staff():
        nm = t["name"]
        if not nm or nm in seen or nm in gone: continue
        seen.add(nm)
        pos = dbpos.get(nm) or (t.get("position") or "")
        out.append({"name": nm, "position": pos, "roles": roles_of(pos)})
    for r in rows:
        nm = r["name"]
        if nm and nm not in seen:
            seen.add(nm); pos = (r["position"] or "").strip()
            out.append({"name": nm, "position": pos, "roles": roles_of(pos)})
    return jsonify(out)

@app.post("/staff/fill_defaults")
def staff_fill_defaults():
    # 填报页默认值:每个直播间最近一场的主播、每个主播最近一场的网资(跳过空/「无」)
    d = request.get_json(force=True, silent=True) or {}
    if not emp_ok(d): return jsonify(err="需员工或管理员密码"), 403
    c = db()
    ra = {}
    for r in c.execute("select room,anchor from live_sessions where ifnull(room,'')<>'' and ifnull(anchor,'')<>'' and anchor<>'无' order by d asc,id asc").fetchall():
        ra[r["room"]] = r["anchor"]
    aw = {}
    for r in c.execute("select anchor,consult from live_sessions where ifnull(anchor,'')<>'' and anchor<>'无' and ifnull(consult,'')<>'' and consult<>'无' order by d asc,id asc").fetchall():
        aw[r["anchor"]] = r["consult"]
    wa = {}
    for r in c.execute("select consult,anchor from live_sessions where ifnull(consult,'')<>'' and consult<>'无' and ifnull(anchor,'')<>'' and anchor<>'无' order by d asc,id asc").fetchall():
        wa[r["consult"]] = r["anchor"]
    c.close()
    # 固定搭配(老板定的),优先于历史数据:夏夏主播+网资一肩挑
    AW_FIXED = {"夏夏": "夏夏"}
    aw.update(AW_FIXED)
    for _a, _w in AW_FIXED.items():
        wa[_w] = _a
    # 扣字小助理固定一人(老板2026-07-26定);注意花名册另有网咨赵鑫杰/后台赵鑫奇,是不同的名字
    # role_defaults 给排班页用:key=岗位key,值=默认人(管理员=张导,小管家=叶淑媛,老板2026-07-26定)
    role_defaults = {}  # 徐州舟格固定岗位待确认
    return jsonify(room_anchor=ra, anchor_wangzi=aw, wangzi_anchor=wa, kouzi_default="赵鑫洁", role_defaults=role_defaults)

@app.post("/shift/list")
def shift_list():
    d = request.get_json(force=True, silent=True) or {}
    if not emp_ok(d): return jsonify(err="查看排班需员工或管理员密码"), 403
    month = clean(d.get("month"), 7)  # 可选 YYYY-MM
    c = db()
    if month:
        rows = c.execute("select id,day,room,tslot,anchor,assist,zk,kouzi,touliu,wangzi,extras from shifts where day like ? order by day asc,id asc", (month + "%",)).fetchall()
    else:
        rows = c.execute("select id,day,room,tslot,anchor,assist,zk,kouzi,touliu,wangzi,extras from shifts order by day asc,id asc limit 800").fetchall()
    c.close()
    out = []
    for x in rows:
        o = dict(x)
        # 自定义岗位(管理员/小管家等)存在 extras JSON 里,展开成普通键给前端
        try: o.update(json.loads(o.pop("extras") or "{}"))
        except Exception: o.pop("extras", None)
        out.append(o)
    return jsonify(out)

@app.post("/shift/save")
def shift_save():
    d = request.get_json(force=True, silent=True) or {}
    g = admin_guard(d)
    if g: return g
    day = clean(d.get("day"), 20)
    if not valid_date(day): return jsonify(err="日期格式不对"), 400
    _crs = _custom_roles()
    bad = reject_unknown_names(d, ("anchor", "assist", "zk", "kouzi", "touliu", "wangzi") + tuple(r["key"] for r in _crs),
                               labels={r["key"]: r["label"] for r in _crs})
    if bad: return bad
    extras = {}
    for r in _crs:
        v = norm_name(d.get(r["key"]))
        if v: extras[r["key"]] = v
    exj = json.dumps(extras, ensure_ascii=False) if extras else ""
    vals = (day, clean(d.get("room"),16), clean(d.get("tslot"),40), norm_name(d.get("anchor")), norm_name(d.get("assist")),
            norm_name(d.get("zk")), norm_name(d.get("kouzi")), norm_name(d.get("touliu")), norm_name(d.get("wangzi")), exj)
    c = db(); cur = c.cursor()
    if numi(d.get("id")) > 0:
        cur.execute("update shifts set day=?,room=?,tslot=?,anchor=?,assist=?,zk=?,kouzi=?,touliu=?,wangzi=?,extras=? where id=?", vals + (numi(d.get("id")),))
    else:
        cur.execute("insert into shifts(day,room,tslot,anchor,assist,zk,kouzi,touliu,wangzi,extras,sort,created) values(?,?,?,?,?,?,?,?,?,?,?,?)",
                    vals + (0, int(time.time())))
    c.commit(); c.close()
    return jsonify(ok=True)

@app.post("/shift/del")
def shift_del():
    d = request.get_json(force=True, silent=True) or {}
    g = admin_guard(d)
    if g: return g
    c = db(); c.execute("delete from shifts where id=?", (numi(d.get("id")),)); c.commit(); c.close()
    return jsonify(ok=True)

# ---------- 人员登记 ----------
def admin_req_ok(d):
    # 浏览器管理操作统一认服务端会话;本机巡检仍可用内部密钥。
    return admin_ok(d) is True

@app.post("/staff/add")
def staff_add():
    # 2026-07-27老板定:人员登记(名字/电话/岗位/入职时间/银行卡)只有管理员统一录入,员工不能自行填
    d = request.get_json(force=True, silent=True) or {}
    if not admin_req_ok(d): return jsonify(err="人员登记只有管理员能操作,请找管理员录入"), 403
    name = norm_name(d.get("name"))
    if not name:
        return jsonify(err="姓名必填"), 400
    ipv = ipaddr(); now = int(time.time())
    c0 = db(); c0.execute("delete from staff_hidden where name=?", (name,)); c0.commit(); c0.close()
    card = digits(clean(d.get("bank_card"), 40))
    if card and not (16 <= len(card) <= 19):
        return jsonify(err="银行卡号应为 16-19 位数字,请核对"), 400
    phone = clean(d.get("phone"), 20)
    position = clean(d.get("position"), 24)
    join_date = clean(d.get("join_date"), 20)
    note = clean(d.get("note"), 60)
    sal_raw = d.get("salary")
    sal_given = sal_raw not in (None, "")
    # 本接口已经过管理员会话校验,不再根据前端明文密码判定。
    is_admin = True
    salary = numf(sal_raw) if sal_given else 0.0
    c = db(); cur = c.cursor()
    r = cur.execute("select max(created) from staff where ip=?", (ipv,)).fetchone()
    if r and r[0] and now - r[0] < 4:
        c.close(); return jsonify(err="提交太快了,请稍等再试"), 429
    # 同名视为同一人:已登记过就合并进原记录(新填的非空字段覆盖,没填的保留原值),不新开一条
    ex = cur.execute("select id,phone,position,join_date,bank_card,salary,note from staff where name=? order by id asc limit 1", (name,)).fetchone()
    if ex:
        # 银行卡防篡改:原记录已有卡号且新提交是另一个卡号时,只有管理员能改,
        # 员工密码持有者保留原卡号(其余字段照常合并)。两种情况都记一条审计,只存后4位。
        old_card = (ex["bank_card"] or "").strip()
        card_kept = False
        if old_card and card and card != old_card:
            applied = 1 if is_admin else 0
            card_kept = applied == 0
            cur.execute("insert into staff_card_log(name,old4,new4,ip,ts,applied) values(?,?,?,?,?,?)",
                        (name, old_card[-4:], card[-4:], ipv, now, applied))
        new_card = old_card if card_kept else (card or old_card)
        # 手机号同样受保护:它是「我的工资」验身份用的后4位来源,被同事改掉等于把工资查询权让出去。
        # 员工只能补空字段,覆盖他人已填的手机/岗位/入职日期需要管理员。
        kept = []
        def merge(field, newv, oldv):
            oldv = (oldv or "").strip()
            if newv and oldv and newv != oldv and not is_admin:
                kept.append(field); return oldv
            return newv or oldv
        new_phone = merge("phone", phone, ex["phone"])
        new_pos = merge("position", position, ex["position"])
        new_join = merge("join_date", join_date, ex["join_date"])
        cur.execute("update staff set phone=?,position=?,join_date=?,bank_card=?,salary=?,note=? where id=?",
            (new_phone, new_pos, new_join,
             new_card, salary if sal_given else (ex["salary"] or 0),
             (note or ex["note"]), ex["id"]))
        c.commit(); c.close()
        out = {"ok": True, "merged": True}
        if card_kept: out["card_kept"] = True
        if kept: out["kept"] = kept
        return jsonify(**out)
    cur.execute("insert into staff(name,phone,position,join_date,bank_card,salary,note,ip,created) values(?,?,?,?,?,?,?,?,?)",
        (name, phone, position, join_date, card, salary, note, ipv, now)); c.commit(); c.close()
    return jsonify(ok=True)

ROLE_KW = [("anchor", ["主播"]), ("assist", ["助播", "出单脸"]), ("zk", ["中控"]),
           ("kouzi", ["后台", "扣字"]), ("touliu", ["投手", "投流"]),
           ("wangzi", ["网咨", "网资", "网管", "网络咨询"])]
# 顺序=排班表单/排班卡/岗位管理的展示顺序(老板2026-07-27定:主播→助播→网络咨询)
ROLE_META = [("anchor", "🎤 主播"), ("assist", "🤝 助播"), ("wangzi", "💬 网络咨询"),
             ("zk", "🎛 中控"), ("kouzi", "⌨️ 扣字小助理"), ("touliu", "📈 投手")]
_CR_CACHE = {"t": 0.0, "v": []}
def _custom_roles():
    """自定义岗位(老板2026-07-25要求可增加岗位)。5秒缓存,避免 org_list 循环里反复查库。"""
    now = time.time()
    if now - _CR_CACHE["t"] > 5:
        c = db(); cur = c.cursor()
        cur.execute("create table if not exists custom_roles(key text primary key,label text,kws text,created integer)")
        c.commit()
        rows = cur.execute("select key,label,kws from custom_roles order by created asc").fetchall(); c.close()
        out = []
        for r in rows:
            try: kws = json.loads(r["kws"] or "[]")
            except Exception: kws = []
            out.append({"key": r["key"], "label": r["label"], "kws": kws or [re.sub(r"^\S+\s", "", r["label"])]})
        _CR_CACHE["v"] = out; _CR_CACHE["t"] = now
    return _CR_CACHE["v"]

def all_role_kw():
    return ROLE_KW + [(r["key"], r["kws"]) for r in _custom_roles()]

def all_role_meta():
    return ROLE_META + [(r["key"], r["label"]) for r in _custom_roles()]

def roles_of(pos):
    pos = pos or ""
    return [k for k, kws in all_role_kw() if any(w in pos for w in kws)]

def hidden_names():
    # 返回值要与各处已归一化的姓名可比,否则带空格/别名写法的离职人员会漏过滤、提成照发。
    c = db(); rows = c.execute("select name from staff_hidden").fetchall(); c.close()
    return set(norm_name(r["name"]) for r in rows)

def roles_off():
    c = db(); rows = c.execute("select role from role_off").fetchall(); c.close()
    return set(r["role"] for r in rows)

def known_names():
    # 名单锁死(老板2026-07-27定):填报/排班里出现的名字必须已在名单里
    # (员工登记 staff 表 + 老板花名册,去掉 staff_hidden 的),新人只能由管理员先在人员登记录入。
    gone = hidden_names()
    s = set()
    c = db(); rows = c.execute("select name from staff").fetchall(); c.close()
    for r in rows:
        n = norm_name(r["name"])
        if n and n not in gone:
            s.add(n)
    try:
        for t in template_staff():
            n = norm_name(t.get("name"))
            if n and n not in gone:
                s.add(n)
    except Exception:
        pass  # 花名册读不了时至少还有 staff 表兜底,不能因 Excel 故障把全公司填报卡死
    return s

NAME_FIELD_LABEL = {"anchor": "主播", "assist": "助播", "zk": "中控", "kouzi": "扣字小助理",
                    "consult": "网络咨询", "wangzi": "网络咨询", "touliu": "投流", "filler": "填报人"}

def reject_unknown_names(d, fields, labels=None):
    # 返回 None=全部合法;否则返回可直接 return 的 (json, 400)。「无」和空值放行(没有此岗选「无」)。
    ok = known_names()
    lab = dict(NAME_FIELD_LABEL); lab.update(labels or {})
    bad = []
    for f in fields:
        v = norm_name(d.get(f))
        if v and v != "无" and v not in ok:
            bad.append("%s「%s」" % (lab.get(f, f), v))
    if bad:
        return jsonify(err="不能提交:%s 不在人员名单里。名单已锁定,填报/排班时不能新增人;新人请先让管理员在「人员登记」录入,录好后这里会自动出现。" % "、".join(bad),
                       unknown_names=bad), 400
    return None

def _cellstr(v):
    if v is None:
        return ""
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    return str(v).strip()

def template_staff():
    """读取私有花名册模板里已有的人员(老板的现有名单),与表单登记合并展示。"""
    try:
        import openpyxl
        wb = openpyxl.load_workbook("/opt/team13-board/private/base_renyuan.xlsx", data_only=True)
        ws = wb.worksheets[0]
        out = []
        for r in range(2, ws.max_row + 1):
            name = norm_name(_cellstr(ws.cell(r, 2).value))
            if not name or "示例" in name or name in ("真实姓名", "姓名", "本名"):
                continue
            try:
                sal = ws.cell(r, 14).value
                sal = float(sal) if sal not in (None, "") else 0
            except Exception:
                sal = 0
            out.append({"id": 0, "src": "花名册", "created": 0, "name": name,
                        "gender": _cellstr(ws.cell(r, 3).value),
                        "age": _cellstr(ws.cell(r, 4).value),
                        "position": _cellstr(ws.cell(r, 5).value),
                        "duty": _cellstr(ws.cell(r, 6).value),
                        "join_date": _cellstr(ws.cell(r, 7).value),
                        "phone": _cellstr(ws.cell(r, 8).value),
                        "idcard": _cellstr(ws.cell(r, 9).value),
                        "address": _cellstr(ws.cell(r, 10).value),
                        "emergency": _cellstr(ws.cell(r, 11).value),
                        "bank_branch": _cellstr(ws.cell(r, 12).value),
                        "bank_card": digits(_cellstr(ws.cell(r, 13).value)),
                        "salary": sal})
        wb.close()
        return out
    except Exception:
        return []

# ---------- 岗位与人员管理(管理员后台) ----------
# ---------- 业绩提成 ----------
# 两种计法(老板2026-07确认,从2026-07整月执行):
#   gmv  = 按直播间 GMV 的百分比,仅直播提成白名单内的人,数据来自场次填报 live_sessions
#   head = 按到店人头给固定金额,仅网络咨询,数据来自咨询日报 daily_reports 的「实际到店」
# 中控、扣字助理、投手及其他岗位仍保留岗位/排班/填报功能,但不参与业绩提成。
COMM_EFFECTIVE_MONTH = "2026-07"
# 直播提成白名单(老板2026-07-26定):拿直播 GMV 提成的只有萌萌、帆帆,都按 1%;
# 其他主播、助播一律没有(无论填在主播位还是助播位)。网络咨询到店提成不受此限。
COMM_LIVE_NAMES = ()  # 徐州舟格提成名单待确认
# 直播提成合并成一档:白名单的人不管站主播位还是助播位,都按「主播」一档累计,
# 一人一行(老板2026-07-26:同一个人别出现两次,累计加总就行)。
COMM_ROLES = [
    {"key": "anchor",  "label": "🎤 主播",       "mode": "gmv",  "src": "live",   "col": "anchor"},
    {"key": "wangzi",  "label": "💬 网络咨询",   "mode": "head", "src": "report", "col": "arrive"},
]
COMM_META = {r["key"]: r for r in COMM_ROLES}
# 比例:主播(含站助播位的场)1%、网络咨询30元/实际到店。
COMM_DEFAULT = {"anchor": [{"min": 0, "rate": 1.0}],
                "wangzi": [{"min": 0, "rate": 30.0}]}
NOT_A_PERSON = ("", "无", "未指定", "-", "—", "没有", "空", "新人")

def comm_exempt_names():
    """免提成名单:在名单上的人不参与任何提成(老板2026-07-26定,首批5位主播)。"""
    c = db(); rows = c.execute("select name from comm_exempt").fetchall(); c.close()
    return set(r["name"] for r in rows)

@app.post("/comm/exempt")
def comm_exempt_get():
    d = request.get_json(force=True, silent=True) or {}
    g = admin_guard(d)
    if g: return g
    return jsonify(names=sorted(comm_exempt_names()))

@app.post("/comm/exempt_save")
def comm_exempt_save():
    d = request.get_json(force=True, silent=True) or {}
    g = admin_guard(d)
    if g: return g
    names = d.get("names")
    if not isinstance(names, list): return jsonify(err="参数不对"), 400
    out = []
    for n in names[:100]:
        n = norm_name(clean(str(n), 24))
        if n and n not in NOT_A_PERSON and n not in out: out.append(n)
    c = db(); cur = c.cursor(); now = int(time.time())
    cur.execute("delete from comm_exempt")
    for n in out: cur.execute("insert into comm_exempt(name,added) values(?,?)", (n, now))
    known = set((r["name"] or "").strip() for r in c.execute("select name from staff").fetchall())
    c.commit(); c.close()
    return jsonify(ok=True, names=sorted(out), unknown=[n for n in out if n not in known])

def comm_rules():
    c = db(); rows = c.execute("select role,base,tiers from comm_rule").fetchall(); c.close()
    saved = {r["role"]: r for r in rows}
    out = []
    for meta in COMM_ROLES:
        k = meta["key"]
        if k in saved:
            try: tiers = json.loads(saved[k]["tiers"] or "[]")
            except Exception: tiers = []
            base = saved[k]["base"] or "month"
        else:
            tiers = COMM_DEFAULT.get(k, []); base = "month"
        tiers = [t for t in tiers if isinstance(t, dict)]
        tiers.sort(key=lambda t: numf(t.get("min")))
        out.append({"key": k, "label": meta["label"], "mode": meta["mode"],
                    "unit": "元/到店" if meta["mode"] == "head" else "%",
                    "base": base, "tiers": tiers})
    return out

def pick_rate(tiers, qty):
    rate = 0.0
    for t in tiers:
        if qty >= numf(t.get("min")): rate = numf(t.get("rate"))
    return rate

@app.post("/comm/rules")
def comm_rules_get():
    d = request.get_json(force=True, silent=True) or {}
    g = admin_guard(d)
    if g: return g
    return jsonify(comm_rules())

@app.post("/comm/rules_save")
def comm_rules_save():
    d = request.get_json(force=True, silent=True) or {}
    g = admin_guard(d)
    if g: return g
    rules = d.get("rules")
    if not isinstance(rules, list): return jsonify(err="参数不对"), 400
    for r in rules:
        if not isinstance(r, dict) or r.get("key") not in COMM_META:
            return jsonify(err="只有主播、助播、网络咨询可以设置业绩提成"), 400
    c = db(); cur = c.cursor(); now = int(time.time())
    for r in rules:
        mode = COMM_META[r["key"]]["mode"]
        base = "session" if r.get("base") == "session" else "month"
        tiers = []
        for t in (r.get("tiers") or [])[:8]:
            if not isinstance(t, dict): continue
            rt = numf(t.get("rate"))
            if rt < 0: return jsonify(err="不能填负数"), 400
            if mode == "gmv" and rt > 100: return jsonify(err="GMV 提成比例要在 0~100% 之间"), 400
            if mode == "head" and rt > 100000: return jsonify(err="单个到店奖励金额过大,请核对"), 400
            tiers.append({"min": max(0.0, numf(t.get("min"))), "rate": rt})
        tiers.sort(key=lambda x: x["min"])
        cur.execute("insert or replace into comm_rule(role,base,tiers,updated) values(?,?,?,?)",
                    (r["key"], base, json.dumps(tiers, ensure_ascii=False), now))
    c.commit(); c.close()
    return jsonify(ok=True)

@app.post("/comm/calc")
def comm_calc():
    d = request.get_json(force=True, silent=True) or {}
    g = admin_guard(d)
    if g: return g
    return jsonify(comm_compute(clean(d.get("month"), 7)))

def comm_compute(month):
    """按月算每个人的提成。'无'/空的岗位不算。"""
    like = (month + "%") if month else "%"
    c = db()
    live = c.execute("select d,room,anchor,assist,zk,kouzi,touliu,gmv from live_sessions where d like ? order by d asc,id asc", (like,)).fetchall()
    rep = c.execute("select d,filler,arrive,invite,leads from daily_reports where d like ? order by d asc,id asc", (like,)).fetchall()
    c.close()
    rules = {r["key"]: r for r in comm_rules()}
    gone = hidden_names()
    exempt = comm_exempt_names()
    _, staff_positions = salary_map()
    agg = {}; dropped = {}
    total_gmv = sum(numf(r["gmv"]) for r in live)
    total_arrive = sum(numi(r["arrive"]) for r in rep)

    def add(name, key, qty, row):
        if not name or name.strip() in NOT_A_PERSON or name.strip() in gone: return
        if norm_name(name) in exempt: return
        if not rules.get(key, {}).get("tiers"): return
        a = agg.setdefault((name.strip(), key), {"name": name.strip(), "role": key,
            "role_label": rules[key]["label"], "mode": rules[key]["mode"],
            "unit": rules[key]["unit"], "cnt": 0, "qty": 0.0, "rows": []})
        a["cnt"] += 1; a["qty"] += qty; a["rows"].append(row)

    for r in live:
        gmv = numf(r["gmv"])
        seen_live = set()
        for col in ("anchor", "assist"):
            nm = norm_name(r[col] or "")
            if nm not in COMM_LIVE_NAMES or nm in seen_live: continue
            seen_live.add(nm)
            add(nm, "anchor", gmv,
                {"d": r["d"], "what": (r["room"] or "直播间"), "qty": gmv})
    for r in rep:
        arv = numi(r["arrive"])
        if arv <= 0: continue
        name = norm_name(r["filler"] or "")
        # 防止借用网咨姓名/日报填报人字段给其他岗位误算到店提成。
        # 被这道门滤掉的人要记下来回给前端提示——否则岗位没登记"网咨"的人到店提成静默归零,没人发现。
        if "wangzi" not in roles_of(staff_positions.get(name, "")):
            if name and name.strip() not in NOT_A_PERSON and name not in gone and name not in exempt:
                dq = dropped.setdefault(name, {"name": name, "arrive": 0, "days": 0,
                                               "position": staff_positions.get(name, "")})
                dq["arrive"] += arv; dq["days"] += 1
            continue
        add(name, "wangzi", arv,
            {"d": r["d"], "what": "到店 " + str(arv) + " 人", "qty": arv})

    out = []
    for a in agg.values():
        rule = rules[a["role"]]; tiers = rule["tiers"]; per_session = (rule["base"] == "session")
        amt = 0.0
        if per_session:
            for row in a["rows"]:
                rt = pick_rate(tiers, row["qty"])
                row["rate"] = rt
                row["amount"] = round(row["qty"] * rt / 100.0, 2) if a["mode"] == "gmv" else round(row["qty"] * rt, 2)
                amt += row["amount"]
            rate_show = round(amt / a["qty"] * 100, 3) if (a["mode"] == "gmv" and a["qty"]) else (round(amt / a["qty"], 2) if a["qty"] else 0)
        else:
            rt = pick_rate(tiers, a["qty"]); rate_show = rt
            amt = round(a["qty"] * rt / 100.0, 2) if a["mode"] == "gmv" else round(a["qty"] * rt, 2)
            for row in a["rows"]:
                row["rate"] = rt
                row["amount"] = round(row["qty"] * rt / 100.0, 2) if a["mode"] == "gmv" else round(row["qty"] * rt, 2)
        a["rate"] = rate_show; a["amount"] = round(amt, 2); a["base"] = rule["base"]
        out.append(a)
    out.sort(key=lambda x: -x["amount"])
    by_role = {}
    for a in out:
        b = by_role.setdefault(a["role"], {"label": a["role_label"], "amount": 0.0, "people": 0})
        b["amount"] = round(b["amount"] + a["amount"], 2); b["people"] += 1
    return {"month": month, "effective_month": COMM_EFFECTIVE_MONTH, "exempt": sorted(exempt),
            "live_names": list(COMM_LIVE_NAMES),
            "sessions": len(live), "reports": len(rep),
            "total_gmv": round(total_gmv, 2), "total_arrive": total_arrive,
            "total_comm": round(sum(a["amount"] for a in out), 2),
            "people": out, "by_role": by_role,
            "dropped": sorted(dropped.values(), key=lambda x: -x["arrive"])}

def salary_map():
    """姓名 → 月底薪(DB管理员设的 > 花名册里的),已删除的人排除。"""
    c = db(); rows = c.execute("select name,salary,position from staff order by id asc").fetchall(); c.close()
    gone = hidden_names(); out = {}; pos = {}
    for t in template_staff():
        nm = t["name"]
        if not nm or nm in gone: continue
        out[nm] = numf(t.get("salary")); pos[nm] = t.get("position") or ""
    for r in rows:
        nm = r["name"]
        if not nm or nm in gone: continue
        # 管理员在名单看板设过的底薪无条件优先于花名册(用 max 会让"调低底薪"保存了却不生效)。
        if numf(r["salary"]) > 0 or nm not in out: out[nm] = numf(r["salary"])
        if (r["position"] or "").strip(): pos[nm] = (r["position"] or "").strip()
    return out, pos

MYPAY_TRIES = {}
def _mypay_throttled(ipv):
    now = time.time()
    a = [t for t in MYPAY_TRIES.get(ipv, []) if now - t < 600]
    MYPAY_TRIES[ipv] = a
    return len(a) >= 8

@app.post("/my/pay")
def my_pay():
    """员工查自己的底薪+提成+算法。员工密码之外,再验本人手机号(或身份证)后4位——
    全员共用密码、姓名自报,不加这道验证任何员工都能看别人工资。老板2026-07-25拍板要员工能看自己的。
    只返回本人数据;发薪总表仍走 PII_KEY。"""
    d = request.get_json(force=True, silent=True) or {}
    if not emp_ok(d): return jsonify(err="需员工或管理员密码"), 403
    ipv = ipaddr()
    if _mypay_throttled(ipv): return jsonify(err="尝试太多次,10分钟后再试"), 429
    name = norm_name(clean(d.get("name"), 24))
    tail = str(d.get("tail4") or "").strip().lower().replace(" ", "")[-4:]
    if not name or len(tail) < 4: return jsonify(err="缺姓名或后4位"), 400
    tails = set(); found = False
    for t in template_staff():
        if norm_name(t["name"]) != name: continue
        found = True
        for v in (t.get("phone"), t.get("idcard")):
            v = str(v or "").strip().lower().replace(" ", "")
            if len(v) >= 4: tails.add(v[-4:])
            dv = digits(v)
            if len(dv) >= 4: tails.add(dv[-4:])
    c = db(); rows = c.execute("select phone,position from staff where name=?", (name,)).fetchall(); c.close()
    pos_db = ""
    for r in rows:
        found = True
        v = digits(str(r["phone"] or ""))
        if len(v) >= 4: tails.add(v[-4:])
        if (r["position"] or "").strip(): pos_db = r["position"].strip()
    if not found: return jsonify(err="花名册里没找到「%s」" % name), 404
    if not tails: return jsonify(err="花名册里没有你的手机号/身份证,请先去人员登记补录,或找统筹"), 400
    if tail not in tails:
        MYPAY_TRIES.setdefault(ipv, []).append(time.time())
        return jsonify(err="后4位对不上,请输入本人登记的手机号(或身份证)后4位"), 403
    month = clean(d.get("month"), 7)
    if not re.match(r"^\d{4}-\d{2}$", month or ""):
        month = (datetime.datetime.now() - datetime.timedelta(hours=3)).strftime("%Y-%m")
    sal, pos = salary_map()
    my_pos = pos.get(name) or pos_db
    # 该月已锁定 -> 读快照。员工看到的必须和老板锁定时发的那份一模一样,
    # 否则之后改了提成规则,员工页和实发工资对不上,又是一轮扯皮。
    srow, sdet, srule = pay_snapshot_person(month, name)
    locked_at = numi(srow["locked_at"]) if srow is not None else 0
    if srow is not None:
        mine = []
        for a in (sdet.get("items") or []):
            b = dict(a); b["rows"] = (b.get("rows") or [])[-31:]
            mine.append(b)
        my_salary = round(numf(srow["salary"]), 2)
        my_comm = round(numf(srow["comm_total"]), 2)
        my_pos = (srow["position"] or "") or my_pos
        rule_src = (srule or {}).get("rules") or comm_rules()
    else:
        locked_rules = pay_snapshot_rules(month)
        if locked_rules is not None:
            # 本月已锁定但快照里没有这个人(锁定时既没底薪也没提成)
            mine = []; my_salary = 0.0; my_comm = 0.0; rule_src = locked_rules
            locked_at = pay_lock_ts(month)
        else:
            comm = comm_compute(month)
            mine = []
            for a in comm["people"]:
                if norm_name(a["name"]) != name: continue
                b = dict(a); b["rows"] = (b.get("rows") or [])[-31:]
                mine.append(b)
            my_salary = round(sal.get(name, 0.0), 2)
            my_comm = round(sum(a["amount"] for a in mine), 2)
            rule_src = comm_rules()
    keys = set(roles_of(my_pos)) | set(a["role"] for a in mine)
    rules = [{"key": r["key"], "label": r["label"], "mode": r["mode"], "unit": r["unit"],
              "base": r["base"], "tiers": r["tiers"]} for r in rule_src
             if r["key"] in keys and r.get("tiers")]
    c = db()
    prow = c.execute("select paid_amount,paid_at,note from pay_payment_record where month=? and name=?", (month, name)).fetchone()
    c.close()
    paid_amount = round(numf(prow["paid_amount"]) if prow else 0.0, 2)
    my_total = round(my_salary + my_comm, 2)
    return jsonify(name=name, month=month, position=my_pos,
                   salary=my_salary,
                   locked=bool(locked_at), locked_at=locked_at, locked_at_text=_ts_text(locked_at),
                   locked_note=(_lock_note(locked_at) if locked_at else "本月工资还没锁定,数字可能随填报和规则变化"),
                   commission_eligible=(("wangzi" in roles_of(my_pos)) or (name in COMM_LIVE_NAMES)) and name not in comm_exempt_names(),
                   comm_exempt=(name in comm_exempt_names()),
                   comm_total=my_comm,
                   total=my_total, paid_amount=paid_amount,
                   remaining=round(max(0.0, my_total - paid_amount), 2),
                   overpaid=round(max(0.0, paid_amount - my_total), 2),
                   paid_at=(numi(prow["paid_at"]) if prow else 0),
                   payment_note=((prow["note"] or "") if prow else ""),
                   items=mine, rules=rules)

# ---------- 发薪总表 + 按月锁定(快照) ----------
# 为什么要快照:comm_rule 没有月份维度,改一次提成比例,历史月份的发薪表会跟着一起变。
# 老板九月把主播提成改成 2%,再打开七月表数字就跟当时实发的对不上了。
# 锁定 = 把"发这个月工资那一刻的计算结果 + 当时的规则"整月落库,之后该月只读快照。

def pay_rows_live(month):
    """实时算发薪总表(不读快照)。返回 (rows, comm)。
    comm_compute 里的免提成名单/离职/白名单/网咨岗位门都已生效,这里拿到的就是最终结果。"""
    comm = comm_compute(month)
    sal, pos = salary_map()
    rows = {}
    for nm, v in sal.items():
        rows[nm] = {"name": nm, "position": pos.get(nm, ""), "salary": round(v, 2),
                    "comm": 0.0, "detail": [], "total": 0.0}
    for p in comm["people"]:
        nm = p["name"]
        r = rows.setdefault(nm, {"name": nm, "position": pos.get(nm, ""), "salary": 0.0,
                                 "comm": 0.0, "detail": [], "total": 0.0})
        r["comm"] = round(r["comm"] + p["amount"], 2)
        r["detail"].append({"role": p["role_label"], "qty": p["qty"], "unit": p["unit"],
                            "rate": p["rate"], "cnt": p["cnt"], "amount": p["amount"]})
    out = []
    for r in rows.values():
        r["total"] = round(r["salary"] + r["comm"], 2)
        if r["salary"] > 0 or r["comm"] > 0: out.append(r)
    out.sort(key=lambda x: -x["total"])
    return out, comm

def _ts_text(ts):
    try:
        return datetime.datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return ""

def _lock_note(ts):
    try:
        t = datetime.datetime.fromtimestamp(int(ts))
        return "本月发薪表已于 %d月%d日 %02d:%02d 锁定,数字不再随提成规则变化" % (t.month, t.day, t.hour, t.minute)
    except Exception:
        return "本月发薪表已锁定"

def pay_snapshot_read(month):
    """读该月快照。返回 (rows, meta, locked_at, locked_by_ip);没锁定返回 (None,None,0,'')"""
    c = db()
    srows = c.execute("select * from pay_snapshot where month=? order by total desc,name asc", (month,)).fetchall()
    c.close()
    if not srows:
        return None, None, 0, ""
    out = []; meta = {}; locked_at = 0; by_ip = ""
    for r in srows:
        try: det = json.loads(r["detail_json"] or "{}")
        except Exception: det = {}
        if not meta:
            try: meta = (json.loads(r["rule_json"] or "{}") or {}).get("meta") or {}
            except Exception: meta = {}
        locked_at = max(locked_at, numi(r["locked_at"]))
        by_ip = by_ip or (r["locked_by_ip"] or "")
        out.append({"name": r["name"], "position": r["position"] or "",
                    "salary": round(numf(r["salary"]), 2), "comm": round(numf(r["comm_total"]), 2),
                    "total": round(numf(r["total"]), 2), "detail": det.get("detail") or []})
    return out, meta, locked_at, by_ip

def pay_lock_ts(month):
    """该月锁定时间戳;没锁定返回 0。"""
    c = db()
    r = c.execute("select max(locked_at) from pay_snapshot where month=?", (month,)).fetchone()
    c.close()
    return numi(r[0]) if r and r[0] else 0

def pay_snapshot_person(month, name):
    """快照里某个人的那一行(name 传归一化后的姓名)。返回 (row, detail, rule) 或 (None,None,None)。"""
    c = db()
    rows = c.execute("select * from pay_snapshot where month=?", (month,)).fetchall()
    c.close()
    for r in rows:
        if norm_name(r["name"]) != name: continue
        try: det = json.loads(r["detail_json"] or "{}")
        except Exception: det = {}
        try: rj = json.loads(r["rule_json"] or "{}")
        except Exception: rj = {}
        return r, (det if isinstance(det, dict) else {}), (rj if isinstance(rj, dict) else {})
    return None, None, None

def pay_snapshot_rules(month):
    """该月锁定时的提成规则(锁定后员工/老板看到的算法说明要用当时那份)。"""
    c = db()
    r = c.execute("select rule_json from pay_snapshot where month=? limit 1", (month,)).fetchone()
    c.close()
    if not r: return None
    try: return (json.loads(r["rule_json"] or "{}") or {}).get("rules")
    except Exception: return None

def pay_payment_apply(month, rows):
    """把付款台账合并到应发行，同时保留“有付款但不在当月应发名单”的异常记录。"""
    c = db()
    prows = c.execute("select name,paid_amount,paid_at,note,source from pay_payment_record where month=? order by name", (month,)).fetchall()
    c.close()
    pmap = {}
    for p in prows:
        pmap[norm_name(p["name"] or "")] = dict(p)
    out = []
    applied = 0.0; remaining = 0.0; overpaid = 0.0
    for src in rows:
        r = dict(src)
        p = pmap.pop(norm_name(r.get("name") or ""), None)
        paid = round(numf(p.get("paid_amount")) if p else 0.0, 2)
        total = round(numf(r.get("total")), 2)
        r["paid_amount"] = paid
        r["remaining"] = round(max(0.0, total - paid), 2)
        r["overpaid"] = round(max(0.0, paid - total), 2)
        r["payment_note"] = (p.get("note") or "") if p else ""
        r["payment_source"] = (p.get("source") or "") if p else ""
        r["paid_at"] = numi(p.get("paid_at")) if p else 0
        applied += min(total, paid); remaining += r["remaining"]; overpaid += r["overpaid"]
        out.append(r)
    extras = []
    for p in pmap.values():
        extras.append({"name": p.get("name") or "", "paid_amount": round(numf(p.get("paid_amount")), 2),
                       "paid_at": numi(p.get("paid_at")), "note": p.get("note") or "", "source": p.get("source") or ""})
    return out, extras, {"sum_paid_applied": round(applied, 2),
                         "sum_paid_recorded": round(sum(numf(p["paid_amount"]) for p in prows), 2),
                         "sum_remaining": round(remaining, 2), "sum_overpaid": round(overpaid, 2)}

@app.post("/pay/table")
def pay_table():
    """发薪总表:底薪 + 当月提成 = 应发合计。含薪资,走名单专用密码。
    该月已锁定 -> 读快照(locked:true);未锁定 -> 实时算(locked:false,数字会随规则变)。"""
    d = request.get_json(force=True, silent=True) or {}
    g = pii_guard(d)
    if g: return g
    month = clean(d.get("month"), 7)
    snap, meta, locked_at, _ = pay_snapshot_read(month)
    if snap is not None:
        out, payment_extras, payment_meta = pay_payment_apply(month, snap)
        return jsonify({"month": month, "rows": out, "locked": True,
                        "locked_at": locked_at, "locked_at_text": _ts_text(locked_at),
                        "locked_note": _lock_note(locked_at),
                        "sum_salary": round(sum(r["salary"] for r in out), 2),
                        "sum_comm": round(sum(r["comm"] for r in out), 2),
                        "sum_total": round(sum(r["total"] for r in out), 2),
                        "sessions": meta.get("sessions", 0), "total_gmv": meta.get("total_gmv", 0),
                        "total_arrive": meta.get("total_arrive", 0), "people": len(out),
                        "payments_extra": payment_extras, **payment_meta})
    out, comm = pay_rows_live(month)
    out, payment_extras, payment_meta = pay_payment_apply(month, out)
    return jsonify({"month": month, "rows": out, "locked": False,
                    "locked_at": 0, "locked_at_text": "",
                    "locked_note": "本月未锁定:提成规则改动会直接改变这里的数字,发薪前请点「锁定本月」存档",
                    "sum_salary": round(sum(r["salary"] for r in out), 2),
                    "sum_comm": round(sum(r["comm"] for r in out), 2),
                    "sum_total": round(sum(r["total"] for r in out), 2),
                    "sessions": comm["sessions"], "total_gmv": comm["total_gmv"],
                    "total_arrive": comm["total_arrive"], "people": len(out),
                    "payments_extra": payment_extras, **payment_meta})

@app.post("/pay/lock")
def pay_lock():
    """把某月发薪总表的当前计算结果落成快照。已锁定要带 force:true 才覆盖(旧快照进归档表)。"""
    d = request.get_json(force=True, silent=True) or {}
    g = admin_guard(d)
    if g: return g
    month = clean(d.get("month"), 7)
    if not re.match(r"^\d{4}-\d{2}$", month or ""):
        return jsonify(err="月份格式不对(应 2026-07)"), 400
    now = int(time.time())
    c = db(); cur = c.cursor()
    old = cur.execute("select count(*),max(locked_at) from pay_snapshot where month=?", (month,)).fetchone()
    if old and old[0]:
        if not (d.get("force") is True or d.get("force") == 1 or str(d.get("force")).lower() == "true"):
            c.close()
            return jsonify(err="%s 已经锁定过了(%s,共 %d 人)。要用现在的数字覆盖,请带 force:true 重发;旧快照会存进归档表。" % (
                               month, _ts_text(old[1]), old[0]),
                           locked=True, locked_at=numi(old[1]), locked_at_text=_ts_text(old[1]),
                           need_force=True, people=old[0]), 409
        cur.execute("insert into pay_snapshot_arch(month,name,position,salary,comm_total,total,detail_json,rule_json,locked_at,locked_by_ip,archived_at) "
                    "select month,name,position,salary,comm_total,total,detail_json,rule_json,locked_at,locked_by_ip,? from pay_snapshot where month=?", (now, month))
        cur.execute("delete from pay_snapshot where month=?", (month,))
    c.commit(); c.close()
    # 计算放在事务外:comm_compute/salary_map 自己开连接,避免长事务占着写锁
    rows, comm = pay_rows_live(month)
    items_by_name = {}
    for p in comm["people"]:
        b = dict(p); b["rows"] = (b.get("rows") or [])[-62:]
        items_by_name.setdefault(p["name"], []).append(b)
    meta = {"sessions": comm["sessions"], "reports": comm["reports"],
            "total_gmv": comm["total_gmv"], "total_arrive": comm["total_arrive"],
            "total_comm": comm["total_comm"], "exempt": comm["exempt"],
            "live_names": comm["live_names"], "effective_month": comm["effective_month"]}
    rule_json = json.dumps({"rules": comm_rules(), "meta": meta}, ensure_ascii=False)
    ipv = ipaddr()
    c = db(); cur = c.cursor()
    for r in rows:
        det = json.dumps({"detail": r["detail"], "items": items_by_name.get(r["name"], [])}, ensure_ascii=False)
        cur.execute("insert into pay_snapshot(month,name,position,salary,comm_total,total,detail_json,rule_json,locked_at,locked_by_ip) values(?,?,?,?,?,?,?,?,?,?)",
                    (month, r["name"], r["position"], r["salary"], r["comm"], r["total"], det, rule_json, now, ipv))
    c.commit(); c.close()
    # 不回传每个人的底薪(锁定只认管理员密码,薪资明细仍走 PII 密码的 /pay/table)
    return jsonify(ok=True, month=month, locked=True, locked_at=now, locked_at_text=_ts_text(now),
                   locked_note=_lock_note(now), people=len(rows),
                   names=[r["name"] for r in rows],
                   sum_comm=round(sum(r["comm"] for r in rows), 2),
                   sum_total=round(sum(r["total"] for r in rows), 2),
                   overwrote=bool(old and old[0]))

@app.post("/pay/unlock")
def pay_unlock():
    """解锁某月:快照进归档表,该月回到实时计算(改错了重来用)。"""
    d = request.get_json(force=True, silent=True) or {}
    g = admin_guard(d)
    if g: return g
    month = clean(d.get("month"), 7)
    if not re.match(r"^\d{4}-\d{2}$", month or ""):
        return jsonify(err="月份格式不对(应 2026-07)"), 400
    now = int(time.time())
    c = db(); cur = c.cursor()
    n = cur.execute("select count(*) from pay_snapshot where month=?", (month,)).fetchone()[0]
    if not n:
        c.close(); return jsonify(err="%s 本来就没有锁定" % month, locked=False), 400
    cur.execute("insert into pay_snapshot_arch(month,name,position,salary,comm_total,total,detail_json,rule_json,locked_at,locked_by_ip,archived_at) "
                "select month,name,position,salary,comm_total,total,detail_json,rule_json,locked_at,locked_by_ip,? from pay_snapshot where month=?", (now, month))
    cur.execute("delete from pay_snapshot where month=?", (month,))
    c.commit(); c.close()
    return jsonify(ok=True, month=month, locked=False, removed=n,
                   locked_note="已解锁:%s 恢复实时计算,数字会随提成规则变化" % month)

@app.post("/pay/locks")
def pay_locks():
    """已锁定的月份列表(前端做月份下拉时标记哪些月已锁)。"""
    d = request.get_json(force=True, silent=True) or {}
    g = admin_guard(d)
    if g: return g
    c = db()
    rows = c.execute("select month,count(*) n,max(locked_at) t from pay_snapshot group by month order by month desc").fetchall()
    c.close()
    return jsonify(months=[{"month": r["month"], "people": r["n"], "locked_at": numi(r["t"]),
                            "locked_at_text": _ts_text(r["t"])} for r in rows])

@app.post("/org/role_add")
def org_role_add():
    """新增自定义岗位。识别关键词默认=岗位名(position 含该词即归入此岗)。
    注意:排班表列和提成规则是固定的,自定义岗位不会出现在那两处。"""
    d = request.get_json(force=True, silent=True) or {}
    g = admin_guard(d)
    if g: return g
    label = clean(d.get("label"), 20)
    if not label: return jsonify(err="岗位名称必填"), 400
    plain = re.sub(r"[\U0001F000-\U0001FAFF\u2600-\u27BF]", "", label).strip()
    if not plain: return jsonify(err="岗位名称不能只有表情"), 400
    kws = d.get("kws")
    if isinstance(kws, str): kws = [x.strip() for x in re.split(r"[,,、/\s]+", kws) if x.strip()]
    if not isinstance(kws, list) or not kws: kws = [plain]
    kws = [clean(str(x), 12) for x in kws[:6] if clean(str(x), 12)]
    for k, lb in all_role_meta():
        if re.sub(r"^\S+\s", "", lb) == plain: return jsonify(err="已有同名岗位"), 400
    for k, ex in all_role_kw():
        if set(ex) & set(kws): return jsonify(err="关键词与现有岗位「%s」重叠" % dict(all_role_meta())[k]), 400
    show = label if label != plain else ("🧩 " + plain)
    key = "c%d" % int(time.time())
    c = db(); c.execute("insert into custom_roles(key,label,kws,created) values(?,?,?,?)",
        (key, show, json.dumps(kws, ensure_ascii=False), int(time.time()))); c.commit(); c.close()
    _CR_CACHE["t"] = 0
    return jsonify(ok=True, key=key)

@app.post("/org/role_drop")
def org_role_drop():
    """彻底删除一个自定义岗位(内置岗位只能用 role_off 停用)。"""
    d = request.get_json(force=True, silent=True) or {}
    g = admin_guard(d)
    if g: return g
    role = clean(d.get("role"), 16)
    if not role.startswith("c") or role in [k for k, _ in ROLE_META]:
        return jsonify(err="内置岗位不能彻底删除,请用停用"), 400
    c = db(); cur = c.cursor()
    cur.execute("delete from custom_roles where key=?", (role,))
    cur.execute("delete from role_off where role=?", (role,))
    c.commit(); c.close()
    _CR_CACHE["t"] = 0
    return jsonify(ok=True)

@app.post("/org/staff_add")
def org_staff_add():
    """管理员直接添人(不用等员工自己登记)。同名合并;若此前被删除,自动恢复。"""
    d = request.get_json(force=True, silent=True) or {}
    g = admin_guard(d)
    if g: return g
    name = norm_name(clean(d.get("name"), 24))
    if not name: return jsonify(err="姓名必填"), 400
    position = clean(d.get("position"), 40)
    phone = digits(clean(d.get("phone"), 20))[:11]
    join_date = clean(d.get("join_date"), 12)
    note = clean(d.get("note"), 60)
    try: salary = float(d.get("salary") or 0)
    except Exception: salary = 0
    if salary < 0 or salary > 1000000: return jsonify(err="底薪数字不对"), 400
    now = int(time.time())
    c = db(); cur = c.cursor()
    cur.execute("delete from staff_hidden where name=?", (name,))
    ex = cur.execute("select id,phone,position,join_date,salary,note from staff where name=? order by id asc limit 1", (name,)).fetchone()
    if ex:
        cur.execute("update staff set phone=?,position=?,join_date=?,salary=?,note=? where id=?",
            (phone or ex["phone"], position or ex["position"], join_date or ex["join_date"],
             salary or ex["salary"] or 0, note or ex["note"], ex["id"]))
    else:
        cur.execute("insert into staff(name,phone,position,join_date,salary,note,ip,created) values(?,?,?,?,?,?,?,?)",
            (name, phone, position, join_date, salary, note, ipaddr(), now))
    c.commit(); c.close()
    return jsonify(ok=True, merged=bool(ex))

@app.post("/org/roles")
def org_roles():
    """排班页用:只返回还在用的岗位(被删除的岗位不出现)。"""
    d = request.get_json(force=True, silent=True) or {}
    if not emp_ok(d): return jsonify(err="需员工或管理员密码"), 403
    off = roles_off()
    return jsonify([{"key": k, "label": lb} for k, lb in all_role_meta() if k not in off])

@app.post("/org/list")
def org_list():
    """管理页用:每个岗位下挂的人 + 未归岗 + 已删除(可恢复)。不含任何敏感字段。"""
    d = request.get_json(force=True, silent=True) or {}
    g = admin_guard(d)
    if g: return g
    c = db()
    dbrows = c.execute("select id,name,position from staff order by id desc").fetchall()
    hid = [dict(r) for r in c.execute("select name,created from staff_hidden order by created desc").fetchall()]
    c.close()
    off = roles_off(); gone = set(h["name"] for h in hid)
    people = {}   # name -> {name, position, id(可删的DB行), src}
    for t in template_staff():
        nm = t["name"]
        if nm and nm not in people:
            people[nm] = {"name": nm, "position": t.get("position") or "", "id": 0, "src": "花名册"}
    for r in dbrows:
        nm = r["name"]
        if not nm: continue
        if nm in people:
            if r["position"]: people[nm]["position"] = r["position"]
            people[nm]["id"] = people[nm]["id"] or r["id"]
            people[nm]["src"] = "花名册+登记"
        else:
            people[nm] = {"name": nm, "position": r["position"] or "", "id": r["id"], "src": "登记"}
    alive = [p for p in people.values() if p["name"] not in gone]
    roles = []
    builtin = set(k for k, _ in ROLE_META)
    for k, lb in all_role_meta():
        mem = [p for p in alive if k in roles_of(p["position"])]
        roles.append({"key": k, "label": lb, "off": 1 if k in off else 0,
                      "custom": 0 if k in builtin else 1,
                      "count": len(mem), "people": mem})
    nofit = [p for p in alive if not roles_of(p["position"])]
    return jsonify({"roles": roles, "nofit": nofit, "hidden": hid, "total": len(alive)})

@app.post("/org/role_off")
def org_role_off():
    """删除/恢复一个岗位。岗位一删,排班表里就不再出现这一栏(历史排班数据保留,恢复后原样回来)。"""
    d = request.get_json(force=True, silent=True) or {}
    g = admin_guard(d)
    if g: return g
    role = clean(d.get("role"), 16)
    if role not in [k for k, _ in all_role_meta()]: return jsonify(err="没有这个岗位"), 400
    c = db(); cur = c.cursor()
    if numi(d.get("off")):
        cur.execute("insert or replace into role_off(role,created) values(?,?)", (role, int(time.time())))
    else:
        cur.execute("delete from role_off where role=?", (role,))
    c.commit(); c.close()
    return jsonify(ok=True)

@app.post("/org/staff_del")
def org_staff_del():
    """删除一个人:DB登记行直接删,花名册(Excel)里的人进黑名单,两边都不再出现。"""
    d = request.get_json(force=True, silent=True) or {}
    g = admin_guard(d)
    if g: return g
    name = norm_name(clean(d.get("name"), 24))
    if not name: return jsonify(err="姓名必填"), 400
    c = db(); cur = c.cursor()
    # 只打"已删除"标记,不动 staff 行 → 恢复时电话/银行卡/薪资原样回来
    cur.execute("insert or replace into staff_hidden(name,created) values(?,?)", (name, int(time.time())))
    c.commit(); c.close()
    return jsonify(ok=True)

@app.post("/org/staff_restore")
def org_staff_restore():
    d = request.get_json(force=True, silent=True) or {}
    g = admin_guard(d)
    if g: return g
    name = norm_name(clean(d.get("name"), 24))
    c = db(); c.execute("delete from staff_hidden where name=?", (name,)); c.commit(); c.close()
    return jsonify(ok=True)

@app.post("/org/staff_unrole")
def org_staff_unrole():
    """只把某人从某个岗位移出(去掉 position 里对应的关键词),其他岗位保留。"""
    d = request.get_json(force=True, silent=True) or {}
    g = admin_guard(d)
    if g: return g
    name = norm_name(clean(d.get("name"), 24)); role = clean(d.get("role"), 16)
    kws = dict(all_role_kw()).get(role)
    if not name or not kws: return jsonify(err="参数不对"), 400
    c = db(); cur = c.cursor()
    ex = cur.execute("select id,position from staff where name=? order by id asc limit 1", (name,)).fetchone()
    pos = (ex["position"] if ex else "") or ""
    if not pos:
        for t in template_staff():
            if t["name"] == name: pos = t.get("position") or ""
    parts = [x for x in re.split(r"[/、,,\s]+", pos) if x]
    keep = [x for x in parts if not any(w in x for w in kws)]
    newpos = "/".join(keep)
    if ex:
        cur.execute("update staff set position=? where id=?", (newpos, ex["id"]))
    else:
        cur.execute("insert into staff(name,position,ip,created) values(?,?,?,?)", (name, newpos, ipaddr(), int(time.time())))
    c.commit(); c.close()
    return jsonify(ok=True, position=newpos)

@app.post("/org/staff_role")
def org_staff_role():
    """把某人调到某个岗位(改 position 文本,决定他能被排哪些岗)。"""
    d = request.get_json(force=True, silent=True) or {}
    g = admin_guard(d)
    if g: return g
    name = norm_name(clean(d.get("name"), 24)); pos = clean(d.get("position"), 24)
    if not name: return jsonify(err="姓名必填"), 400
    c = db(); cur = c.cursor()
    ex = cur.execute("select id from staff where name=? order by id asc limit 1", (name,)).fetchone()
    if ex:
        cur.execute("update staff set position=? where id=?", (pos, ex["id"]))
    else:
        cur.execute("insert into staff(name,position,ip,created) values(?,?,?,?)", (name, pos, ipaddr(), int(time.time())))
    c.commit(); c.close()
    return jsonify(ok=True)

@app.post("/staff/list")
def staff_list():
    d = request.get_json(force=True, silent=True) or {}
    g = pii_guard(d)
    if g: return g
    c = db(); rows = c.execute("select id,name,phone,position,join_date,bank_card,salary,note,created from staff order by id desc limit 500").fetchall(); c.close()
    gone = hidden_names()
    rows = [x for x in rows if x["name"] not in gone]
    # DB 按姓名去重(id desc,取最新一条)
    dbmap = {}
    for x in rows:
        r = dict(x); r["src"] = "登记"
        if r["name"] not in dbmap:
            dbmap[r["name"]] = r
    out = []; seen = set()
    for t in template_staff():
        nm = t["name"]
        if nm in gone: continue
        seen.add(nm)
        if nm in dbmap:
            dbr = dbmap[nm]
            for k in ("phone", "position", "join_date", "bank_card", "note"):
                if dbr.get(k): t[k] = dbr[k]
            if (dbr.get("salary") or 0) > 0: t["salary"] = dbr["salary"]
            t["id"] = dbr["id"]; t["src"] = "花名册+登记"
        out.append(t)
    for nm, dbr in dbmap.items():
        if nm not in seen:
            out.append(dbr)
    return jsonify(out)

@app.post("/staff/salary")
def staff_salary():
    d = request.get_json(force=True, silent=True) or {}
    g = pii_guard(d)
    if g: return g
    idv = numi(d.get("id")); name = norm_name(clean(d.get("name"), 24)); sal = numf(d.get("salary"))
    c = db(); cur = c.cursor()
    if idv > 0:
        cur.execute("update staff set salary=? where id=?", (sal, idv))
    elif name:
        ex = cur.execute("select id from staff where name=?", (name,)).fetchone()
        if ex:
            cur.execute("update staff set salary=? where id=?", (sal, ex["id"]))
        else:
            cur.execute("insert into staff(name,salary,ip,created) values(?,?,?,?)", (name, sal, ipaddr(), int(time.time())))
    else:
        c.close(); return jsonify(err="缺少姓名或id"), 400
    c.commit(); c.close()
    return jsonify(ok=True)

@app.post("/staff/del")
def staff_del():
    d = request.get_json(force=True, silent=True) or {}
    g = pii_guard(d)
    if g: return g
    c = db(); cur = c.cursor(); idv = numi(d.get("id"))
    r = cur.execute("select name from staff where id=?", (idv,)).fetchone()
    if r and r["name"]:
        cur.execute("insert or replace into staff_hidden(name,created) values(?,?)", (r["name"], int(time.time())))
    cur.execute("delete from staff where id=?", (idv,)); c.commit(); c.close()
    return jsonify(ok=True)

@app.post("/staff/xlsx")
def staff_xlsx():
    d = request.get_json(force=True, silent=True) or {}
    g = pii_guard(d)
    if g: return g
    import openpyxl, io, urllib.parse
    TMPL = "/opt/team13-board/private/base_renyuan.xlsx"
    wb = openpyxl.load_workbook(TMPL)
    ws = wb.worksheets[0]
    # 岗位→职责对照
    resp = {}
    if len(wb.worksheets) > 1:
        w2 = wb.worksheets[1]
        for r in range(2, w2.max_row + 1):
            p = w2.cell(r, 1).value
            if p not in (None, ""):
                resp[str(p).strip()] = w2.cell(r, 2).value
    # 找最后有数据的行 + 最大序号
    last, lastno = 1, 0
    for r in range(2, ws.max_row + 1):
        v1 = ws.cell(r, 1).value; v2 = ws.cell(r, 2).value; v6 = ws.cell(r, 6).value
        if isinstance(v1, (int, float)) or (v2 not in (None, "")) or (v6 not in (None, "")):
            last = r
            if isinstance(v1, (int, float)):
                lastno = int(v1)
    # 追加表单登记:①要带 salary(否则月底薪列永远空);②排除已离职;③花名册里已有的人不重复追加。
    c = db(); rows = c.execute("select name,phone,position,join_date,bank_card,salary from staff order by id asc").fetchall(); c.close()
    gone = hidden_names()
    in_tpl = set()
    for r in range(2, ws.max_row + 1):
        v2 = ws.cell(r, 2).value
        if v2 not in (None, ""): in_tpl.add(norm_name(str(v2)))
    rr = last + 1; no = lastno
    for s in rows:
        nm = norm_name(s["name"] or "")
        if not nm or nm in gone or nm in in_tpl: continue
        in_tpl.add(nm)
        no += 1
        ws.cell(rr, 1).value = no
        ws.cell(rr, 2).value = s["name"]
        ws.cell(rr, 5).value = s["position"]
        pj = resp.get((s["position"] or "").strip())
        if pj:
            ws.cell(rr, 6).value = pj
        ws.cell(rr, 7).value = s["join_date"]
        ws.cell(rr, 8).value = s["phone"]
        try:
            if s["salary"]: ws.cell(rr, 14).value = s["salary"]
        except Exception: pass
        if s["bank_card"]:
            ws.cell(rr, 12).value = "中国银行"
            ws.cell(rr, 13).value = s["bank_card"]
        rr += 1
    bio = io.BytesIO(); wb.save(bio); bio.seek(0)
    fn = urllib.parse.quote("人员登记表_发薪信息.xlsx")
    return Response(bio.read(), mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition": "attachment; filename*=UTF-8''" + fn})

# ---------- 每日健康巡检(只读) ----------
def biz_now():
    """营业日口径的"现在":凌晨3点前算前一天(团队干到凌晨3点)。"""
    return datetime.datetime.now() - datetime.timedelta(hours=3)

@app.post("/selfcheck")
def selfcheck():
    """巡检脚本用的只读体检接口:填报量、提成、锁定状态、脏数据计数、各表行数。
    只做 SELECT,不写任何业务表。字段全英文、结构扁平,方便脚本 diff 前一天的结果。"""
    d = request.get_json(force=True, silent=True) or {}
    g = admin_guard(d)
    if g: return g
    bn = biz_now()
    today = bn.strftime("%Y-%m-%d")
    yday = (bn - datetime.timedelta(days=1)).strftime("%Y-%m-%d")
    month = clean(d.get("month"), 7)
    if not re.match(r"^\d{4}-\d{2}$", month or ""):
        month = bn.strftime("%Y-%m")
    c = db()
    def one(sql, args=()):
        r = c.execute(sql, args).fetchone()
        return numi(r[0]) if r and r[0] is not None else 0
    out = {}
    # generated_at 是营业日口径(已减3小时),真实墙上时间看 wall_clock/generated_ts
    out["generated_at"] = bn.strftime("%Y-%m-%d %H:%M:%S")
    out["wall_clock"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    out["generated_ts"] = int(time.time())
    out["biz_date"] = today
    out["biz_date_prev"] = yday
    out["month"] = month
    # 填报量
    out["live_today"] = one("select count(*) from live_sessions where d=?", (today,))
    out["live_yesterday"] = one("select count(*) from live_sessions where d=?", (yday,))
    out["live_month"] = one("select count(*) from live_sessions where d like ?", (month + "%",))
    out["reports_today"] = one("select count(*) from daily_reports where d=?", (today,))
    out["reports_yesterday"] = one("select count(*) from daily_reports where d=?", (yday,))
    out["reports_month"] = one("select count(*) from daily_reports where d like ?", (month + "%",))
    out["shifts_total"] = one("select count(*) from shifts")
    out["shifts_today"] = one("select count(*) from shifts where ifnull(day,'')=?", (today,))
    # 人员
    out["staff_total"] = one("select count(*) from staff")
    out["staff_hidden"] = one("select count(*) from staff_hidden")
    out["comm_exempt_count"] = one("select count(*) from comm_exempt")
    out["comm_rule_rows"] = one("select count(*) from comm_rule")
    # 人员资料完整性:只检查当前有效人员,不回传手机号或银行卡号本身。
    hidden = hidden_names()
    active_staff = [r for r in c.execute("select name,phone,bank_card from staff").fetchall()
                    if norm_name(r["name"] or "") and norm_name(r["name"] or "") not in hidden]
    out["staff_active"] = len(active_staff)
    out["staff_missing_phone_names"] = sorted(set(
        norm_name(r["name"] or "") for r in active_staff if not (r["phone"] or "").strip()))
    out["staff_missing_bank_card_names"] = sorted(set(
        norm_name(r["name"] or "") for r in active_staff if not digits(r["bank_card"] or "")))
    out["staff_missing_phone"] = len(out["staff_missing_phone_names"])
    out["staff_missing_bank_card"] = len(out["staff_missing_bank_card_names"])
    out["comm_rule_source"] = "database" if out["comm_rule_rows"] else "code_default"

    # 历史工资快照不改写,但核对时要认已确认别名,避免把同一人误报8为“未匹配”。
    known = known_names()
    # 历史工资与历史排班允许匹配已离职/已隐藏人员；隐藏名单是状态记录，不等于“从未登记”。
    # 当前填报仍继续使用 known_names() 的有效名单约束，不因此放开离职人员提交权限。
    known_historical = known | hidden_names()
    pay_unmatched = []
    for r in c.execute("select name from pay_snapshot where month=? order by name", (month,)).fetchall():
        raw = (r["name"] or "").strip()
        if raw and norm_name(raw) not in known_historical:
            pay_unmatched.append(raw)
    out["pay_unmatched_staff_names"] = sorted(set(pay_unmatched))
    out["pay_unmatched_staff"] = len(out["pay_unmatched_staff_names"])

    # 排班的中控/后台字段可以用“/”组合多人,巡检时拆开后再与花名册比较。
    shift_unknown = set()
    for r in c.execute("select anchor,assist,zk,kouzi,touliu,wangzi from shifts").fetchall():
        for col in ("anchor", "assist", "zk", "kouzi", "touliu", "wangzi"):
            for raw in re.split(r"[/、,，+＋]+", r[col] or ""):
                name = norm_name(raw)
                if name and name not in NOT_A_PERSON and name not in known_historical:
                    shift_unknown.add(name)
    out["shift_unmatched_staff_names"] = sorted(shift_unknown)
    out["shift_unmatched_staff"] = len(out["shift_unmatched_staff_names"])
    # 脏数据:同场同人重复(归一化后)
    dup_ids = []; dup_aa_ids = []
    for r in c.execute("select id,anchor,assist,zk,kouzi,touliu,consult from live_sessions").fetchall():
        seen = {}
        for k, _lb in LIVE_POS_LABEL:
            nm = norm_name(r[k] or "")
            if not nm or nm in NOT_A_PERSON: continue
            if nm in seen:
                if r["id"] not in dup_ids: dup_ids.append(r["id"])
                if set((seen[nm], k)) == set(("anchor", "assist")) and r["id"] not in dup_aa_ids:
                    dup_aa_ids.append(r["id"])
                continue
            seen[nm] = k
    out["dirty_dup_person_sessions"] = len(dup_ids)
    out["dirty_dup_person_ids"] = dup_ids[:50]
    # 主播+助播同人 = 真会多算提成的那一类,单独计数
    out["dirty_dup_anchor_assist"] = len(dup_aa_ids)
    out["dirty_dup_anchor_assist_ids"] = dup_aa_ids[:50]
    over = c.execute("select id from daily_reports where ifnull(arrive,0) > ifnull(invite,0)").fetchall()
    out["dirty_arrive_gt_invite"] = len(over)
    out["dirty_arrive_gt_invite_ids"] = [r["id"] for r in over][:50]
    out["dirty_zero_gmv_sessions"] = one("select count(*) from live_sessions where ifnull(gmv,0)=0")
    out["dirty_zero_gmv_sessions_month"] = one("select count(*) from live_sessions where ifnull(gmv,0)=0 and d like ?", (month + "%",))
    out["dirty_report_no_anchor"] = one("select count(*) from daily_reports where ifnull(trim(anchor),'')=''")
    out["dirty_report_no_anchor_month"] = one("select count(*) from daily_reports where ifnull(trim(anchor),'')='' and d like ?", (month + "%",))
    # 各表行数
    tables = {}
    for t in ("live_sessions", "daily_reports", "shifts", "staff", "staff_hidden", "comm_rule",
              "comm_exempt", "role_off", "messages", "topics", "replies", "materials",
              "quiz_results", "staff_card_log", "pay_snapshot", "pay_snapshot_arch", "pay_payment_record"):
        try: tables[t] = one("select count(*) from %s" % t)
        except Exception: tables[t] = -1
    out["tables"] = tables
    out["pay_snapshot_rows"] = one("select count(*) from pay_snapshot where month=?", (month,))
    out["pay_snapshot_months"] = [r[0] for r in c.execute("select distinct month from pay_snapshot order by month desc").fetchall()]
    out["pay_payment_rows"] = one("select count(*) from pay_payment_record where month=?", (month,))
    pr = c.execute("select coalesce(sum(paid_amount),0) from pay_payment_record where month=?", (month,)).fetchone()
    out["pay_paid_recorded"] = round(numf(pr[0]) if pr else 0.0, 2)
    c.close()
    # 本月提成(与前一天对比可发现异常跳变)
    comm = comm_compute(month)
    out["comm_total"] = comm["total_comm"]
    out["comm_people_count"] = len(comm["people"])
    out["comm_people"] = [{"name": p["name"], "role": p["role"], "qty": p["qty"],
                           "amount": p["amount"]} for p in comm["people"]]
    out["comm_total_gmv"] = comm["total_gmv"]
    out["comm_total_arrive"] = comm["total_arrive"]
    out["comm_dropped_count"] = len(comm.get("dropped") or [])
    # 锁定状态
    lt = pay_lock_ts(month)
    out["pay_locked"] = bool(lt)
    out["pay_locked_at"] = lt
    out["pay_locked_at_text"] = _ts_text(lt)
    return jsonify(out)

# ---------- 徐州舟格电商运营日报 / 核账 / 8组看板 ----------
# 金额一律按“分”存整数。充值是资金流，和广告实际消耗分开；报销只改变付款状态，
# 不会再次进入成本。当前数据只能计算“阶段贡献利润”，不能称为公司净利润。
ECOM_RECHARGE_TYPES = ("广告充值", "报销充值", "其他充值")
ECOM_REIMBURSEMENT_STATES = ("待报销", "已报销", "无需报销", "已冲销")
ECOM_RECONCILE_STATES = ("pending", "confirmed", "rejected")

def _ecom_init():
    c = db(); cur = c.cursor()
    cur.execute("""create table if not exists ecom_daily_reports(
        id integer primary key autoincrement,
        biz_date text not null,
        group_no integer not null,
        reporter text not null default '',
        ad_spend_cents integer not null default 0,
        performance_cents integer not null default 0,
        note text not null default '',
        reconcile_status text not null default 'pending',
        reconcile_note text not null default '',
        reconciled_by text not null default '',
        reconciled_at integer not null default 0,
        ip text not null default '',
        created integer not null,
        updated integer not null,
        unique(biz_date, group_no),
        check(group_no between 1 and 8),
        check(ad_spend_cents >= 0),
        check(performance_cents >= 0)
    )""")
    cur.execute("""create table if not exists ecom_recharges(
        id integer primary key autoincrement,
        daily_id integer not null,
        recharge_type text not null,
        amount_cents integer not null default 0,
        note text not null default '',
        created integer not null,
        foreign key(daily_id) references ecom_daily_reports(id) on delete cascade,
        check(amount_cents >= 0)
    )""")
    cur.execute("""create table if not exists ecom_account_purchases(
        id integer primary key autoincrement,
        daily_id integer not null,
        account_name text not null,
        cost_cents integer not null default 0,
        voucher_url text not null,
        reimbursement_status text not null default '待报销',
        reimbursed_cents integer not null default 0,
        note text not null default '',
        created integer not null,
        foreign key(daily_id) references ecom_daily_reports(id) on delete cascade,
        check(cost_cents >= 0),
        check(reimbursed_cents >= 0)
    )""")
    cur.execute("""create table if not exists ecom_order_accounts(
        id integer primary key autoincrement,
        daily_id integer not null,
        account_name text not null,
        created integer not null,
        foreign key(daily_id) references ecom_daily_reports(id) on delete cascade
    )""")
    cur.execute("""create table if not exists ecom_audit_log(
        id integer primary key autoincrement,
        daily_id integer not null,
        action text not null,
        actor text not null default '',
        before_json text not null default '',
        after_json text not null default '',
        ip text not null default '',
        created integer not null
    )""")
    cur.execute("create index if not exists idx_ecom_daily_date_group on ecom_daily_reports(biz_date,group_no)")
    cur.execute("create index if not exists idx_ecom_daily_status on ecom_daily_reports(reconcile_status,biz_date)")
    cur.execute("create index if not exists idx_ecom_recharge_daily on ecom_recharges(daily_id)")
    cur.execute("create index if not exists idx_ecom_purchase_daily on ecom_account_purchases(daily_id)")
    cur.execute("create index if not exists idx_ecom_order_daily on ecom_order_accounts(daily_id)")
    c.commit(); c.close()

def _ecom_now_date():
    # 服务器/操作者可能不在中国时区，业务日期固定按北京时间。
    return (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=8)).date()

def _ecom_money_cents(value, field):
    if value is None or value == "":
        return 0
    try:
        d = Decimal(str(value).strip())
        if not d.is_finite() or d < 0:
            raise ValueError
        if d.as_tuple().exponent < -2:
            raise ValueError
        cents = int((d * 100).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
        if cents > 100000000000000:
            raise ValueError
        return cents
    except (InvalidOperation, ValueError, TypeError):
        raise ValueError("%s必须是非负金额，最多保留两位小数" % field)

def _ecom_yuan(cents):
    return float((Decimal(int(cents or 0)) / Decimal(100)).quantize(Decimal("0.01")))

def _v2_ratio(numerator_cents, denominator_cents):
    """财务看板统一用四舍五入（ROUND_HALF_UP），避免 Python round 的偶数舍入。"""
    denominator = int(denominator_cents or 0)
    if denominator <= 0:
        return None
    ratio = Decimal(int(numerator_cents or 0)) / Decimal(denominator)
    return float(ratio.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))

def _ecom_actor():
    role, name = _sess_parse(request.cookies.get("zb13sess", ""))
    if role == "admin":
        return name or "管理员"
    if role == "employee":
        return name or "员工"
    return "内部巡检"

def _ecom_safe_json(v):
    return json.dumps(v, ensure_ascii=False, separators=(",", ":"))

def _ecom_role_guard(d=None, admin=False):
    # V1组级日报已停用归档。员工端全部切换到V2员工级接口，旧接口只留管理员只读/回滚使用，
    # 防止员工绕过新页面直接请求旧API读取全公司或伪造组别。
    d = d or {}
    ok = admin_ok(d)
    if not ok:
        return jsonify(err="旧版组级接口已停用，仅管理员可访问"), 403
    return None

def _ecom_report_dict(c, report_id):
    r = c.execute("select * from ecom_daily_reports where id=?", (report_id,)).fetchone()
    if not r:
        return None
    recharges = c.execute("select id,recharge_type,amount_cents,note from ecom_recharges where daily_id=? order by id", (report_id,)).fetchall()
    purchases = c.execute("""select id,account_name,cost_cents,voucher_url,reimbursement_status,
        reimbursed_cents,note from ecom_account_purchases where daily_id=? order by id""", (report_id,)).fetchall()
    accounts = c.execute("select id,account_name from ecom_order_accounts where daily_id=? order by id", (report_id,)).fetchall()
    recharge_total = sum(int(x["amount_cents"] or 0) for x in recharges)
    account_cost = sum(int(x["cost_cents"] or 0) for x in purchases)
    reimbursed_total = sum(int(x["reimbursed_cents"] or 0) for x in purchases)
    pending_reimbursement = sum(max(0, int(x["cost_cents"] or 0) - int(x["reimbursed_cents"] or 0))
                                  for x in purchases if x["reimbursement_status"] == "待报销")
    contribution = int(r["performance_cents"] or 0) - int(r["ad_spend_cents"] or 0) - account_cost
    return {
        "id": r["id"], "biz_date": r["biz_date"], "group_no": r["group_no"],
        "group_name": "第%d组" % r["group_no"], "reporter": r["reporter"],
        "ad_spend": _ecom_yuan(r["ad_spend_cents"]),
        "performance": _ecom_yuan(r["performance_cents"]),
        "note": r["note"], "status": r["reconcile_status"],
        "reconcile_note": r["reconcile_note"], "reconciled_by": r["reconciled_by"],
        "reconciled_at": r["reconciled_at"], "created": r["created"], "updated": r["updated"],
        "recharges": [{"id": x["id"], "type": x["recharge_type"],
                       "amount": _ecom_yuan(x["amount_cents"]), "note": x["note"]} for x in recharges],
        "account_purchases": [{"id": x["id"], "account_name": x["account_name"],
            "cost": _ecom_yuan(x["cost_cents"]), "voucher_url": x["voucher_url"],
            "reimbursement_status": x["reimbursement_status"],
            "reimbursed": _ecom_yuan(x["reimbursed_cents"]), "note": x["note"]} for x in purchases],
        "order_accounts": [{"id": x["id"], "account_name": x["account_name"]} for x in accounts],
        "summary": {"recharge_total": _ecom_yuan(recharge_total),
            "account_cost": _ecom_yuan(account_cost), "reimbursed_total": _ecom_yuan(reimbursed_total),
            "pending_reimbursement": _ecom_yuan(pending_reimbursement),
            "order_account_count": len(set(x["account_name"] for x in accounts)),
            "contribution_profit": _ecom_yuan(contribution),
            "roi": (round(float(r["performance_cents"]) / float(r["ad_spend_cents"]), 2)
                    if int(r["ad_spend_cents"] or 0) > 0 else None)}
    }

def _ecom_validate_range(start, end):
    if not valid_date(start) or not valid_date(end):
        raise ValueError("日期格式应为 YYYY-MM-DD")
    if start > end:
        raise ValueError("开始日期不能晚于结束日期")
    try:
        ds = datetime.datetime.strptime(start, "%Y-%m-%d").date()
        de = datetime.datetime.strptime(end, "%Y-%m-%d").date()
        if (de - ds).days > 1095:
            raise ValueError("单次查询范围不能超过3年")
    except ValueError as exc:
        if str(exc) == "单次查询范围不能超过3年":
            raise
        raise ValueError("日期格式应为 YYYY-MM-DD")

@app.get("/ecom/report")
def ecom_report_get():
    guard = _ecom_role_guard()
    if guard: return guard
    day = clean(request.args.get("date"), 10)
    try: group_no = int(request.args.get("group", "0"))
    except Exception: group_no = 0
    if not valid_date(day) or group_no not in range(1, 9):
        return jsonify(err="请选择正确的业务日期和组别"), 400
    c = db(); r = c.execute("select id from ecom_daily_reports where biz_date=? and group_no=?", (day, group_no)).fetchone()
    out = _ecom_report_dict(c, r["id"]) if r else None
    c.close()
    return jsonify(report=out, group_name="第%d组" % group_no)

@app.post("/ecom/report/save")
def ecom_report_save():
    d = request.get_json(force=True, silent=True) or {}
    guard = _ecom_role_guard(d)
    if guard: return guard
    day = clean(d.get("biz_date"), 10)
    try: group_no = int(d.get("group_no"))
    except Exception: group_no = 0
    if not valid_date(day) or group_no not in range(1, 9):
        return jsonify(err="请选择正确的业务日期和组别"), 400
    try:
        ad_spend = _ecom_money_cents(d.get("ad_spend"), "广告实际消耗")
        performance = _ecom_money_cents(d.get("performance"), "上报业绩")
    except ValueError as exc:
        return jsonify(err=str(exc)), 400
    reporter = clean(d.get("reporter"), 30) or _ecom_actor()
    note = clean(d.get("note"), 500)
    recharges = d.get("recharges") or []
    purchases = d.get("account_purchases") or []
    order_accounts = d.get("order_accounts") or []
    if not isinstance(recharges, list) or not isinstance(purchases, list) or not isinstance(order_accounts, list):
        return jsonify(err="明细数据格式不正确"), 400
    if len(recharges) > 50 or len(purchases) > 50 or len(order_accounts) > 100:
        return jsonify(err="单张日报明细过多，请拆分后提交"), 400
    clean_recharges = []
    clean_purchases = []
    clean_accounts = []
    try:
        for i, x in enumerate(recharges):
            if not isinstance(x, dict): raise ValueError("充值明细格式不正确")
            typ = clean(x.get("type"), 12)
            if typ not in ECOM_RECHARGE_TYPES: raise ValueError("第%d条充值类型不正确" % (i + 1))
            amount = _ecom_money_cents(x.get("amount"), "第%d条充值金额" % (i + 1))
            if amount <= 0: raise ValueError("第%d条充值金额必须大于0" % (i + 1))
            clean_recharges.append((typ, amount, clean(x.get("note"), 200)))
        for i, x in enumerate(purchases):
            if not isinstance(x, dict): raise ValueError("买号明细格式不正确")
            name = clean(x.get("account_name"), 80)
            cost = _ecom_money_cents(x.get("cost"), "第%d条买号费用" % (i + 1))
            voucher = clean(x.get("voucher_url"), 500)
            state = clean(x.get("reimbursement_status"), 12) or "待报销"
            reimbursed = _ecom_money_cents(x.get("reimbursed"), "第%d条已报销金额" % (i + 1))
            if not name: raise ValueError("第%d条买号记录缺少账号名称" % (i + 1))
            if cost <= 0: raise ValueError("第%d条买号费用必须大于0" % (i + 1))
            if not VOUCHER_URL_RE.match(voucher):
                raise ValueError("第%d条买号记录必须上传付款凭证图片" % (i + 1))
            voucher_name = voucher.rsplit("/", 1)[-1]
            voucher_path = os.path.join(UPLOAD_DIR, voucher_name)
            if not os.path.isfile(voucher_path) or not sniff_image(voucher_path):
                raise ValueError("第%d条买号付款凭证不存在或图片格式无效，请重新上传" % (i + 1))
            if state not in ECOM_REIMBURSEMENT_STATES: raise ValueError("第%d条报销状态不正确" % (i + 1))
            if reimbursed > cost: raise ValueError("第%d条已报销金额不能大于买号费用" % (i + 1))
            if state == "已报销" and reimbursed != cost:
                raise ValueError("第%d条标记已报销时，已报销金额应等于买号费用" % (i + 1))
            clean_purchases.append((name, cost, voucher, state, reimbursed, clean(x.get("note"), 200)))
        seen = set()
        for i, x in enumerate(order_accounts):
            name = clean(x.get("account_name") if isinstance(x, dict) else x, 80)
            if not name: raise ValueError("第%d条出单账号名称不能为空" % (i + 1))
            key = unicodedata.normalize("NFKC", name).strip().lower()
            if key in seen: raise ValueError("出单账号“%s”重复，请合并后再提交" % name)
            seen.add(key); clean_accounts.append(name)
    except ValueError as exc:
        return jsonify(err=str(exc)), 400
    now = int(time.time()); c = db()
    try:
        c.execute("begin immediate")
        old = c.execute("select id,reconcile_status from ecom_daily_reports where biz_date=? and group_no=?", (day, group_no)).fetchone()
        before = _ecom_report_dict(c, old["id"]) if old else None
        role, _ = _sess_parse(request.cookies.get("zb13sess", ""))
        if old and old["reconcile_status"] == "confirmed" and role != "admin":
            c.rollback(); c.close()
            return jsonify(err="该日报已核账，需管理员退回后才能修改"), 409
        if old:
            rid = old["id"]
            c.execute("""update ecom_daily_reports set reporter=?,ad_spend_cents=?,performance_cents=?,note=?,
                reconcile_status='pending',reconcile_note='',reconciled_by='',reconciled_at=0,ip=?,updated=? where id=?""",
                (reporter, ad_spend, performance, note, ipaddr(), now, rid))
            c.execute("delete from ecom_recharges where daily_id=?", (rid,))
            c.execute("delete from ecom_account_purchases where daily_id=?", (rid,))
            c.execute("delete from ecom_order_accounts where daily_id=?", (rid,))
            action = "update"
        else:
            cur = c.execute("""insert into ecom_daily_reports(biz_date,group_no,reporter,ad_spend_cents,
                performance_cents,note,reconcile_status,ip,created,updated) values(?,?,?,?,?,?,'pending',?,?,?)""",
                (day, group_no, reporter, ad_spend, performance, note, ipaddr(), now, now))
            rid = cur.lastrowid; action = "create"
        for typ, amount, nt in clean_recharges:
            c.execute("insert into ecom_recharges(daily_id,recharge_type,amount_cents,note,created) values(?,?,?,?,?)",
                      (rid, typ, amount, nt, now))
        for name, cost, voucher, state, reimbursed, nt in clean_purchases:
            c.execute("""insert into ecom_account_purchases(daily_id,account_name,cost_cents,voucher_url,
                reimbursement_status,reimbursed_cents,note,created) values(?,?,?,?,?,?,?,?)""",
                (rid, name, cost, voucher, state, reimbursed, nt, now))
        for name in clean_accounts:
            c.execute("insert into ecom_order_accounts(daily_id,account_name,created) values(?,?,?)", (rid, name, now))
        after = _ecom_report_dict(c, rid)
        c.execute("insert into ecom_audit_log(daily_id,action,actor,before_json,after_json,ip,created) values(?,?,?,?,?,?,?)",
                  (rid, action, _ecom_actor(), _ecom_safe_json(before), _ecom_safe_json(after), ipaddr(), now))
        c.commit(); c.close()
        return jsonify(ok=True, report=after, message="已保存并进入待核账")
    except sqlite3.IntegrityError:
        c.rollback(); c.close(); return jsonify(err="同一天同一组已存在日报，请刷新后重试"), 409
    except Exception:
        c.rollback(); c.close(); return jsonify(err="保存失败，请稍后重试"), 500

@app.post("/ecom/reconcile")
def ecom_reconcile():
    d = request.get_json(force=True, silent=True) or {}
    guard = _ecom_role_guard(d, admin=True)
    if guard: return guard
    try: rid = int(d.get("id"))
    except Exception: rid = 0
    state = clean(d.get("status"), 12)
    note = clean(d.get("note"), 500)
    if state not in ECOM_RECONCILE_STATES:
        return jsonify(err="核账状态不正确"), 400
    if state == "rejected" and not note:
        return jsonify(err="退回时必须填写原因"), 400
    now = int(time.time()); c = db()
    try:
        c.execute("begin immediate")
        before = _ecom_report_dict(c, rid)
        if not before:
            c.rollback(); c.close(); return jsonify(err="日报不存在"), 404
        actor = _ecom_actor()
        reconciled_at = now if state == "confirmed" else 0
        c.execute("""update ecom_daily_reports set reconcile_status=?,reconcile_note=?,reconciled_by=?,
            reconciled_at=?,updated=? where id=?""", (state, note, actor, reconciled_at, now, rid))
        after = _ecom_report_dict(c, rid)
        c.execute("insert into ecom_audit_log(daily_id,action,actor,before_json,after_json,ip,created) values(?,?,?,?,?,?,?)",
                  (rid, "reconcile_%s" % state, actor, _ecom_safe_json(before), _ecom_safe_json(after), ipaddr(), now))
        c.commit(); c.close(); return jsonify(ok=True, report=after)
    except Exception:
        c.rollback(); c.close(); return jsonify(err="核账失败，请稍后重试"), 500

@app.post("/ecom/report/delete")
def ecom_report_delete():
    d = request.get_json(force=True, silent=True) or {}
    guard = _ecom_role_guard(d, admin=True)
    if guard: return guard
    try: rid = int(d.get("id"))
    except Exception: rid = 0
    c = db(); now = int(time.time())
    try:
        c.execute("begin immediate")
        before = _ecom_report_dict(c, rid)
        if not before:
            c.rollback(); c.close(); return jsonify(err="日报不存在"), 404
        c.execute("delete from ecom_recharges where daily_id=?", (rid,))
        c.execute("delete from ecom_account_purchases where daily_id=?", (rid,))
        c.execute("delete from ecom_order_accounts where daily_id=?", (rid,))
        c.execute("delete from ecom_daily_reports where id=?", (rid,))
        c.execute("insert into ecom_audit_log(daily_id,action,actor,before_json,after_json,ip,created) values(?,?,?,?,?,?,?)",
                  (rid, "delete", _ecom_actor(), _ecom_safe_json(before), "", ipaddr(), now))
        c.commit(); c.close(); return jsonify(ok=True)
    except Exception:
        c.rollback(); c.close(); return jsonify(err="删除失败，请稍后重试"), 500

def _ecom_blank_summary(group_no=None):
    return {"group_no": group_no, "group_name": ("第%d组" % group_no if group_no else "公司合计"),
        "ad_spend_cents": 0, "performance_cents": 0, "recharge_cents": 0,
        "account_cost_cents": 0, "reimbursed_cents": 0, "pending_reimbursement_cents": 0,
        "order_account_keys": set(), "new_account_count": 0, "report_count": 0,
        "contribution_profit_cents": 0}

def _ecom_public_summary(x):
    return {"group_no": x["group_no"], "group_name": x["group_name"],
        "ad_spend": _ecom_yuan(x["ad_spend_cents"]), "performance": _ecom_yuan(x["performance_cents"]),
        "recharge_total": _ecom_yuan(x["recharge_cents"]), "account_cost": _ecom_yuan(x["account_cost_cents"]),
        "reimbursed_total": _ecom_yuan(x["reimbursed_cents"]),
        "pending_reimbursement": _ecom_yuan(x["pending_reimbursement_cents"]),
        "order_account_count": len(x["order_account_keys"]), "new_account_count": x["new_account_count"],
        "report_count": x["report_count"], "contribution_profit": _ecom_yuan(x["contribution_profit_cents"]),
        "roi": (round(float(x["performance_cents"]) / float(x["ad_spend_cents"]), 2)
                if x["ad_spend_cents"] > 0 else None)}

@app.get("/ecom/dashboard")
def ecom_dashboard():
    guard = _ecom_role_guard()
    if guard: return guard
    today = _ecom_now_date(); default_start = today.replace(day=1).isoformat(); default_end = today.isoformat()
    start = clean(request.args.get("start"), 10) or default_start
    end = clean(request.args.get("end"), 10) or default_end
    try: _ecom_validate_range(start, end)
    except ValueError as exc: return jsonify(err=str(exc)), 400
    c = db(); rows = c.execute("""select id from ecom_daily_reports where biz_date between ? and ?
        order by biz_date desc,group_no asc,id desc limit 4000""", (start, end)).fetchall()
    reports = [_ecom_report_dict(c, r["id"]) for r in rows]
    c.close()
    groups_all = {i: _ecom_blank_summary(i) for i in range(1, 9)}
    groups_confirmed = {i: _ecom_blank_summary(i) for i in range(1, 9)}
    company_all = _ecom_blank_summary(); company_confirmed = _ecom_blank_summary()
    def add(target, report):
        target["ad_spend_cents"] += int(round(report["ad_spend"] * 100))
        target["performance_cents"] += int(round(report["performance"] * 100))
        target["recharge_cents"] += int(round(report["summary"]["recharge_total"] * 100))
        target["account_cost_cents"] += int(round(report["summary"]["account_cost"] * 100))
        target["reimbursed_cents"] += int(round(report["summary"]["reimbursed_total"] * 100))
        target["pending_reimbursement_cents"] += int(round(report["summary"]["pending_reimbursement"] * 100))
        target["order_account_keys"].update(
            unicodedata.normalize("NFKC", x["account_name"]).strip().lower()
            for x in report["order_accounts"] if x["account_name"].strip())
        target["new_account_count"] += len(report["account_purchases"])
        target["report_count"] += 1
        target["contribution_profit_cents"] += int(round(report["summary"]["contribution_profit"] * 100))
    for r in reports:
        add(groups_all[r["group_no"]], r); add(company_all, r)
        if r["status"] == "confirmed":
            add(groups_confirmed[r["group_no"]], r); add(company_confirmed, r)
    status_counts = {s: sum(1 for r in reports if r["status"] == s) for s in ECOM_RECONCILE_STATES}
    return jsonify(ok=True, start=start, end=end,
        official={"company": _ecom_public_summary(company_confirmed),
                  "groups": [_ecom_public_summary(groups_confirmed[i]) for i in range(1, 9)]},
        submitted={"company": _ecom_public_summary(company_all),
                   "groups": [_ecom_public_summary(groups_all[i]) for i in range(1, 9)]},
        status_counts=status_counts, reports=reports,
        definitions={
            "ad_spend": "已核账的广告实际消耗，不含充值",
            "performance": "当前为人工上报业绩，待确认是支付GMV、净GMV还是结算额",
            "contribution_profit": "阶段贡献利润 = 上报业绩 - 广告实际消耗 - 买号费用；不等于公司净利润",
            "recharge": "充值是资金流，不计入广告消耗，也不重复扣减利润",
            "reimbursement": "报销只改变垫付款状态，不会再次计入成本"})

if SCHEMA_MIGRATION_MODE:
    _ecom_init()

# ---------- 徐州舟格电商运营 V2：员工绩效 / 分组权限 / 账号资产 ----------
V2_ACCOUNT_STATUSES = ("待运营", "运营中", "已出单", "受限", "封禁", "停用")

def _v2_normalize_key_part(value):
    """账号公司级查重键：NFKC + 小写 + 去所有空白。

    不把连字符、标点符号等强行删除，避免两个真实不同的账号被误合并。
    """
    text = unicodedata.normalize("NFKC", value or "").lower()
    text = "".join(ch for ch in text if unicodedata.category(ch) not in ("Cf", "Cc"))
    return re.sub(r"\s+", "", text)

def _v2_account_display(value, maximum, field):
    if not isinstance(value, str):
        raise ValueError("%s格式不正确" % field)
    text = unicodedata.normalize("NFKC", value)
    text = "".join(ch for ch in text if unicodedata.category(ch) not in ("Cf", "Cc")).strip()
    if len(text) > maximum:
        raise ValueError("%s不能超过%d个字符" % (field, maximum))
    return text

def _v2_account_key(name, platform):
    return (_v2_normalize_key_part(name), _v2_normalize_key_part(platform))

def _v2_init():
    c = db(); q = c.cursor()
    q.execute("""create table if not exists ecom_v2_schema_version(
        version integer primary key, applied_at integer not null, note text not null default '')""")
    q.execute("""create table if not exists ecom_v2_groups(
        group_no integer primary key, group_name text not null, created integer not null, updated integer not null,
        check(group_no between 1 and 8))""")
    q.execute("""create table if not exists ecom_v2_members(
        name text primary key, group_no integer not null, is_leader integer not null default 0,
        active integer not null default 1, password_hash text not null default '', auth_version integer not null default 1,
        created integer not null, updated integer not null,
        check(group_no between 1 and 8))""")
    ensure_cols(q, "ecom_v2_members", [("password_hash", "text not null default ''"),
                                         ("auth_version", "integer not null default 1")])
    q.execute("""create table if not exists ecom_v2_reports(
        id integer primary key autoincrement, biz_date text not null, group_no integer not null,
        employee_name text not null, gmv_cents integer not null default 0, refund_cents integer not null default 0,
        ad_spend_cents integer not null default 0,
        note text not null default '', reconcile_status text not null default 'pending',
        reconcile_note text not null default '', reconciled_by text not null default '', reconciled_at integer not null default 0,
        revision integer not null default 1, last_rejection_note text not null default '', resubmitted_at integer not null default 0,
        ip text not null default '', created integer not null, updated integer not null,
        unique(biz_date, employee_name), check(group_no between 1 and 8),
        check(gmv_cents >= 0), check(refund_cents >= 0), check(ad_spend_cents >= 0))""")
    ensure_cols(q, "ecom_v2_reports", [("refund_cents", "integer not null default 0"),
                                         ("revision", "integer not null default 1"),
                                         ("last_rejection_note", "text not null default ''"),
                                         ("resubmitted_at", "integer not null default 0")])
    q.execute("""create table if not exists ecom_v2_recharges(
        id integer primary key autoincrement, report_id integer not null, recharge_type text not null,
        amount_cents integer not null default 0, note text not null default '', created integer not null,
        check(amount_cents >= 0))""")
    q.execute("""create table if not exists ecom_v2_purchases(
        id integer primary key autoincrement, report_id integer not null, account_name text not null,
        platform text not null default '', account_key text not null default '', platform_key text not null default '',
        cost_cents integer not null default 0, voucher_url text not null,
        reimbursement_status text not null default '待报销', reimbursed_cents integer not null default 0,
        account_status text not null default '待运营', note text not null default '', active integer not null default 1,
        reimbursement_revision integer not null default 1, retired_at integer not null default 0,
        retired_reason text not null default '', created integer not null,
        check(cost_cents >= 0), check(reimbursed_cents >= 0))""")
    ensure_cols(q, "ecom_v2_purchases", [("account_key", "text not null default ''"),
                                           ("platform_key", "text not null default ''"),
                                           ("active", "integer not null default 1"),
                                           ("reimbursement_revision", "integer not null default 1"),
                                           ("retired_at", "integer not null default 0"),
                                           ("retired_reason", "text not null default ''")])
    q.execute("""create table if not exists ecom_v2_account_updates(
        id integer primary key autoincrement, report_id integer not null, account_name text not null,
        platform text not null default '', account_status text not null, note text not null default '',
        expected_account_revision integer not null default 0, created integer not null)""")
    ensure_cols(q, "ecom_v2_account_updates", [("expected_account_revision", "integer not null default 0")])
    q.execute("""create table if not exists ecom_v2_accounts(
        id integer primary key autoincrement, account_name text not null, platform text not null default '',
        account_key text not null default '', platform_key text not null default '',
        group_no integer not null, owner_name text not null, purchase_cost_cents integer not null default 0,
        purchase_date text not null default '', voucher_url text not null default '', account_status text not null default '待运营',
        note text not null default '', active integer not null default 1, revision integer not null default 1,
        created integer not null, updated integer not null,
        unique(account_name, platform, owner_name), check(group_no between 1 and 8), check(purchase_cost_cents >= 0))""")
    ensure_cols(q, "ecom_v2_accounts", [("account_key", "text not null default ''"),
                                          ("platform_key", "text not null default ''"),
                                          ("revision", "integer not null default 1")])
    q.execute("""create table if not exists ecom_v2_account_history(
        id integer primary key autoincrement, account_id integer not null, old_status text not null default '',
        new_status text not null, changed_by text not null default '', note text not null default '',
        report_id integer not null default 0, created integer not null)""")
    ensure_cols(q, "ecom_v2_account_history", [("report_id", "integer not null default 0")])
    q.execute("""create table if not exists ecom_v2_account_snapshots(
        report_id integer not null, account_name text not null, platform text not null default '',
        before_json text not null default '', history_cursor integer not null default 0,
        applied_revision integer not null default 0, created integer not null,
        unique(report_id,account_name,platform))""")
    ensure_cols(q, "ecom_v2_account_snapshots", [("history_cursor", "integer not null default 0"),
                                                    ("applied_revision", "integer not null default 0")])
    q.execute("""create table if not exists ecom_v2_revoked_sessions(
        token_hash text primary key, expires integer not null, created integer not null)""")
    q.execute("delete from ecom_v2_revoked_sessions where expires<=?", (int(time.time()),))
    q.execute("""create table if not exists ecom_v2_audit(
        id integer primary key autoincrement, report_id integer not null default 0, action text not null,
        actor text not null default '', before_json text not null default '', after_json text not null default '',
        ip text not null default '', created integer not null)""")
    q.execute("""create table if not exists ecom_v2_reimbursement_events(
        id integer primary key autoincrement, purchase_id integer not null, report_id integer not null,
        reimbursement_status text not null, amount_cents integer not null default 0,
        payment_ref text not null default '', note text not null default '', actor text not null default '',
        request_key text not null default '',
        ip text not null default '', created integer not null,
        check(amount_cents >= 0))""")
    ensure_cols(q, "ecom_v2_reimbursement_events", [("request_key", "text not null default ''")])
    q.execute("""create table if not exists ecom_v2_settlements(
        id integer primary key autoincrement, start_date text not null, end_date text not null,
        group_no integer not null default 0, version integer not null default 1,
        status text not null default 'closed', snapshot_json text not null, snapshot_hash text not null,
        close_note text not null default '', created_by text not null default '', created_at integer not null,
        reopened_by text not null default '', reopened_at integer not null default 0,
        reopen_reason text not null default '',
        unique(start_date,end_date,group_no,version), check(group_no between 0 and 8))""")
    now = int(time.time())
    for i in range(1, 9):
        q.execute("insert or ignore into ecom_v2_groups(group_no,group_name,created,updated) values(?,?,?,?)",
                  (i, "第%d组" % i, now, now))
    # 兼容已有数据：只回填空键，不改显示名、归属、成本或状态。
    for r in q.execute("""select id,account_name,platform from ecom_v2_purchases
        where account_key='' or (platform<>'' and platform_key='')""").fetchall():
        account_key, platform_key = _v2_account_key(r["account_name"], r["platform"])
        q.execute("update ecom_v2_purchases set account_key=?,platform_key=? where id=?",
                  (account_key, platform_key, r["id"]))
    for r in q.execute("""select id,account_name,platform from ecom_v2_accounts
        where account_key='' or (platform<>'' and platform_key='')""").fetchall():
        account_key, platform_key = _v2_account_key(r["account_name"], r["platform"])
        q.execute("update ecom_v2_accounts set account_key=?,platform_key=? where id=?",
                  (account_key, platform_key, r["id"]))
    q.execute("create index if not exists idx_v2_report_date_group on ecom_v2_reports(biz_date,group_no)")
    q.execute("create index if not exists idx_v2_report_employee on ecom_v2_reports(employee_name,biz_date)")
    q.execute("create index if not exists idx_v2_report_status on ecom_v2_reports(reconcile_status,biz_date)")
    q.execute("create index if not exists idx_v2_purchase_report on ecom_v2_purchases(report_id)")
    q.execute("create index if not exists idx_v2_recharge_report on ecom_v2_recharges(report_id)")
    q.execute("create index if not exists idx_v2_account_update_report on ecom_v2_account_updates(report_id)")
    # 旧版同名索引不含 active，必须在单进程迁移中重建才会真正升级。
    q.execute("drop index if exists idx_v2_purchase_normalized")
    q.execute("create index idx_v2_purchase_normalized on ecom_v2_purchases(account_key,platform_key,active,report_id)")
    q.execute("create index if not exists idx_v2_account_group_owner on ecom_v2_accounts(group_no,owner_name)")
    q.execute("create index if not exists idx_v2_account_normalized on ecom_v2_accounts(account_key,platform_key,active,id)")
    q.execute("create index if not exists idx_v2_reimbursement_purchase on ecom_v2_reimbursement_events(purchase_id,created)")
    q.execute("create index if not exists idx_v2_reimbursement_report on ecom_v2_reimbursement_events(report_id,created)")
    q.execute("create index if not exists idx_v2_reimbursement_event_purchase_report on ecom_v2_reimbursement_events(purchase_id,report_id)")
    q.execute("create index if not exists idx_v2_settlement_range on ecom_v2_settlements(status,start_date,end_date,group_no)")
    normalized_duplicate = q.execute("""select 1 from ecom_v2_accounts
        group by account_key,platform_key having count(*)>1 limit 1""").fetchone()
    if not normalized_duplicate:
        # 空库/无冲突库直接获得数据库级公司唯一保护；老库若存在
        # 规范化冲突则不强行合并，保证升级不中断，由业务人员后续核对。
        q.execute("""create unique index if not exists idx_v2_account_normalized_unique
            on ecom_v2_accounts(account_key,platform_key)""")
    # 老事件补不可重复请求键，再建立数据库级幂等约束。
    for event in q.execute("select id from ecom_v2_reimbursement_events where request_key='' order by id").fetchall():
        q.execute("update ecom_v2_reimbursement_events set request_key=? where id=?",
                  ("legacy-event-%d" % int(event["id"]), event["id"]))
    q.execute("create unique index if not exists idx_v2_reimbursement_request on ecom_v2_reimbursement_events(request_key)")
    # SQLite 旧表无法直接 ALTER 增加 CHECK/FK，用触发器对新写入强制同等约束。
    q.execute("""create trigger if not exists trg_v2_purchase_report_insert
        before insert on ecom_v2_purchases when not exists(
            select 1 from ecom_v2_reports where id=new.report_id)
        begin select raise(abort,'report_not_found'); end""")
    q.execute("""create trigger if not exists trg_v2_recharge_report_insert
        before insert on ecom_v2_recharges when not exists(
            select 1 from ecom_v2_reports where id=new.report_id)
        begin select raise(abort,'report_not_found'); end""")
    q.execute("""create trigger if not exists trg_v2_update_report_insert
        before insert on ecom_v2_account_updates when not exists(
            select 1 from ecom_v2_reports where id=new.report_id)
        begin select raise(abort,'report_not_found'); end""")
    q.execute("""create trigger if not exists trg_v2_purchase_state_insert
        before insert on ecom_v2_purchases when
            new.reimbursement_status not in('待报销','已报销','无需报销','已冲销') or
            new.account_status not in('待运营','运营中','已出单','受限','封禁','停用') or new.active not in(0,1)
        begin select raise(abort,'invalid_purchase_state'); end""")
    q.execute("""create trigger if not exists trg_v2_purchase_state_update
        before update of reimbursement_status,account_status,active on ecom_v2_purchases when
            new.reimbursement_status not in('待报销','已报销','无需报销','已冲销') or
            new.account_status not in('待运营','运营中','已出单','受限','封禁','停用') or new.active not in(0,1)
        begin select raise(abort,'invalid_purchase_state'); end""")
    q.execute("insert or replace into ecom_v2_schema_version(version,applied_at,note) values(3,?,?)",
              (int(time.time()), "R3责任链、报销版本和单进程迁移"))
    # 全新数据库同时登记版本化迁移账本，避免应用 health=3、备份/巡检却显示 schema=0。
    q.execute("""create table if not exists team13_schema_contract(
        singleton integer primary key check(singleton=1),contract_version integer not null,updated_at integer not null)""")
    q.execute("insert or replace into team13_schema_contract(singleton,contract_version,updated_at) values(1,3,?)",
              (int(time.time()),))
    q.execute("""create table if not exists team13_schema_migrations(
        version integer primary key,name text not null,checksum text not null,applied_at text not null)""")
    applied_at=datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00","Z")
    q.execute("""insert or ignore into team13_schema_migrations(version,name,checksum,applied_at)
        values(3,'0003_operational_contract.sql',?,?)""",
        ("8036b5a2ab64b4cbc3db75c49b1083fc07c080c618f2525f4a5bb975684a742f",applied_at))
    c.commit(); c.close()

def _v2_require_schema():
    """工作进程只校验不迁移；版本不足就拒绝启动，防止新代码带旧库运行。"""
    c = db()
    try:
        row = c.execute("select max(version) version from ecom_v2_schema_version").fetchone()
        if not row or int(row["version"] or 0) < 3:
            raise RuntimeError("数据库版本低于 3，请先执行单进程迁移")
        required = {
            "ecom_v2_purchases": ("active", "reimbursement_revision", "retired_at", "retired_reason"),
            "ecom_v2_account_updates": ("expected_account_revision",),
            "ecom_v2_account_snapshots": ("applied_revision",),
            "ecom_v2_reimbursement_events": ("request_key",),
        }
        for table, columns in required.items():
            present = set(x[1] for x in c.execute("pragma table_info(%s)" % table).fetchall())
            if any(column not in present for column in columns):
                raise RuntimeError("数据库结构不完整: %s" % table)
    finally:
        c.close()

def _v2_member(c=None):
    role, name = _sess_parse(request.cookies.get("zb13sess", ""))
    if role == "admin":
        return {"role": "admin", "name": name or "管理员", "group_no": 0,
                "group_name": "全公司", "is_leader": True, "active": True}
    if role != "employee" or not name:
        return None
    own = not c
    if own: c = db()
    r = c.execute("""select m.name,m.group_no,m.is_leader,m.active,g.group_name
        from ecom_v2_members m join ecom_v2_groups g on g.group_no=m.group_no where m.name=?""", (name,)).fetchone()
    if own: c.close()
    if not r or not r["active"]:
        return None
    return {"role": "employee", "name": r["name"], "group_no": r["group_no"],
            "group_name": r["group_name"], "is_leader": bool(r["is_leader"]), "active": True}

def _v2_guard(leader=False, admin=False):
    me = _v2_member()
    if not me:
        return None, (jsonify(err="账号尚未分组，请联系管理员配置所属小组"), 403)
    if admin and me["role"] != "admin":
        return None, (jsonify(err="仅老板/管理员可操作"), 403)
    if leader and me["role"] != "admin" and not me["is_leader"]:
        return None, (jsonify(err="仅老板或本组组长可查看"), 403)
    return me, None

def _v2_find_account(c, name, platform):
    account_key, platform_key = _v2_account_key(name, platform)
    return c.execute("""select * from ecom_v2_accounts
        where account_key=? and platform_key=? order by active desc,id limit 1""",
        (account_key, platform_key)).fetchone()

def _v2_closed_settlement(c, day, group_no):
    return c.execute("""select id,start_date,end_date,group_no,version from ecom_v2_settlements
        where status='closed' and start_date<=? and end_date>=? and group_no in (0,?)
        order by group_no desc,id desc limit 1""", (day, day, int(group_no or 0))).fetchone()

def _v2_password_hash(password):
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("ascii"), 180000).hex()
    return salt + "$" + digest

def _v2_password_verify(password, stored):
    try:
        salt, expected = (stored or "").split("$", 1)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("ascii"), 180000).hex()
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False

def _v2_voucher_ok(url):
    if not VOUCHER_URL_RE.match(url or ""):
        return False
    name = url.rsplit("/", 1)[-1]
    path = os.path.join(UPLOAD_DIR, name)
    return os.path.isfile(path) and verify_image_file(path, name.rsplit(".", 1)[-1])

def _v2_group_map(c):
    return {int(r["group_no"]): r["group_name"] for r in c.execute(
        "select group_no,group_name from ecom_v2_groups order by group_no").fetchall()}

def _v2_report_from_parts(r, gm, rs, ps, us):
    account_cost = sum(int(x["cost_cents"] or 0) for x in ps)
    recharge = sum(int(x["amount_cents"] or 0) for x in rs)
    reimbursed = sum(int(x["reimbursed_cents"] or 0) for x in ps)
    pending_reimbursement = sum(max(0, int(x["cost_cents"] or 0) - int(x["reimbursed_cents"] or 0))
        for x in ps if x["reimbursement_status"] == "待报销")
    net_gmv = int(r["gmv_cents"] or 0) - int(r["refund_cents"] or 0)
    profit = net_gmv - int(r["ad_spend_cents"] or 0) - account_cost
    return {"id": r["id"], "biz_date": r["biz_date"], "group_no": r["group_no"],
        "group_name": gm.get(r["group_no"], "第%d组" % r["group_no"]), "employee_name": r["employee_name"],
        "gmv": _ecom_yuan(net_gmv), "gross_gmv": _ecom_yuan(r["gmv_cents"]),
        "refund": _ecom_yuan(r["refund_cents"]), "ad_spend": _ecom_yuan(r["ad_spend_cents"]),
        "note": r["note"], "status": r["reconcile_status"], "reconcile_note": r["reconcile_note"],
        "reconciled_by": r["reconciled_by"], "reconciled_at": r["reconciled_at"],
        "revision": int(r["revision"] or 1), "last_rejection_note": r["last_rejection_note"],
        "resubmitted_at": int(r["resubmitted_at"] or 0),
        "is_resubmitted": bool(r["last_rejection_note"] and r["reconcile_status"] == "pending"),
        "created": r["created"], "updated": r["updated"],
        "recharges": [{"id": x["id"], "type": x["recharge_type"], "amount": _ecom_yuan(x["amount_cents"]),
                       "note": x["note"]} for x in rs],
        "purchases": [{"id": x["id"], "account_name": x["account_name"], "platform": x["platform"],
            "cost": _ecom_yuan(x["cost_cents"]), "voucher_url": x["voucher_url"],
            "reimbursement_status": x["reimbursement_status"], "reimbursed": _ecom_yuan(x["reimbursed_cents"]),
            "reimbursement_revision": int(x["reimbursement_revision"] or 1),
            "account_status": x["account_status"], "note": x["note"]} for x in ps],
        "account_updates": [{"id": x["id"], "account_name": x["account_name"], "platform": x["platform"],
            "account_status": x["account_status"], "note": x["note"],
            "expected_account_revision": int(x["expected_account_revision"] or 0)} for x in us],
        "summary": {"recharge_total": _ecom_yuan(recharge), "account_cost": _ecom_yuan(account_cost),
            "reimbursed_total": _ecom_yuan(reimbursed), "pending_reimbursement": _ecom_yuan(pending_reimbursement),
            "profit": _ecom_yuan(profit),
            "ad_roi": _v2_ratio(net_gmv, r["ad_spend_cents"]),
            "input_roi": _v2_ratio(net_gmv, int(r["ad_spend_cents"] or 0) + account_cost)}}

def _v2_reports_batch(c, report_ids):
    """批量取日报主表和三类明细，查询数与日报数无关。"""
    ids = []
    seen = set()
    for value in report_ids or []:
        try: rid = int(value)
        except Exception: continue
        if rid > 0 and rid not in seen:
            ids.append(rid); seen.add(rid)
    if not ids: return []
    marks = ",".join("?" for _ in ids)
    rows = c.execute("select * from ecom_v2_reports where id in (%s)" % marks, ids).fetchall()
    by_id = {int(r["id"]): r for r in rows}
    recharges = {rid: [] for rid in ids}; purchases = {rid: [] for rid in ids}; updates = {rid: [] for rid in ids}
    for x in c.execute("""select id,report_id,recharge_type,amount_cents,note from ecom_v2_recharges
        where report_id in (%s) order by id""" % marks, ids).fetchall():
        recharges.setdefault(int(x["report_id"]), []).append(x)
    for x in c.execute("""select id,report_id,account_name,platform,cost_cents,voucher_url,reimbursement_status,
        reimbursed_cents,reimbursement_revision,account_status,note from ecom_v2_purchases
        where active=1 and report_id in (%s) order by id""" % marks, ids).fetchall():
        purchases.setdefault(int(x["report_id"]), []).append(x)
    for x in c.execute("""select id,report_id,account_name,platform,account_status,note,expected_account_revision from ecom_v2_account_updates
        where report_id in (%s) order by id""" % marks, ids).fetchall():
        updates.setdefault(int(x["report_id"]), []).append(x)
    gm = _v2_group_map(c)
    return [_v2_report_from_parts(by_id[rid], gm, recharges.get(rid, []), purchases.get(rid, []), updates.get(rid, []))
            for rid in ids if rid in by_id]

def _v2_report_dict(c, rid):
    rows = _v2_reports_batch(c, [rid])
    return rows[0] if rows else None

def _v2_sync_account(c, group_no, owner, day, name, platform, status, cost=0, voucher="", note="", report_id=0):
    # 普通日报只能更新资产状态，不能隐式改变组别/负责人。账号转交必须另走管理员流程。
    account_key, platform_key = _v2_account_key(name, platform)
    old = _v2_find_account(c, name, platform)
    now = int(time.time())
    if old:
        use_group = int(old["group_no"]); use_owner = old["owner_name"]
        use_cost = cost if cost > 0 else int(old["purchase_cost_cents"] or 0)
        use_date = day if cost > 0 else old["purchase_date"]
        use_voucher = voucher if voucher else old["voucher_url"]
        c.execute("""update ecom_v2_accounts set account_key=?,platform_key=?,group_no=?,owner_name=?,
            purchase_cost_cents=?,purchase_date=?,voucher_url=?,account_status=?,note=?,active=?,
            revision=revision+1,updated=? where id=?""",
            (account_key, platform_key, use_group, use_owner, use_cost, use_date, use_voucher, status, note,
             0 if status == "停用" else 1, now, old["id"]))
        if old["account_status"] != status or old["note"] != note or cost > 0:
            history_note = note or "同状态确认/资料更新"
            c.execute("insert into ecom_v2_account_history(account_id,old_status,new_status,changed_by,note,report_id,created) values(?,?,?,?,?,?,?)",
                      (old["id"], old["account_status"], status, _ecom_actor(), history_note, report_id, now))
    else:
        q = c.execute("""insert into ecom_v2_accounts(account_name,platform,account_key,platform_key,group_no,owner_name,
            purchase_cost_cents,purchase_date,voucher_url,account_status,note,active,revision,created,updated)
            values(?,?,?,?,?,?,?,?,?,?,?,?,1,?,?)""",
            (name, platform, account_key, platform_key, group_no, owner, cost, day if cost > 0 else "", voucher,
             status, note, 0 if status == "停用" else 1, now, now))
        c.execute("insert into ecom_v2_account_history(account_id,old_status,new_status,changed_by,note,report_id,created) values(?,?,?,?,?,?,?)",
                  (q.lastrowid, "", status, _ecom_actor(), note, report_id, now))

def _v2_snapshot_account(c, report_id, name, platform):
    exists = c.execute("select 1 from ecom_v2_account_snapshots where report_id=? and account_name=? and platform=?",
                       (report_id, name, platform)).fetchone()
    if exists: return
    old = _v2_find_account(c, name, platform)
    cursor = 0
    if old:
        cursor = c.execute("select ifnull(max(id),0) n from ecom_v2_account_history where account_id=?",
                           (old["id"],)).fetchone()["n"]
    c.execute("insert into ecom_v2_account_snapshots(report_id,account_name,platform,before_json,history_cursor,applied_revision,created) values(?,?,?,?,?,0,?)",
              (report_id, name, platform, _ecom_safe_json(dict(old)) if old else "", cursor, int(time.time())))

def _v2_mark_snapshot_applied(c, report_id, name, platform):
    current = _v2_find_account(c, name, platform)
    if not current: raise ValueError("账号资产同步失败")
    c.execute("update ecom_v2_account_snapshots set applied_revision=? where report_id=? and account_name=? and platform=?",
              (int(current["revision"] or 1), report_id, name, platform))

def _v2_apply_report_accounts(c, report):
    rid = int(report["id"])
    for x in report["purchases"]:
        _v2_snapshot_account(c, rid, x["account_name"], x["platform"])
        _v2_sync_account(c, report["group_no"], report["employee_name"], report["biz_date"],
            x["account_name"], x["platform"], x["account_status"], int(round(x["cost"] * 100)),
            x["voucher_url"], x["note"], rid)
        _v2_mark_snapshot_applied(c, rid, x["account_name"], x["platform"])
    for x in report["account_updates"]:
        current = _v2_find_account(c, x["account_name"], x["platform"])
        expected = int(x.get("expected_account_revision") or 0)
        if expected and (not current or int(current["revision"] or 1) != expected):
            raise ValueError("账号“%s”在提交后已被更新，请退回日报重新读取" % x["account_name"])
        if not expected and current:
            raise ValueError("账号“%s”在提交后已出现，请退回日报重新读取" % x["account_name"])
        _v2_snapshot_account(c, rid, x["account_name"], x["platform"])
        _v2_sync_account(c, report["group_no"], report["employee_name"], report["biz_date"],
            x["account_name"], x["platform"], x["account_status"], 0, "", x["note"], rid)
        _v2_mark_snapshot_applied(c, rid, x["account_name"], x["platform"])

def _v2_rollback_report_accounts(c, report_id):
    snaps = c.execute("select * from ecom_v2_account_snapshots where report_id=? order by rowid desc",
                      (report_id,)).fetchall()
    for s in snaps:
        current = _v2_find_account(c, s["account_name"], s["platform"])
        if current and int(current["revision"] or 1) != int(s["applied_revision"] or 0):
            raise ValueError("账号“%s”核账后已有人工修改，不能自动回滚" % s["account_name"])
        if current and c.execute("select 1 from ecom_v2_account_history where account_id=? and id>? and report_id<>? limit 1",
                                 (current["id"], int(s["history_cursor"] or 0), report_id)).fetchone():
            raise ValueError("涉及账号已有后续状态变化，请先处理后续记录")
    for s in snaps:
        before = json.loads(s["before_json"]) if s["before_json"] else None
        current = _v2_find_account(c, s["account_name"], s["platform"])
        if before:
            before_account_key = before.get("account_key") or _v2_account_key(before["account_name"], before["platform"])[0]
            before_platform_key = before.get("platform_key") or _v2_account_key(before["account_name"], before["platform"])[1]
            c.execute("""update ecom_v2_accounts set account_name=?,platform=?,account_key=?,platform_key=?,
                group_no=?,owner_name=?,purchase_cost_cents=?,purchase_date=?,voucher_url=?,account_status=?,note=?,
                active=?,revision=?,created=?,updated=? where id=?""",
                (before["account_name"],before["platform"],before_account_key,before_platform_key,
                 before["group_no"],before["owner_name"],
                 before["purchase_cost_cents"],before["purchase_date"],before["voucher_url"],before["account_status"],
                 before["note"],before["active"],int(before.get("revision") or 1),before["created"],before["updated"],before["id"]))
        elif current:
            c.execute("delete from ecom_v2_accounts where id=?", (current["id"],))
    c.execute("delete from ecom_v2_account_history where report_id=?", (report_id,))
    c.execute("delete from ecom_v2_account_snapshots where report_id=?", (report_id,))

@app.get("/ecom/v2/me")
def v2_me():
    me, err = _v2_guard()
    if err: return err
    c = db(); groups = [{"group_no": r["group_no"], "group_name": r["group_name"]} for r in c.execute(
        "select group_no,group_name from ecom_v2_groups order by group_no").fetchall()]
    c.close()
    return jsonify(ok=True, me=me, groups=groups, account_statuses=V2_ACCOUNT_STATUSES)

@app.get("/ecom/v2/members")
def v2_members_get():
    me, err = _v2_guard(admin=True)
    if err: return err
    c = db()
    rows = c.execute("""select m.name,m.group_no,m.is_leader,m.active,g.group_name,ifnull(s.phone,'') phone
        from ecom_v2_members m join ecom_v2_groups g on g.group_no=m.group_no
        left join staff s on s.name=m.name order by m.group_no,m.is_leader desc,m.name""").fetchall()
    groups = [{"group_no": r["group_no"], "group_name": r["group_name"]} for r in c.execute(
        "select group_no,group_name from ecom_v2_groups order by group_no").fetchall()]
    c.close()
    return jsonify(ok=True, members=[dict(x) for x in rows], groups=groups)

@app.post("/ecom/v2/member/save")
def v2_member_save():
    me, err = _v2_guard(admin=True)
    if err: return err
    d = request.get_json(force=True, silent=True) or {}
    name = norm_name(d.get("name")); phone = re.sub(r"\D", "", str(d.get("phone") or ""))[:15]
    try: group_no = int(d.get("group_no"))
    except Exception: group_no = 0
    leader = 1 if _truthy(d.get("is_leader")) else 0
    active = 0 if d.get("active") is False else 1
    login_password = str(d.get("login_password") or "")
    if not name or group_no not in range(1, 9): return jsonify(err="请填写姓名并选择第1组至第8组"), 400
    if len(phone) < 6: return jsonify(err="手机号至少6位，用于员工实名登录"), 400
    now = int(time.time()); c = db()
    try:
        c.execute("begin immediate")
        old = c.execute("select * from ecom_v2_members where name=?", (name,)).fetchone()
        if not old and len(login_password) < 6:
            c.rollback(); c.close(); return jsonify(err="新增员工时请设置至少6位个人登录密码"), 400
        if login_password and len(login_password) < 6:
            c.rollback(); c.close(); return jsonify(err="个人登录密码至少6位"), 400
        passhash = _v2_password_hash(login_password) if login_password else (old["password_hash"] if old else "")
        auth_version = int(old["auth_version"] or 1) + (1 if login_password else 0) if old else 1
        c.execute("""insert or replace into ecom_v2_members(name,group_no,is_leader,active,password_hash,auth_version,created,updated)
            values(?,?,?,?,?,?,?,?)""", (name, group_no, leader, active, passhash, auth_version,
            old["created"] if old else now, now))
        staffrow = c.execute("select id from staff where name=?", (name,)).fetchone()
        if staffrow: c.execute("update staff set phone=? where id=?", (phone, staffrow["id"]))
        else: c.execute("insert into staff(name,phone,note,created) values(?,?,?,?)", (name, phone, "舟格运营人员分组", now))
        c.execute("insert into ecom_v2_audit(action,actor,before_json,after_json,ip,created) values(?,?,?,?,?,?)",
                  ("member_save", _ecom_actor(), _ecom_safe_json(dict(old) if old else None),
                   _ecom_safe_json({"name": name, "group_no": group_no, "is_leader": leader, "active": active}), ipaddr(), now))
        c.commit(); c.close(); return jsonify(ok=True)
    except Exception:
        c.rollback(); c.close(); return jsonify(err="保存人员分组失败"), 500

@app.post("/ecom/v2/group/save")
def v2_group_save():
    me, err = _v2_guard(admin=True)
    if err: return err
    d = request.get_json(force=True, silent=True) or {}
    try: group_no = int(d.get("group_no"))
    except Exception: group_no = 0
    group_name = clean(d.get("group_name"), 30)
    if group_no not in range(1, 9) or not group_name: return jsonify(err="组别名称不能为空"), 400
    c = db(); c.execute("update ecom_v2_groups set group_name=?,updated=? where group_no=?",
                        (group_name, int(time.time()), group_no)); c.commit(); c.close()
    return jsonify(ok=True)

@app.get("/ecom/v2/report")
def v2_report_get():
    me, err = _v2_guard()
    if err: return err
    day = clean(request.args.get("date"), 10)
    employee = norm_name(request.args.get("employee")) if me["role"] == "admin" else me["name"]
    if not valid_date(day) or not employee: return jsonify(err="日期或员工不正确"), 400
    c = db(); r = c.execute("select id from ecom_v2_reports where biz_date=? and employee_name=?", (day, employee)).fetchone()
    out = _v2_report_dict(c, r["id"]) if r else None; c.close()
    return jsonify(ok=True, report=out)

@app.get("/ecom/v2/my/reports")
def v2_my_reports():
    me, err = _v2_guard()
    if err: return err
    try: days = int(request.args.get("days", "7") or 7)
    except Exception: days = 7
    days = min(31, max(1, days))
    employee = me["name"] if me["role"] != "admin" else norm_name(request.args.get("employee"))
    if not employee: return jsonify(err="请选择运营员工"), 400
    end = _ecom_now_date()
    start = (end - datetime.timedelta(days=days - 1)).isoformat()
    c = db()
    ids = c.execute("""select id from ecom_v2_reports where employee_name=? and biz_date>=?
        order by biz_date desc,id desc""", (employee, start)).fetchall()
    reports = [_v2_report_dict(c, x["id"]) for x in ids]
    c.close()
    return jsonify(ok=True, employee=employee, days=days, reports=reports)

@app.post("/ecom/v2/report/save")
def v2_report_save():
    me, err = _v2_guard()
    if err: return err
    d = request.get_json(force=True, silent=True) or {}
    day = clean(d.get("biz_date"), 10)
    if not valid_date(day): return jsonify(err="业务日期格式不正确"), 400
    if day > _ecom_now_date().isoformat(): return jsonify(err="不能填报未来日期"), 400
    c = db()
    if me["role"] == "admin":
        employee = norm_name(d.get("employee_name"))
        member = c.execute("select name,group_no,active from ecom_v2_members where name=?", (employee,)).fetchone()
        if not member or not member["active"]:
            c.close(); return jsonify(err="请选择已启用且已分组的运营员工"), 400
        group_no = member["group_no"]
    else:
        employee = me["name"]; group_no = me["group_no"]
    try:
        gmv = _ecom_money_cents(d.get("gmv"), "GMV")
        refund = _ecom_money_cents(d.get("refund"), "退款金额")
        ad_spend = _ecom_money_cents(d.get("ad_spend"), "广告消耗")
    except ValueError as exc:
        c.close(); return jsonify(err=str(exc)), 400
    note = clean(d.get("note"), 500)
    try: expected_revision = int(d.get("expected_revision", 0))
    except Exception: expected_revision = -1
    recharges = d.get("recharges") or []; purchases = d.get("purchases") or []; updates = d.get("account_updates") or []
    if not isinstance(recharges, list) or not isinstance(purchases, list) or not isinstance(updates, list):
        c.close(); return jsonify(err="明细数据格式不正确"), 400
    if len(recharges) > 50 or len(purchases) > 50 or len(updates) > 200:
        c.close(); return jsonify(err="单张日报明细过多，请拆分处理"), 400
    cr=[]; cp=[]; cu=[]
    try:
        for i,x in enumerate(recharges):
            if not isinstance(x, dict): raise ValueError("第%d条充值明细格式不正确"%(i+1))
            typ=clean(x.get("type"),12); amount=_ecom_money_cents(x.get("amount"),"第%d条充值金额"%(i+1))
            if typ not in ECOM_RECHARGE_TYPES or amount<=0: raise ValueError("第%d条充值明细不正确"%(i+1))
            cr.append((typ,amount,clean(x.get("note"),200)))
        seen=set()
        for i,x in enumerate(purchases):
            if not isinstance(x, dict): raise ValueError("第%d条买号记录格式不正确"%(i+1))
            name=_v2_account_display(x.get("account_name"),80,"第%d条账号名称"%(i+1)); platform=_v2_account_display(x.get("platform") or "",30,"第%d条平台"%(i+1))
            cost=_ecom_money_cents(x.get("cost"),"第%d条账号成本"%(i+1)); voucher=clean(x.get("voucher_url"),500)
            rstate=clean(x.get("reimbursement_status"),12) or "待报销"
            reimb=_ecom_money_cents(x.get("reimbursed"),"第%d条已报销金额"%(i+1))
            astate=clean(x.get("account_status"),12) or "待运营"; key=_v2_account_key(name,platform)
            if not name or cost<=0: raise ValueError("第%d条买号记录缺少账号名称或成本"%(i+1))
            if key in seen: raise ValueError("买号账号“%s”重复"%name)
            if not _v2_voucher_ok(voucher): raise ValueError("第%d条买号记录必须上传有效付款凭证"%(i+1))
            if rstate not in ("待报销", "无需报销") or astate not in V2_ACCOUNT_STATUSES:
                raise ValueError("第%d条报销状态只能选择待报销或无需报销；已报销由老板在报销中心确认"%(i+1))
            if reimb != 0:
                raise ValueError("第%d条已报销金额由老板在报销中心确认，填报时必须为0"%(i+1))
            seen.add(key); cp.append((name,platform,key[0],key[1],cost,voucher,rstate,reimb,astate,clean(x.get("note"),200)))
        purchase_keys=set(seen); seen=set()
        for i,x in enumerate(updates):
            if not isinstance(x, dict): raise ValueError("第%d条账号状态格式不正确"%(i+1))
            name=_v2_account_display(x.get("account_name"),80,"第%d条账号名称"%(i+1)); platform=_v2_account_display(x.get("platform") or "",30,"第%d条平台"%(i+1))
            status=clean(x.get("account_status"),12); key=_v2_account_key(name,platform)
            if not name or status not in V2_ACCOUNT_STATUSES: raise ValueError("第%d条账号状态不正确"%(i+1))
            if key in purchase_keys: raise ValueError("账号“%s”不能同时填买号和状态更新，请合并为一条"%name)
            if key in seen: raise ValueError("账号状态“%s”重复"%name)
            seen.add(key); cu.append((name,platform,status,clean(x.get("note"),200)))
    except ValueError as exc:
        c.close(); return jsonify(err=str(exc)), 400
    now=int(time.time())
    try:
        c.execute("begin immediate")
        closed = _v2_closed_settlement(c, day, group_no)
        if closed:
            c.rollback(); c.close(); return jsonify(
                err="该日期已进入第%d版结算，需老板在结算中心重新打开后才能修改" % int(closed["version"] or 1)), 409
        old=c.execute("""select id,reconcile_status,reconcile_note,revision,last_rejection_note,resubmitted_at
            from ecom_v2_reports where biz_date=? and employee_name=?""",(day,employee)).fetchone()
        before=_v2_report_dict(c,old["id"]) if old else None
        if old and old["reconcile_status"]=="confirmed":
            c.rollback(); c.close(); return jsonify(err="该日报已核账，必须先在核账中心退回后再修改"),409
        if old and expected_revision != int(old["revision"] or 1):
            c.rollback(); c.close(); return jsonify(err="日报已被更新，请重新读取后再提交"),409
        if not old and expected_revision != 0:
            c.rollback(); c.close(); return jsonify(err="当前日报状态已变化，请刷新后再试"),409
        # 买号成本公司内只记一次。必须在同一写事务中同时查 pending/confirmed，
        # 否则两张待核账日报可以同时占用同一账号并在后续重复扣成本。
        own_id = int(old["id"]) if old else 0
        for name,platform,account_key,platform_key,*_ in cp:
            existing_account = _v2_find_account(c, name, platform)
            if existing_account and int(existing_account["group_no"]) != int(group_no):
                c.rollback(); c.close(); return jsonify(err="账号“%s”属于其他小组，不能在本组记买号成本" % name),403
            conflict = c.execute("""select r.id,r.employee_name,r.biz_date,r.reconcile_status
                from ecom_v2_purchases p join ecom_v2_reports r on r.id=p.report_id
                where p.account_key=? and p.platform_key=? and r.id<>?
                  and p.active=1 and r.reconcile_status in ('pending','confirmed') limit 1""",
                (account_key, platform_key, own_id)).fetchone()
            if conflict:
                c.rollback(); c.close(); return jsonify(err="账号“%s”已在公司台账记过买号成本；转交或状态变化请改填“账号状态更新”" % name),409
        checked_updates=[]
        for name,platform,status,nt in cu:
            existing_account = _v2_find_account(c, name, platform)
            if existing_account and int(existing_account["group_no"]) != int(group_no):
                c.rollback(); c.close(); return jsonify(err="账号“%s”属于其他小组，无权更新或接管" % name),403
            checked_updates.append((name,platform,status,nt,
                int(existing_account["revision"] or 1) if existing_account else 0))
        cu=checked_updates
        if old:
            rid=old["id"]
            was_rejected = old["reconcile_status"] == "rejected"
            last_rejection = old["reconcile_note"] if was_rejected else old["last_rejection_note"]
            resubmitted_at = now if was_rejected else int(old["resubmitted_at"] or 0)
            c.execute("""update ecom_v2_reports set group_no=?,gmv_cents=?,refund_cents=?,ad_spend_cents=?,note=?,
                reconcile_status='pending',reconcile_note='',reconciled_by='',reconciled_at=0,
                revision=?,last_rejection_note=?,resubmitted_at=?,ip=?,updated=? where id=?""",
                (group_no,gmv,refund,ad_spend,note,int(old["revision"] or 1)+1,last_rejection,
                 resubmitted_at,ipaddr(),now,rid))
            c.execute("delete from ecom_v2_recharges where report_id=?",(rid,))
            c.execute("delete from ecom_v2_account_updates where report_id=?",(rid,))
            # 已产生报销事件的买号明细永不硬删，避免付款证据变成孤儿；旧版本只退出当前汇总。
            c.execute("""update ecom_v2_purchases set active=0,retired_at=?,retired_reason=?
                where report_id=? and exists(select 1 from ecom_v2_reimbursement_events e where e.purchase_id=ecom_v2_purchases.id)""",
                (now,"日报重提，保留历史付款链",rid))
            c.execute("""delete from ecom_v2_purchases where report_id=? and active=1
                and not exists(select 1 from ecom_v2_reimbursement_events e where e.purchase_id=ecom_v2_purchases.id)""",(rid,))
            action="report_resubmit" if was_rejected else "report_update"
        else:
            q=c.execute("""insert into ecom_v2_reports(biz_date,group_no,employee_name,gmv_cents,refund_cents,ad_spend_cents,
                note,reconcile_status,ip,created,updated) values(?,?,?,?,?,?,?,'pending',?,?,?)""",
                (day,group_no,employee,gmv,refund,ad_spend,note,ipaddr(),now,now))
            rid=q.lastrowid; action="report_create"
        for typ,amount,nt in cr:
            c.execute("insert into ecom_v2_recharges(report_id,recharge_type,amount_cents,note,created) values(?,?,?,?,?)",(rid,typ,amount,nt,now))
        for name,platform,account_key,platform_key,cost,voucher,rstate,reimb,astate,nt in cp:
            c.execute("""insert into ecom_v2_purchases(report_id,account_name,platform,account_key,platform_key,
                cost_cents,voucher_url,reimbursement_status,reimbursed_cents,account_status,note,created)
                values(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (rid,name,platform,account_key,platform_key,cost,voucher,rstate,reimb,astate,nt,now))
        for name,platform,status,nt,account_revision in cu:
            c.execute("""insert into ecom_v2_account_updates(report_id,account_name,platform,account_status,note,
                expected_account_revision,created) values(?,?,?,?,?,?,?)""",
                      (rid,name,platform,status,nt,account_revision,now))
        after=_v2_report_dict(c,rid)
        c.execute("insert into ecom_v2_audit(report_id,action,actor,before_json,after_json,ip,created) values(?,?,?,?,?,?,?)",
                  (rid,action,_ecom_actor(),_ecom_safe_json(before),_ecom_safe_json(after),ipaddr(),now))
        message = "退回修改已重新提交，等待核账" if old and old["reconcile_status"] == "rejected" else "已提交，等待核账"
        c.commit(); c.close(); return jsonify(ok=True,report=after,message=message)
    except sqlite3.IntegrityError:
        c.rollback(); c.close(); return jsonify(err="该员工当天日报已存在，请刷新后重试"),409
    except sqlite3.OperationalError as exc:
        c.rollback(); c.close(); return _sqlite_operational_response(exc)
    except Exception:
        c.rollback(); c.close(); return jsonify(err="日报保存失败"),500

def _v2_sum_blank(name=""):
    return {"name":name,"gmv_cents":0,"gross_gmv_cents":0,"refund_cents":0,"ad_spend_cents":0,"account_cost_cents":0,
            "recharge_cents":0,"profit_cents":0,"report_count":0,"bought_accounts":0}

def _v2_sum_public(x):
    invest=x["ad_spend_cents"]+x["account_cost_cents"]
    return {"name":x["name"],"gmv":_ecom_yuan(x["gmv_cents"]),"gross_gmv":_ecom_yuan(x["gross_gmv_cents"]),
        "refund":_ecom_yuan(x["refund_cents"]),"ad_spend":_ecom_yuan(x["ad_spend_cents"]),
        "account_cost":_ecom_yuan(x["account_cost_cents"]),"recharge_total":_ecom_yuan(x["recharge_cents"]),
        "profit":_ecom_yuan(x["profit_cents"]),"report_count":x["report_count"],"bought_accounts":x["bought_accounts"],
        "ad_roi":_v2_ratio(x["gmv_cents"],x["ad_spend_cents"]),
        "input_roi":_v2_ratio(x["gmv_cents"],invest)}

def _v2_aggregate_rows(c, where, params, key_select, group_by, confirmed_only=False):
    """只在已筛选日报上做相关子查询，避免短日期查看也全表扫描明细表。"""
    status_sql = " and r.reconcile_status='confirmed'" if confirmed_only else ""
    sql = """select %s,
            coalesce(sum(r.gmv_cents-r.refund_cents),0) gmv_cents,
            coalesce(sum(r.gmv_cents),0) gross_gmv_cents,
            coalesce(sum(r.refund_cents),0) refund_cents,
            coalesce(sum(r.ad_spend_cents),0) ad_spend_cents,
            coalesce(sum(coalesce((select sum(p.cost_cents) from ecom_v2_purchases p
                where p.report_id=r.id and p.active=1),0)),0) account_cost_cents,
            coalesce(sum(coalesce((select sum(rc.amount_cents) from ecom_v2_recharges rc
                where rc.report_id=r.id),0)),0) recharge_cents,
            count(*) report_count,
            coalesce(sum(coalesce((select count(*) from ecom_v2_purchases p
                where p.report_id=r.id and p.active=1),0)),0) bought_accounts
        from ecom_v2_reports r
        where %s%s group by %s""" % (key_select, where, status_sql, group_by)
    return c.execute(sql, params).fetchall()

def _v2_sum_from_aggregate(row, name=""):
    out = _v2_sum_blank(name)
    if not row: return out
    for key in ("gmv_cents","gross_gmv_cents","refund_cents","ad_spend_cents",
                "account_cost_cents","recharge_cents","report_count","bought_accounts"):
        out[key] = int(row[key] or 0)
    out["profit_cents"] = out["gmv_cents"] - out["ad_spend_cents"] - out["account_cost_cents"]
    return out

def _v2_page_arg(name, default, maximum):
    try: value = int(request.args.get(name, str(default)) or default)
    except Exception: value = default
    return min(maximum, max(0, value))

@app.get("/ecom/v2/dashboard")
def v2_dashboard():
    me,err=_v2_guard(leader=True)
    if err:return err
    today=_ecom_now_date(); start=clean(request.args.get("start"),10) or (today-datetime.timedelta(days=6)).isoformat()
    end=clean(request.args.get("end"),10) or today.isoformat()
    try:_ecom_validate_range(start,end)
    except ValueError as exc:return jsonify(err=str(exc)),400
    try:req_group=int(request.args.get("group","0") or 0)
    except Exception:return jsonify(err="小组筛选参数不正确"),400
    if me["role"]=="admin" and req_group not in range(0,9):
        return jsonify(err="小组筛选参数不正确"),400
    group_filter=me["group_no"] if me["role"]!="admin" else (req_group if req_group in range(1,9) else 0)
    c=db(); params=[start,end]; where="r.biz_date between ? and ?"
    if group_filter:where+=" and r.group_no=?";params.append(group_filter)
    gm=_v2_group_map(c)
    member_sql="select name,group_no,is_leader from ecom_v2_members where active=1"
    member_params=[]
    if group_filter:member_sql+=" and group_no=?";member_params.append(group_filter)
    members=c.execute(member_sql+" order by group_no,is_leader desc,name",member_params).fetchall()
    employee_meta={x["name"]:{"group_no":x["group_no"],"group_name":gm.get(x["group_no"],""),
        "is_leader":bool(x["is_leader"])} for x in members}

    # 公司/状态、小组、员工三类汇总均在 SQL 中完成，不加载日报明细。
    status_rows=_v2_aggregate_rows(c,where,params,"r.reconcile_status status","r.reconcile_status")
    status_map={x["status"]:x for x in status_rows}
    company=_v2_sum_from_aggregate(status_map.get("confirmed"),"公司合计")
    pending=_v2_sum_from_aggregate(status_map.get("pending"),"待核账")
    rejected=_v2_sum_from_aggregate(status_map.get("rejected"),"已退回")
    group_rows=_v2_aggregate_rows(c,where,params,"r.group_no group_no","r.group_no",True)
    group_map={int(x["group_no"]):x for x in group_rows}
    employee_rows=_v2_aggregate_rows(c,where,params,
        "r.employee_name name,max(r.group_no) report_group_no","r.employee_name",True)
    employee_agg={x["name"]:x for x in employee_rows}

    employees={x["name"]:_v2_sum_from_aggregate(employee_agg.get(x["name"]),x["name"]) for x in members}
    for row in employee_rows:
        if row["name"] not in employees:
            employees[row["name"]]=_v2_sum_from_aggregate(row,row["name"])
            old_group=int(row["report_group_no"] or 0)
            employee_meta[row["name"]]={"group_no":old_group,"group_name":gm.get(old_group,""),"is_leader":False}
    emp=[]
    for name,x in employees.items():
        z=_v2_sum_public(x);z.update(employee_meta.get(name,{}));emp.append(z)
    emp.sort(key=lambda x:(-x["profit"],-x["gmv"],x["name"]))
    group_numbers=[group_filter] if group_filter else list(range(1,9))
    grp=[]
    for i in group_numbers:
        z=_v2_sum_public(_v2_sum_from_aggregate(group_map.get(i),gm.get(i,"第%d组"%i)))
        z.update({"group_no":i,"group_name":gm.get(i,"第%d组"%i)});grp.append(z)

    status_counts={s:int(status_map[s]["report_count"] or 0) if s in status_map else 0 for s in ECOM_RECONCILE_STATES}
    report_total=sum(status_counts.values())
    requested_report_status=clean(request.args.get("report_status"),12) if request.endpoint=="v2_dashboard" else ""
    if requested_report_status and requested_report_status not in ECOM_RECONCILE_STATES:
        c.close();return jsonify(err="核账状态筛选不正确"),400
    report_detail_where=where
    report_detail_params=list(params)
    if requested_report_status:
        report_detail_where+=" and r.reconcile_status=?";report_detail_params.append(requested_report_status)
    report_filtered_total=int(c.execute("select count(*) n from ecom_v2_reports r where "+report_detail_where,
        report_detail_params).fetchone()["n"] or 0)
    acc_where="" if not group_filter else " where group_no=?"
    acc_params=[] if not group_filter else [group_filter]
    acc_summary=c.execute("select count(*) total,coalesce(sum(active),0) active_total from ecom_v2_accounts"+acc_where,
                          acc_params).fetchone()
    status_breakdown={s:0 for s in V2_ACCOUNT_STATUSES}
    for x in c.execute("select account_status,count(*) n from ecom_v2_accounts"+acc_where+
                       " group by account_status",acc_params).fetchall():
        status_breakdown[x["account_status"]]=int(x["n"] or 0)
    account_total=int(acc_summary["total"] or 0);active_account_total=int(acc_summary["active_total"] or 0)
    account_detail_clauses=[] if not group_filter else ["group_no=?"]
    account_detail_params=[] if not group_filter else [group_filter]
    requested_account_status=clean(request.args.get("account_status"),12) if request.endpoint=="v2_dashboard" else ""
    requested_account_keyword=clean(request.args.get("account_keyword"),80) if request.endpoint=="v2_dashboard" else ""
    if requested_account_status:
        if requested_account_status not in V2_ACCOUNT_STATUSES:
            c.close();return jsonify(err="账号状态筛选不正确"),400
        account_detail_clauses.append("account_status=?");account_detail_params.append(requested_account_status)
    if requested_account_keyword:
        escaped=requested_account_keyword.replace("\\","\\\\").replace("%","\\%").replace("_","\\_")
        like="%%%s%%"%escaped
        account_detail_clauses.append("(account_name like ? escape '\\' or owner_name like ? escape '\\' or platform like ? escape '\\')")
        account_detail_params.extend([like,like,like])
    account_detail_where=(" where "+" and ".join(account_detail_clauses)) if account_detail_clauses else ""
    account_filtered_total=int(c.execute("select count(*) n from ecom_v2_accounts"+account_detail_where,
        account_detail_params).fetchone()["n"] or 0)

    # 默认不返回全量日报/账号。页面需要明细时显式传 include，并受分页上限保护。
    include=set()
    if request.endpoint=="v2_dashboard":
        include={x.strip().lower() for x in (request.args.get("include") or "").split(",") if x.strip()}
    report_limit=_v2_page_arg("report_limit",50,200);report_offset=_v2_page_arg("report_offset",0,1000000)
    account_limit=_v2_page_arg("account_limit",50,200);account_offset=_v2_page_arg("account_offset",0,1000000)
    reports=[]
    if "reports" in include and report_limit:
        id_rows=c.execute("select r.id from ecom_v2_reports r where %s order by r.biz_date desc,r.group_no,r.employee_name limit ? offset ?"%report_detail_where,
                          report_detail_params+[report_limit,report_offset]).fetchall()
        reports=_v2_reports_batch(c,[x["id"] for x in id_rows])
    account_out=[]
    if "accounts" in include and account_limit:
        account_rows=c.execute("""select id,account_name,platform,group_no,owner_name,purchase_cost_cents,
            purchase_date,voucher_url,account_status,note,active,revision,updated from ecom_v2_accounts"""+
            account_detail_where+" order by active desc,group_no,owner_name,account_name limit ? offset ?",
            account_detail_params+[account_limit,account_offset]).fetchall()
        for x in account_rows:
            account_out.append({"id":x["id"],"account_name":x["account_name"],"platform":x["platform"],
                "group_no":x["group_no"],"group_name":gm.get(x["group_no"],""),"owner_name":x["owner_name"],
                "purchase_cost":_ecom_yuan(x["purchase_cost_cents"]),"purchase_date":x["purchase_date"],
                "voucher_url":x["voucher_url"],"account_status":x["account_status"],"note":x["note"],
                "active":bool(x["active"]),"revision":int(x["revision"] or 1),"updated":x["updated"]})

    submitted_rows=c.execute("select r.biz_date,r.employee_name from ecom_v2_reports r where %s"%where,params).fetchall()
    expected_names=[x["name"] for x in members]
    submitted_names=set(r["employee_name"] for r in submitted_rows)
    missing_names=[x for x in expected_names if x not in submitted_names]
    # 服务器仍使用 Python 3.6，不能使用 date.fromisoformat。
    start_date=datetime.datetime.strptime(start,"%Y-%m-%d").date()
    end_date=datetime.datetime.strptime(end,"%Y-%m-%d").date()
    calendar_days=[];cursor=start_date
    while cursor<=end_date:
        calendar_days.append(cursor.isoformat());cursor+=datetime.timedelta(days=1)
    trend_rows=_v2_aggregate_rows(c,where,params,"r.biz_date day","r.biz_date",True)
    trend_map={x["day"]:_v2_sum_from_aggregate(x,x["day"]) for x in trend_rows}
    trend=[]
    for day in calendar_days:
        point=_v2_sum_public(trend_map.get(day,_v2_sum_blank(day)))
        point["day"]=day;trend.append(point)
    submitted_keys={(r["biz_date"],r["employee_name"]) for r in submitted_rows if r["employee_name"] in expected_names}
    missing_entries=[];missing_person_days=0
    for day in calendar_days:
        for name in expected_names:
            if (day,name) not in submitted_keys:
                missing_person_days+=1
                if len(missing_entries)<200:missing_entries.append({"biz_date":day,"employee_name":name})
    expected_person_days=len(calendar_days)*len(expected_names)
    submission={"mode":"day" if start==end else "range","expected_count":len(expected_names),
        "submitted_count":len(set(expected_names)&submitted_names),"missing_count":len(missing_names),
        "missing_names":missing_names,"expected_person_days":expected_person_days,
        "submitted_person_days":expected_person_days-missing_person_days,"missing_person_days":missing_person_days,
        "missing_entries":missing_entries,"missing_entries_truncated":missing_person_days>len(missing_entries),
        "missing_entry_limit":200,"basis":"按自然日应填，当前未设置休息/请假豁免"}
    reports_meta={"included":"reports" in include,"total":report_filtered_total,"scope_total":report_total,
        "filter_status":requested_report_status,"limit":report_limit,
        "offset":report_offset,"returned":len(reports),"has_more":report_offset+len(reports)<report_filtered_total}
    accounts_meta={"included":"accounts" in include,"total":account_filtered_total,"scope_total":account_total,"limit":account_limit,
        "offset":account_offset,"returned":len(account_out),"has_more":account_offset+len(account_out)<account_filtered_total}
    reimbursement=c.execute("""select
        coalesce(sum(case when p.reimbursement_status='待报销' then p.cost_cents else 0 end),0) pending,
        coalesce(sum(case when p.reimbursement_status='已冲销' then 1 else 0 end),0) reversed_count
        from ecom_v2_purchases p join ecom_v2_reports r on r.id=p.report_id
        where p.active=1 and %s and r.reconcile_status='confirmed'"""%where,params).fetchone()
    freshness=c.execute("select coalesce(max(r.updated),0) latest_report,coalesce(max(r.reconciled_at),0) latest_reconciled from ecom_v2_reports r where %s"%where,params).fetchone()
    alerts={"pending_reports":status_counts["pending"],"rejected_reports":status_counts["rejected"],
        "missing_person_days":missing_person_days,"pending_reimbursement":_ecom_yuan(reimbursement["pending"]),
        "reversed_reimbursement_count":int(reimbursement["reversed_count"] or 0),
        "negative_groups":sum(1 for x in grp if x["report_count"]>0 and x["profit"]<0)}
    c.close()
    return jsonify(ok=True,start=start,end=end,scope_group=group_filter,me=me,company=_v2_sum_public(company),
        pending=_v2_sum_public(pending),rejected=_v2_sum_public(rejected),groups=grp,employees=emp,
        leaderboard=[x for x in emp if x["report_count"]>0][:10],reports=reports,
        accounts=account_out,reports_meta=reports_meta,accounts_meta=accounts_meta,
        account_total=account_total,active_account_total=active_account_total,
        account_status_breakdown=status_breakdown,status_counts=status_counts,
        submission=submission,trend=trend,alerts=alerts,
        freshness={"latest_report":int(freshness["latest_report"] or 0),
            "latest_reconciled":int(freshness["latest_reconciled"] or 0)},
        definitions={"gmv":"净GMV=人工上报支付GMV-退款金额，不等于实际回款","profit":"阶段贡献利润=净GMV-广告实际消耗-账号成本",
            "ad_roi":"广告投产=净GMV/广告实际消耗","input_roi":"综合投入产出比=净GMV/(广告实际消耗+账号成本)"})

@app.post("/ecom/v2/reconcile")
def v2_reconcile():
    me,err=_v2_guard(leader=True)
    if err:return err
    d=request.get_json(force=True,silent=True) or {}
    try:rid=int(d.get("id"))
    except Exception:rid=0
    try:expected_revision=int(d.get("expected_revision"))
    except Exception:return jsonify(err="核账版本缺失，请刷新日报后再操作"),400
    status=clean(d.get("status"),12);note=clean(d.get("note"),500)
    if status not in ("confirmed", "rejected"):return jsonify(err="核账状态不正确"),400
    if status=="rejected" and not note:return jsonify(err="退回必须填写原因"),400
    c=db();c.execute("begin immediate");before=_v2_report_dict(c,rid)
    if not before:c.close();return jsonify(err="日报不存在"),404
    if expected_revision != int(before["revision"] or 1):
        c.rollback();c.close();return jsonify(err="日报内容已更新，请重新打开并核对最新版"),409
    closed = _v2_closed_settlement(c, before["biz_date"], before["group_no"])
    if closed:
        c.rollback();c.close();return jsonify(
            err="该日报已进入第%d版结算，需老板重新打开结算后才能变更核账状态" % int(closed["version"] or 1)),409
    if me["role"]!="admin":
        if before["group_no"]!=me["group_no"]:c.close();return jsonify(err="无权操作其他小组日报"),403
        target_member=c.execute("select is_leader from ecom_v2_members where name=?",
                                (before["employee_name"],)).fetchone()
        if target_member and int(target_member["is_leader"] or 0):
            c.close();return jsonify(err="组长日报统一由老板核账，组长之间不能互审"),403
    if before["status"]=="rejected":
        c.close();return jsonify(err="该日报已退回，需员工修改后重新提交，不能直接核账"),409
    if before["status"]=="confirmed" and status=="confirmed":
        c.close();return jsonify(err="该日报已经核账，无需重复确认"),409
    if before["status"]=="confirmed" and status=="rejected" and any(
            x["reimbursement_status"]=="已报销" for x in before["purchases"]):
        c.rollback();c.close();return jsonify(err="该日报存在已报销买号费用，请先在报销中心撤回报销状态"),409
    now=int(time.time());actor=_ecom_actor()
    try:
        if status=="confirmed":
            # 兼容迁移前已经存在的多张 pending 重复账号：第一张可核账，
            # 后续日报在核账时被已核账成本拦住，不会继续重复入账。
            for purchase in before["purchases"]:
                account_key, platform_key = _v2_account_key(purchase["account_name"], purchase["platform"])
                conflict = c.execute("""select r.id from ecom_v2_purchases p
                    join ecom_v2_reports r on r.id=p.report_id
                    where p.account_key=? and p.platform_key=? and r.id<>?
                      and p.active=1 and r.reconcile_status='confirmed' limit 1""",
                    (account_key, platform_key, rid)).fetchone()
                if conflict:
                    raise ValueError("账号“%s”已有已核账买号成本，本日报不能重复入账" % purchase["account_name"])
            _v2_apply_report_accounts(c, before)
        elif before["status"]=="confirmed": _v2_rollback_report_accounts(c, rid)
    except ValueError as exc:
        c.rollback();c.close();return jsonify(err=str(exc)),409
    if status=="confirmed":
        q=c.execute("""update ecom_v2_reports set reconcile_status=?,reconcile_note=?,reconciled_by=?,
            reconciled_at=?,revision=revision+1,updated=? where id=? and revision=? and reconcile_status='pending'""",
            (status,note,actor,now,now,rid,expected_revision))
    else:
        q=c.execute("""update ecom_v2_reports set reconcile_status=?,reconcile_note=?,last_rejection_note=?,
            reconciled_by=?,reconciled_at=0,revision=revision+1,updated=?
            where id=? and revision=? and reconcile_status in ('pending','confirmed')""",
            (status,note,note,actor,now,rid,expected_revision))
    if q.rowcount != 1:
        c.rollback();c.close();return jsonify(err="日报状态已变化，请刷新后再操作"),409
    after=_v2_report_dict(c,rid)
    c.execute("insert into ecom_v2_audit(report_id,action,actor,before_json,after_json,ip,created) values(?,?,?,?,?,?,?)",
              (rid,"reconcile_%s"%status,actor,_ecom_safe_json(before),_ecom_safe_json(after),ipaddr(),now))
    c.commit();c.close();return jsonify(ok=True,report=after)

@app.post("/ecom/v2/account/save")
def v2_account_save():
    me,err=_v2_guard(leader=True)
    if err:return err
    d=request.get_json(force=True,silent=True) or {}
    try:aid=int(d.get("id"))
    except Exception:aid=0
    try: expected_revision=int(d.get("expected_revision"))
    except Exception:return jsonify(err="账号版本缺失，请刷新台账后再操作"),400
    if expected_revision < 1:return jsonify(err="账号版本不正确，请刷新台账后再操作"),400
    status=clean(d.get("account_status"),12);note=clean(d.get("note"),200)
    if status not in V2_ACCOUNT_STATUSES:return jsonify(err="账号状态不正确"),400
    c=db();c.execute("begin immediate")
    row=c.execute("select * from ecom_v2_accounts where id=?",(aid,)).fetchone()
    if not row:c.rollback();c.close();return jsonify(err="账号不存在"),404
    if me["role"]!="admin" and row["group_no"]!=me["group_no"]:c.rollback();c.close();return jsonify(err="无权管理其他小组账号"),403
    now=int(time.time());q=c.execute("""update ecom_v2_accounts set account_status=?,note=?,active=?,
        revision=revision+1,updated=? where id=? and revision=?""",
        (status,note,0 if status=="停用" else 1,now,aid,expected_revision))
    if q.rowcount != 1:
        c.rollback();c.close();return jsonify(err="账号状态已被他人更新，请刷新后重试"),409
    c.execute("insert into ecom_v2_account_history(account_id,old_status,new_status,changed_by,note,created) values(?,?,?,?,?,?)",
              (aid,row["account_status"],status,_ecom_actor(),note or "同状态确认/备注更新",now))
    new_revision=expected_revision+1
    c.execute("insert into ecom_v2_audit(action,actor,before_json,after_json,ip,created) values(?,?,?,?,?,?)",
              ("account_status",_ecom_actor(),_ecom_safe_json(dict(row)),
               _ecom_safe_json({"id":aid,"account_status":status,"note":note,"revision":new_revision}),ipaddr(),now))
    c.commit();c.close();return jsonify(ok=True,revision=new_revision)

@app.get("/ecom/v2/reimbursements")
def v2_reimbursements():
    me,err=_v2_guard(leader=True)
    if err:return err
    today=_ecom_now_date();start=clean(request.args.get("start"),10) or (today-datetime.timedelta(days=30)).isoformat()
    end=clean(request.args.get("end"),10) or today.isoformat()
    try:_ecom_validate_range(start,end)
    except ValueError as exc:return jsonify(err=str(exc)),400
    status=clean(request.args.get("status"),12)
    if status and status not in ECOM_REIMBURSEMENT_STATES:return jsonify(err="报销状态不正确"),400
    where=["r.biz_date between ? and ?","r.reconcile_status='confirmed'","p.active=1"];params=[start,end]
    if me["role"]!="admin":where.append("r.group_no=?");params.append(me["group_no"])
    totals_where_sql=" and ".join(where);totals_params=list(params)
    if status:where.append("p.reimbursement_status=?");params.append(status)
    where_sql=" and ".join(where)
    limit=_v2_page_arg("limit",100,200);offset=_v2_page_arg("offset",0,1000000)
    c=db()
    totals=c.execute("""select count(*) n,coalesce(sum(p.cost_cents),0) cost,
        coalesce(sum(case when p.reimbursement_status='已报销' then p.reimbursed_cents else 0 end),0) paid,
        coalesce(sum(case when p.reimbursement_status='待报销' then p.cost_cents else 0 end),0) pending,
        coalesce(sum(case when p.reimbursement_status='已冲销' then p.cost_cents else 0 end),0) reversed,
        coalesce(sum(case when p.reimbursement_status='已冲销' then 1 else 0 end),0) reversed_count
        from ecom_v2_purchases p join ecom_v2_reports r on r.id=p.report_id where %s"""%totals_where_sql,totals_params).fetchone()
    filtered_count=int(c.execute("""select count(*) n from ecom_v2_purchases p
        join ecom_v2_reports r on r.id=p.report_id where %s"""%where_sql,params).fetchone()["n"] or 0)
    rows=c.execute("""select p.id,p.report_id,p.account_name,p.platform,p.cost_cents,p.voucher_url,
        p.reimbursement_status,p.reimbursed_cents,p.reimbursement_revision,p.note,
        r.biz_date,r.group_no,r.employee_name,g.group_name
        from ecom_v2_purchases p join ecom_v2_reports r on r.id=p.report_id
        join ecom_v2_groups g on g.group_no=r.group_no where %s
        order by case p.reimbursement_status when '待报销' then 0 when '已报销' then 1 else 2 end,
        r.biz_date desc,p.id desc limit ? offset ?"""%where_sql,params+[limit,offset]).fetchall()
    events={}
    if rows:
        ids=[int(x["id"]) for x in rows];marks=",".join("?" for _ in ids)
        for x in c.execute("""select purchase_id,reimbursement_status,amount_cents,payment_ref,note,actor,created
            from ecom_v2_reimbursement_events where purchase_id in (%s) order by id desc"""%marks,ids).fetchall():
            events.setdefault(int(x["purchase_id"]),[]).append({"status":x["reimbursement_status"],
                "amount":_ecom_yuan(x["amount_cents"]),"payment_ref":x["payment_ref"],"note":x["note"],
                "actor":x["actor"],"created":x["created"]})
    out=[]
    for x in rows:
        out.append({"id":x["id"],"report_id":x["report_id"],"biz_date":x["biz_date"],
            "group_no":x["group_no"],"group_name":x["group_name"],"employee_name":x["employee_name"],
            "account_name":x["account_name"],"platform":x["platform"],"cost":_ecom_yuan(x["cost_cents"]),
            "voucher_url":x["voucher_url"],"status":x["reimbursement_status"],
            "reimbursed":_ecom_yuan(x["reimbursed_cents"]),"revision":int(x["reimbursement_revision"] or 1),
            "note":x["note"],"events":events.get(int(x["id"]),[])})
    c.close();return jsonify(ok=True,start=start,end=end,rows=out,summary={"count":int(totals["n"] or 0),
        "cost":_ecom_yuan(totals["cost"]),"paid":_ecom_yuan(totals["paid"]),
        "pending":_ecom_yuan(totals["pending"]),"reversed":_ecom_yuan(totals["reversed"]),
        "reversed_count":int(totals["reversed_count"] or 0)},meta={"filtered_count":filtered_count,"limit":limit,
        "offset":offset,"returned":len(out),"has_more":offset+len(out)<filtered_count},
        definitions={"reimbursement":"报销只记录资金返还状态，不再次扣减利润"})

@app.post("/ecom/v2/reimbursement/save")
def v2_reimbursement_save():
    me,err=_v2_guard(admin=True)
    if err:return err
    d=request.get_json(force=True,silent=True) or {}
    try:pid=int(d.get("purchase_id"))
    except Exception:pid=0
    try:expected_revision=int(d.get("expected_revision"))
    except Exception:return jsonify(err="报销版本缺失，请刷新后再操作"),400
    status=clean(d.get("status"),12);payment_ref=clean(d.get("payment_ref"),80);note=clean(d.get("note"),300)
    request_key=clean(d.get("request_key"),80)
    if status not in ECOM_REIMBURSEMENT_STATES:return jsonify(err="报销状态不正确"),400
    if len(request_key)<8:return jsonify(err="请求标识缺失，请刷新后再操作"),400
    c=db();c.execute("begin immediate")
    duplicate=c.execute("select purchase_id,reimbursement_status,amount_cents from ecom_v2_reimbursement_events where request_key=?",
                        (request_key,)).fetchone()
    if duplicate:
        if int(duplicate["purchase_id"] or 0)!=pid or duplicate["reimbursement_status"]!=status:
            c.rollback();c.close();return jsonify(err="请求标识已用于其他报销操作，请刷新后重试"),409
        current=c.execute("select reimbursement_revision from ecom_v2_purchases where id=?",(pid,)).fetchone()
        c.commit();c.close();return jsonify(ok=True,duplicate=True,status=duplicate["reimbursement_status"],
            reimbursed=_ecom_yuan(duplicate["amount_cents"]),revision=int(current["reimbursement_revision"] or 1) if current else 0)
    row=c.execute("""select p.*,r.biz_date,r.group_no,r.reconcile_status from ecom_v2_purchases p
        join ecom_v2_reports r on r.id=p.report_id where p.id=? and p.active=1""",(pid,)).fetchone()
    if not row:c.rollback();c.close();return jsonify(err="买号记录不存在"),404
    if expected_revision != int(row["reimbursement_revision"] or 1):
        c.rollback();c.close();return jsonify(err="报销状态已被他人更新，请刷新后重试"),409
    if row["reconcile_status"]!="confirmed":c.rollback();c.close();return jsonify(err="日报核账确认后才能办理报销"),409
    closed=_v2_closed_settlement(c,row["biz_date"],row["group_no"])
    if closed:c.rollback();c.close();return jsonify(err="该记录已进入结算，需重新打开结算后才能调整报销"),409
    current=row["reimbursement_status"]
    allowed={"待报销":("已报销","无需报销"),"无需报销":("待报销",),
             "已报销":("已冲销",),"已冲销":("待报销",)}
    if status not in allowed.get(current, ()):
        c.rollback();c.close();return jsonify(err="报销状态不能从“%s”直接变为“%s”"%(current,status)),409
    if status in ("已报销","已冲销") and len(payment_ref)<4:
        c.rollback();c.close();return jsonify(err="请填写付款或冲销参考号"),400
    if status in ("无需报销","已冲销","待报销") and len(note)<5:
        c.rollback();c.close();return jsonify(err="该状态调整必须填写至少5字原因"),400
    amount=int(row["cost_cents"] or 0) if status=="已报销" else 0
    now=int(time.time());before={"status":current,"amount":_ecom_yuan(row["reimbursed_cents"]),
        "revision":expected_revision}
    q=c.execute("""update ecom_v2_purchases set reimbursement_status=?,reimbursed_cents=?,
        reimbursement_revision=reimbursement_revision+1 where id=? and active=1 and reimbursement_revision=?""",
        (status,amount,pid,expected_revision))
    if q.rowcount!=1:c.rollback();c.close();return jsonify(err="报销状态已变化，请刷新后重试"),409
    c.execute("""insert into ecom_v2_reimbursement_events(purchase_id,report_id,reimbursement_status,
        amount_cents,payment_ref,note,actor,request_key,ip,created) values(?,?,?,?,?,?,?,?,?,?)""",
        (pid,row["report_id"],status,amount,payment_ref,note,_ecom_actor(),request_key,ipaddr(),now))
    after={"status":status,"amount":_ecom_yuan(amount),"payment_ref":payment_ref,"note":note,
        "revision":expected_revision+1,"request_key":request_key}
    c.execute("insert into ecom_v2_audit(report_id,action,actor,before_json,after_json,ip,created) values(?,?,?,?,?,?,?)",
        (row["report_id"],"reimbursement_%s"%status,_ecom_actor(),_ecom_safe_json(before),_ecom_safe_json(after),ipaddr(),now))
    c.commit();c.close();return jsonify(ok=True,status=status,reimbursed=_ecom_yuan(amount),revision=expected_revision+1)

def _v2_settlement_snapshot(c,start,end,group_no):
    where="r.biz_date between ? and ?";params=[start,end]
    if group_no:where+=" and r.group_no=?";params.append(group_no)
    status_rows=_v2_aggregate_rows(c,where,params,"r.reconcile_status status","r.reconcile_status")
    status_map={x["status"]:x for x in status_rows}
    company=_v2_sum_from_aggregate(status_map.get("confirmed"),"结算合计")
    employee_rows=_v2_aggregate_rows(c,where,params,"r.employee_name name,max(r.group_no) group_no","r.employee_name",True)
    employees=[]
    for x in employee_rows:
        item=_v2_sum_public(_v2_sum_from_aggregate(x,x["name"]));item["group_no"]=int(x["group_no"] or 0);employees.append(item)
    employees.sort(key=lambda x:(-x["profit"],-x["gmv"],x["name"]))
    group_rows=_v2_aggregate_rows(c,where,params,"r.group_no group_no","r.group_no",True)
    groups=[];gm=_v2_group_map(c)
    for x in group_rows:
        item=_v2_sum_public(_v2_sum_from_aggregate(x,gm.get(int(x["group_no"]),"")))
        item["group_no"]=int(x["group_no"]);groups.append(item)
    member_where="active=1";member_params=[]
    if group_no:member_where+=" and group_no=?";member_params.append(group_no)
    active_members=[x["name"] for x in c.execute(
        "select name from ecom_v2_members where "+member_where+" order by name",member_params).fetchall()]
    member_count=len(active_members)
    start_day=datetime.datetime.strptime(start,"%Y-%m-%d").date()
    end_day=datetime.datetime.strptime(end,"%Y-%m-%d").date()
    days=(end_day-start_day).days+1
    report_rows=c.execute("select r.biz_date,r.employee_name from ecom_v2_reports r where "+where,params).fetchall()
    active_set=set(active_members)
    submitted_keys=set((x["biz_date"],x["employee_name"]) for x in report_rows if x["employee_name"] in active_set)
    missing_entries=[]
    for offset in range(days):
        day=(start_day+datetime.timedelta(days=offset)).isoformat()
        for employee_name in active_members:
            if (day,employee_name) not in submitted_keys:
                missing_entries.append({"biz_date":day,"employee_name":employee_name})
    submitted=len(submitted_keys)
    reimbursement=c.execute("""select
        coalesce(sum(case when p.reimbursement_status='待报销' then p.cost_cents else 0 end),0) pending,
        coalesce(sum(case when p.reimbursement_status='已报销' then p.reimbursed_cents else 0 end),0) paid,
        coalesce(sum(case when p.reimbursement_status='已冲销' then p.cost_cents else 0 end),0) reversed,
        coalesce(sum(case when p.reimbursement_status='已冲销' then 1 else 0 end),0) reversed_count
        from ecom_v2_purchases p join ecom_v2_reports r on r.id=p.report_id
        where p.active=1 and %s and r.reconcile_status='confirmed'"""%where,params).fetchone()
    counts={s:int(status_map[s]["report_count"] or 0) if s in status_map else 0 for s in ECOM_RECONCILE_STATES}
    return {"start":start,"end":end,"group_no":group_no,"company":_v2_sum_public(company),
        "groups":groups,"employees":employees,"status_counts":counts,"active_member_count":member_count,
        "calendar_days":days,"expected_person_days":member_count*days,"submitted_person_days":submitted,
        "missing_person_days":len(missing_entries),"missing_entries":missing_entries,
        "pending_reimbursement":_ecom_yuan(reimbursement["pending"]),"paid_reimbursement":_ecom_yuan(reimbursement["paid"]),
        "reversed_reimbursement":_ecom_yuan(reimbursement["reversed"]),
        "reversed_reimbursement_count":int(reimbursement["reversed_count"] or 0),
        "definitions":{"gmv":"净GMV=支付GMV-退款","profit":"阶段贡献利润=净GMV-广告消耗-账号成本；不是公司净利润",
            "submission":"按当前启用成员和自然日计算，尚未扣除休假/轮休"}}

@app.get("/ecom/v2/settlement/preview")
def v2_settlement_preview():
    me,err=_v2_guard(admin=True)
    if err:return err
    start=clean(request.args.get("start"),10);end=clean(request.args.get("end"),10)
    try:group_no=int(request.args.get("group","0") or 0)
    except Exception:group_no=-1
    if group_no not in range(0,9):return jsonify(err="结算范围不正确"),400
    try:_ecom_validate_range(start,end)
    except ValueError as exc:return jsonify(err=str(exc)),400
    c=db();snapshot=_v2_settlement_snapshot(c,start,end,group_no);counts=snapshot["status_counts"]
    overlap=bool(c.execute("""select id from ecom_v2_settlements where status='closed'
        and not(end_date<? or start_date>?) and (group_no=0 or ?=0 or group_no=?) limit 1""",
        (start,end,group_no,group_no)).fetchone())
    c.close();blockers=[]
    if overlap:blockers.append("与现有已结算期间重叠")
    if counts["confirmed"]<=0:blockers.append("范围内没有已核账日报")
    if counts["pending"]:blockers.append("待核账%d份"%counts["pending"])
    if counts["rejected"]:blockers.append("已退回%d份"%counts["rejected"])
    if snapshot["pending_reimbursement"]>0:blockers.append("待报销%s元"%snapshot["pending_reimbursement"])
    if snapshot["reversed_reimbursement_count"]>0:blockers.append("已冲销待处理%d笔"%snapshot["reversed_reimbursement_count"])
    if snapshot["missing_person_days"]>0:blockers.append("漏报%d人日（可核实后带说明结算）"%snapshot["missing_person_days"])
    return jsonify(ok=True,snapshot=snapshot,blockers=blockers,ready=not blockers,
        ready_with_missing=bool(blockers and len(blockers)==1 and snapshot["missing_person_days"]>0 and not overlap))

@app.get("/ecom/v2/settlements")
def v2_settlements():
    me,err=_v2_guard(admin=True)
    if err:return err
    c=db();rows=c.execute("select * from ecom_v2_settlements order by created_at desc,id desc limit 100").fetchall();out=[]
    for x in rows:
        try:snapshot=json.loads(x["snapshot_json"])
        except Exception:snapshot={}
        out.append({"id":x["id"],"start":x["start_date"],"end":x["end_date"],"group_no":x["group_no"],
            "version":x["version"],"status":x["status"],"snapshot_hash":x["snapshot_hash"],"snapshot":snapshot,
            "close_note":x["close_note"],"created_by":x["created_by"],"created_at":x["created_at"],
            "reopened_by":x["reopened_by"],"reopened_at":x["reopened_at"],"reopen_reason":x["reopen_reason"]})
    c.close();return jsonify(ok=True,settlements=out)

@app.post("/ecom/v2/settlement/close")
def v2_settlement_close():
    me,err=_v2_guard(admin=True)
    if err:return err
    d=request.get_json(force=True,silent=True) or {};start=clean(d.get("start"),10);end=clean(d.get("end"),10)
    try:group_no=int(d.get("group_no",0) or 0)
    except Exception:group_no=-1
    note=clean(d.get("note"),300);allow_missing=_truthy(d.get("allow_missing"))
    if group_no not in range(0,9):return jsonify(err="结算范围不正确"),400
    try:_ecom_validate_range(start,end)
    except ValueError as exc:return jsonify(err=str(exc)),400
    c=db();c.execute("begin immediate")
    overlap=c.execute("""select id from ecom_v2_settlements where status='closed'
        and not(end_date<? or start_date>?) and (group_no=0 or ?=0 or group_no=?) limit 1""",
        (start,end,group_no,group_no)).fetchone()
    if overlap:c.rollback();c.close();return jsonify(err="该日期范围与现有已结算期间重叠，请先重新打开原结算"),409
    snapshot=_v2_settlement_snapshot(c,start,end,group_no);counts=snapshot["status_counts"]
    if counts["confirmed"]<=0:c.rollback();c.close();return jsonify(err="范围内没有已核账日报，不能结算"),409
    if counts["pending"] or counts["rejected"]:
        c.rollback();c.close();return jsonify(err="仍有待核账或已退回日报，处理完后才能结算"),409
    if snapshot["pending_reimbursement"]>0:
        c.rollback();c.close();return jsonify(err="仍有待报销买号费用，处理完后才能结算"),409
    if snapshot["reversed_reimbursement_count"]>0:
        c.rollback();c.close();return jsonify(err="仍有已冲销买号费用；请重新标记为待报销或无需报销后再结算"),409
    if snapshot["missing_person_days"]>0 and (not allow_missing or len(note)<5):
        c.rollback();c.close();return jsonify(err="存在漏报人天；确认属于休假/轮休等例外时，请勾选允许漏报并填写至少5字说明"),409
    vrow=c.execute("select coalesce(max(version),0)+1 v from ecom_v2_settlements where start_date=? and end_date=? and group_no=?",
                   (start,end,group_no)).fetchone();version=int(vrow["v"] or 1)
    snapshot_text=json.dumps(snapshot,ensure_ascii=False,sort_keys=True,separators=(",",":"))
    snapshot_hash=hashlib.sha256(snapshot_text.encode("utf-8")).hexdigest();now=int(time.time())
    q=c.execute("""insert into ecom_v2_settlements(start_date,end_date,group_no,version,status,snapshot_json,
        snapshot_hash,close_note,created_by,created_at) values(?,?,?,?,'closed',?,?,?,?,?)""",
        (start,end,group_no,version,snapshot_text,snapshot_hash,note,_ecom_actor(),now))
    c.execute("insert into ecom_v2_audit(action,actor,before_json,after_json,ip,created) values(?,?,?,?,?,?)",
        ("settlement_close",_ecom_actor(),"",_ecom_safe_json({"id":q.lastrowid,"start":start,"end":end,
         "group_no":group_no,"version":version,"snapshot_hash":snapshot_hash}),ipaddr(),now))
    c.commit();c.close();return jsonify(ok=True,id=q.lastrowid,version=version,snapshot_hash=snapshot_hash,snapshot=snapshot)

@app.post("/ecom/v2/settlement/reopen")
def v2_settlement_reopen():
    me,err=_v2_guard(admin=True)
    if err:return err
    d=request.get_json(force=True,silent=True) or {}
    try:sid=int(d.get("id"))
    except Exception:sid=0
    reason=clean(d.get("reason"),300)
    if len(reason)<5:return jsonify(err="重新打开结算必须填写至少5字原因"),400
    c=db();c.execute("begin immediate");row=c.execute("select * from ecom_v2_settlements where id=?",(sid,)).fetchone()
    if not row:c.rollback();c.close();return jsonify(err="结算记录不存在"),404
    if row["status"]!="closed":c.rollback();c.close();return jsonify(err="该结算已重新打开"),409
    now=int(time.time());c.execute("""update ecom_v2_settlements set status='reopened',reopened_by=?,
        reopened_at=?,reopen_reason=? where id=? and status='closed'""",(_ecom_actor(),now,reason,sid))
    c.execute("insert into ecom_v2_audit(action,actor,before_json,after_json,ip,created) values(?,?,?,?,?,?)",
        ("settlement_reopen",_ecom_actor(),_ecom_safe_json(dict(row)),_ecom_safe_json({"reason":reason}),ipaddr(),now))
    c.commit();c.close();return jsonify(ok=True)

@app.get("/ecom/v2/export/employees.csv")
def v2_export_employees():
    me,err=_v2_guard(leader=True)
    if err:return err
    # 复用同一聚合接口的底层数据会让下载和看板保持同一筛选口径；这里直接调用视图函数并解析响应。
    resp=v2_dashboard()
    if isinstance(resp, tuple): return resp
    payload=resp.get_json() if hasattr(resp,"get_json") else None
    if not payload:return jsonify(err="导出失败"),500
    lines=["员工,组别,支付GMV,退款,净GMV,广告消耗,账号成本,充值资金流,阶段贡献利润,已核账日报数,广告投产,综合投入产出比,买号数量"]
    for x in payload["employees"]:
        if not x["report_count"]: continue
        vals=[x["name"],x.get("group_name","")] + [x["gross_gmv"],x["refund"],x["gmv"],x["ad_spend"],
            x["account_cost"],x["recharge_total"],x["profit"],x["report_count"],
            "" if x["ad_roi"] is None else x["ad_roi"],"" if x["input_roi"] is None else x["input_roi"],x["bought_accounts"]]
        lines.append(",".join('"%s"'%str(v).replace('"','""') for v in vals))
    data="\ufeff"+"\n".join(lines)
    return Response(data,mimetype="text/csv",headers={"Content-Disposition":"attachment; filename=zhouge_employee_performance.csv"})

if SCHEMA_MIGRATION_MODE:
    _v2_init()
else:
    _v2_require_schema()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8312)
