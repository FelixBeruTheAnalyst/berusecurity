import os
import sqlite3
import threading
import hashlib
import re
import math
import socket
from queue import Queue
from datetime import datetime
from flask import Flask, render_template, request, jsonify, redirect
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from groq import Groq

DB_PATH    = "/tmp/berusecurity.db"
REPORT_DIR = "/tmp/beru_reports"
MODEL      = "llama-3.3-70b-versatile"

app            = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "beru2026secretkey")
ADMIN_USER     = os.environ.get("ADMIN_USER", "felix")
ADMIN_PASS     = os.environ.get("ADMIN_PASS", "BeruSecurity2026!")
client         = Groq(api_key=os.environ.get("GROQ_API_KEY",""))

login_manager  = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login_page"

class User(UserMixin):
    def __init__(self, id): self.id = id

@login_manager.user_loader
def load_user(uid):
    return User(uid) if uid == ADMIN_USER else None

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS scans(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, scan_type TEXT,
        target TEXT, total_found INTEGER,
        verdict TEXT, client_id INTEGER DEFAULT 0)""")
    c.execute("""CREATE TABLE IF NOT EXISTS findings(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER, timestamp TEXT,
        risk_level TEXT, category TEXT,
        target TEXT, description TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS attackers(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT UNIQUE, first_seen TEXT,
        last_seen TEXT, attack_count INTEGER DEFAULT 1,
        attack_types TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS clients(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL, company TEXT,
        email TEXT, phone TEXT, notes TEXT,
        created_at TEXT, status TEXT DEFAULT 'active')""")
    conn.commit()
    conn.close()

init_db()

def db_query(sql, params=()):
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    c.execute(sql, params)
    rows = c.fetchall()
    conn.close()
    return rows

def db_exec(sql, params=()):
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    c.execute(sql, params)
    lid  = c.lastrowid
    conn.commit()
    conn.close()
    return lid

SYSTEM = """You are BeruSecurity AI, expert cybersecurity analyst.
Give clear, concise, actionable security advice. Max 3 paragraphs."""

def ask_ai(prompt, max_tokens=600):
    try:
        resp = client.chat.completions.create(
            model=MODEL, max_tokens=max_tokens,
            messages=[
                {"role":"system","content":SYSTEM},
                {"role":"user",  "content":prompt}
            ]
        )
        return resp.choices[0].message.content
    except Exception as e:
        return "AI unavailable: " + str(e)

RISK_PORTS = {
    21: ("CRITICAL","FTP",        "Plain text passwords — disable, use SFTP"),
    22: ("INFO",    "SSH",        "Secure remote access — ensure key auth"),
    23: ("CRITICAL","Telnet",     "Unencrypted — disable immediately"),
    25: ("HIGH",    "SMTP",       "Email server exposed"),
    53: ("MEDIUM",  "DNS",        "Check for zone transfer vulnerability"),
    80: ("LOW",     "HTTP",       "Web server — ensure HTTPS redirect"),
    135:("MEDIUM",  "RPC",        "Windows RPC — restrict to internal"),
    139:("HIGH",    "NetBIOS",    "Windows sharing — common attack vector"),
    443:("INFO",    "HTTPS",      "Secure web — verify SSL certificate"),
    445:("CRITICAL","SMB",        "Ransomware entry point — block from internet"),
    3306:("CRITICAL","MySQL",     "Database exposed — serious risk"),
    3389:("HIGH",   "RDP",        "Remote Desktop — brute force target"),
    5432:("HIGH",   "PostgreSQL", "Database exposed — restrict access"),
    6379:("CRITICAL","Redis",     "No auth by default — full takeover risk"),
    8080:("LOW",    "HTTP-Alt",   "Dev server — check if production"),
}

def port_scan(target):
    open_ports = []
    queue = Queue()
    lock  = threading.Lock()
    for p in range(1,1025): queue.put(p)
    def worker():
        while not queue.empty():
            try:
                port = queue.get_nowait()
                s    = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                if s.connect_ex((target, port)) == 0:
                    with lock: open_ports.append(port)
                s.close()
            except: pass
            queue.task_done()
    threads = [threading.Thread(target=worker) for _ in range(100)]
    for t in threads: t.daemon=True; t.start()
    for t in threads: t.join()
    return sorted(open_ports)

COMMON = {"password","123456","qwerty","abc123","letmein",
          "admin","felix123","admin123","welcome","password123"}

def analyze_password(pwd):
    score, issues, bonuses = 0, [], []
    length = len(pwd)
    if length < 8:    issues.append("Too short"); score += 5
    elif length < 12: score += 25; bonuses.append("Decent length")
    elif length < 16: score += 35; bonuses.append("Good length")
    else:             score += 45; bonuses.append("Excellent length")
    hl = bool(re.search(r'[a-z]',pwd))
    hu = bool(re.search(r'[A-Z]',pwd))
    hd = bool(re.search(r'[0-9]',pwd))
    hs = bool(re.search(r'[^a-zA-Z0-9]',pwd))
    if hl: score += 5
    else:  issues.append("No lowercase letters")
    if hu: score += 10; bonuses.append("Has uppercase")
    else:  issues.append("No uppercase letters")
    if hd: score += 10; bonuses.append("Has numbers")
    else:  issues.append("No numbers")
    if hs: score += 20; bonuses.append("Has special characters")
    else:  issues.append("No special characters")
    if pwd.lower() in COMMON: issues.append("Common password"); score = min(score,10)
    if re.search(r'(123|abc|qwe)',pwd.lower()): issues.append("Sequential pattern"); score -= 10
    score   = max(0, min(score, 100))
    cs      = (26 if hl else 0)+(26 if hu else 0)+(10 if hd else 0)+(32 if hs else 0)
    entropy = math.log2(cs**length) if cs else 0
    secs    = (2**entropy)/1_000_000_000
    if secs < 1:          ct = "< 1 second"
    elif secs < 3600:     ct = str(int(secs/60))+" minutes"
    elif secs < 86400:    ct = str(int(secs/3600))+" hours"
    elif secs < 31536000: ct = str(int(secs/86400))+" days"
    else:
        y = secs/31536000
        ct = str(int(y))+" years" if y < 1e6 else str(int(y/1e6))+"M years"
    if score >= 80:   strength = "STRONG"
    elif score >= 60: strength = "MODERATE"
    elif score >= 35: strength = "WEAK"
    else:             strength = "VERY WEAK"
    breach = 0
    try:
        import urllib.request
        sha1   = hashlib.sha1(pwd.encode()).hexdigest().upper()
        pre,sf = sha1[:5],sha1[5:]
        req    = urllib.request.Request(
            "https://api.pwnedpasswords.com/range/"+pre,
            headers={"User-Agent":"BeruSecurity"})
        resp   = urllib.request.urlopen(req,timeout=5).read().decode()
        breach = next((int(l.split(":")[1]) for l in resp.splitlines() if l.split(":")[0]==sf),0)
    except: breach = -1
    return {"score":score,"strength":strength,"length":length,
            "entropy":round(entropy,1),"crack_time":ct,
            "issues":issues,"bonuses":bonuses,"breach":breach,
            "has_lower":hl,"has_upper":hu,"has_digit":hd,"has_symbol":hs}

def save_scan(scan_type, target, findings, verdict, client_id=0):
    ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sid = db_exec(
        "INSERT INTO scans(timestamp,scan_type,target,total_found,verdict,client_id) VALUES(?,?,?,?,?,?)",
        (ts, scan_type, target, len(findings), verdict, client_id)
    )
    for risk,cat,desc in findings:
        db_exec(
            "INSERT INTO findings(scan_id,timestamp,risk_level,category,target,description) VALUES(?,?,?,?,?,?)",
            (sid, ts, risk, cat, target, desc)
        )
    return sid

# ══════════════════════════════════════════════════════════
# ROUTES
# ══════════════════════════════════════════════════════════

@app.route("/login", methods=["GET","POST"])
def login_page():
    error = ""
    if request.method == "POST":
        u = request.form.get("username","")
        p = request.form.get("password","")
        if u == ADMIN_USER and p == ADMIN_PASS:
            login_user(User(u))
            return redirect("/")
        error = "Invalid credentials"
    return """<!DOCTYPE html><html><head><title>BeruSecurity Login</title>
<style>*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',sans-serif;background:#0b0d12;display:flex;
     align-items:center;justify-content:center;min-height:100vh}
.box{background:#141820;border:1px solid #1e2a3a;border-radius:14px;
     padding:48px 40px;width:380px;text-align:center}
.logo{font-size:22px;font-weight:800;color:#22A39F;letter-spacing:2px;margin-bottom:6px}
.sub{font-size:12px;color:#7d8590;margin-bottom:32px}
input{width:100%;background:#0b0d12;border:1px solid #1e2a3a;border-radius:8px;
      color:#e6edf3;padding:12px 14px;font-size:13px;outline:none;margin-bottom:14px;display:block}
input:focus{border-color:#22A39F}
button{width:100%;background:#22A39F;color:#0b0d12;border:none;padding:12px;
       border-radius:8px;font-size:14px;font-weight:700;cursor:pointer}
.err{color:#ff4444;font-size:12px;margin-bottom:14px;background:#200d0d;
     padding:8px;border-radius:6px;border:1px solid #ff4444}
.foot{font-size:11px;color:#4a5568;margin-top:20px}
</style></head><body><div class="box">
<div class="logo">🔐 BeruSecurity</div>
<div class="sub">AI-Powered Security Platform</div>""" + \
("<div class='err'>"+error+"</div>" if error else "") + \
"""<form method="POST">
<input type="text" name="username" placeholder="Username" required>
<input type="password" name="password" placeholder="Password" required>
<button type="submit">Login →</button>
</form>
<div class="foot">BeruSecurity v1.0 — Built by Felix</div>
</div></body></html>"""

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/login")

@app.route("/")
@login_required
def index():
    total  = db_query("SELECT COUNT(*) FROM scans")[0][0]
    crit   = db_query("SELECT COUNT(*) FROM findings WHERE risk_level='CRITICAL'")[0][0]
    high   = db_query("SELECT COUNT(*) FROM findings WHERE risk_level='HIGH'")[0][0]
    atk    = db_query("SELECT COUNT(*) FROM attackers")[0][0]
    recent = db_query("SELECT timestamp,scan_type,target,total_found,verdict FROM scans ORDER BY timestamp DESC LIMIT 5")
    return render_template("index.html", total=total, crit=crit, high=high, atk=atk, recent=recent)

@app.route("/scan", methods=["GET","POST"])
@login_required
def scan():
    if request.method == "POST":
        target    = request.form.get("target","").strip()
        client_id = int(request.form.get("client_id", 0))
        if not target:
            return jsonify({"error":"No target provided"})
        try:
            open_ports = port_scan(target)
            findings   = []
            results    = []
            for port in open_ports:
                r,svc,desc = RISK_PORTS.get(port,("UNKNOWN","Unknown","Research manually"))
                findings.append((r, svc, "Port "+str(port)+" open — "+desc))
                results.append({"port":port,"risk":r,"service":svc,"description":desc})
            verdict = "CLEAN"
            if findings:
                risks   = [f[0] for f in findings]
                verdict = ("CRITICAL" if "CRITICAL" in risks else
                          "HIGH"     if "HIGH"     in risks else
                          "MEDIUM"   if "MEDIUM"   in risks else "LOW")
            save_scan("PORT_SCAN", target, findings, verdict, client_id)
            ai_note = ask_ai(
                "Analyze port scan of "+target+":\n"+
                "\n".join("Port "+str(r["port"])+" "+r["service"]+" ["+r["risk"]+"]" for r in results)+
                "\n2 sentence assessment and most important action."
            ) if results else "No open ports found. Target appears clean."
            return jsonify({"target":target,"ports":results,"verdict":verdict,"ai":ai_note})
        except Exception as e:
            return jsonify({"error":str(e)})
    all_clients = db_query("SELECT id,name,company FROM clients ORDER BY name")
    return render_template("scan.html", all_clients=all_clients)

@app.route("/password", methods=["GET","POST"])
@login_required
def password():
    if request.method == "POST":
        pwd = request.form.get("password","")
        if not pwd:
            return jsonify({"error":"No password provided"})
        result  = analyze_password(pwd)
        finding = []
        if result["score"] < 50:
            finding = [("CRITICAL","WEAK_PASSWORD",
                       "Score "+str(result["score"])+"/100: "+"; ".join(result["issues"]))]
        save_scan("PASSWORD", pwd[:3]+"***", finding,
                  "CRITICAL" if result["score"]<35 else result["strength"])
        result["ai"] = ask_ai(
            "Password score "+str(result["score"])+"/100, strength "+result["strength"]+
            ", crack time "+result["crack_time"]+
            ", issues: "+", ".join(result["issues"])+". 2 sentences of advice."
        )
        return jsonify(result)
    return render_template("password.html")

@app.route("/dashboard")
@login_required
def dashboard():
    stats = {
        "scans":    db_query("SELECT COUNT(*) FROM scans")[0][0],
        "findings": db_query("SELECT COUNT(*) FROM findings")[0][0],
        "critical": db_query("SELECT COUNT(*) FROM findings WHERE risk_level='CRITICAL'")[0][0],
        "high":     db_query("SELECT COUNT(*) FROM findings WHERE risk_level='HIGH'")[0][0],
    }
    by_risk     = db_query("SELECT risk_level,COUNT(*) FROM findings GROUP BY risk_level ORDER BY COUNT(*) DESC")
    by_type     = db_query("SELECT scan_type,COUNT(*) FROM scans GROUP BY scan_type")
    top_targets = db_query("SELECT target,COUNT(*) FROM findings GROUP BY target ORDER BY COUNT(*) DESC LIMIT 5")
    attackers   = db_query("SELECT ip_address,attack_count,first_seen,last_seen FROM attackers ORDER BY attack_count DESC")
    findings    = db_query("SELECT timestamp,risk_level,category,target,description FROM findings WHERE risk_level IN ('CRITICAL','HIGH') ORDER BY timestamp DESC LIMIT 10")
    scans       = db_query("SELECT timestamp,scan_type,target,total_found,verdict FROM scans ORDER BY timestamp DESC LIMIT 10")
    return render_template("dashboard.html", stats=stats, by_risk=by_risk,
        by_type=by_type, top_targets=top_targets, attackers=attackers,
        findings=findings, scans=scans)

@app.route("/ai-chat", methods=["GET","POST"])
@login_required
def ai_chat():
    if request.method == "POST":
        data    = request.get_json()
        history = data.get("history",[])
        try:
            msgs = [{"role":"system","content":SYSTEM}] + history
            resp = client.chat.completions.create(model=MODEL, max_tokens=600, messages=msgs)
            return jsonify({"reply": resp.choices[0].message.content})
        except Exception as e:
            return jsonify({"reply":"AI error: "+str(e)})
    ctx_findings = db_query(
        "SELECT risk_level,category,target,description FROM findings "
        "WHERE risk_level IN ('CRITICAL','HIGH') "
        "ORDER BY CASE risk_level WHEN 'CRITICAL' THEN 0 ELSE 1 END LIMIT 6"
    )
    ctx     = "BeruSecurity context:\n"
    ctx    += "\n".join("["+r+"] "+c+" on "+t+": "+d for r,c,t,d in ctx_findings)
    ctx    += "\n\nGreet Felix, summarize in 2 sentences, ask what to focus on."
    opening = ask_ai(ctx)
    return render_template("chat.html", opening=opening)

@app.route("/report")
@login_required
def report():
    findings  = db_query(
        "SELECT risk_level,category,target,description FROM findings ORDER BY "
        "CASE risk_level WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END")
    scans     = db_query("SELECT timestamp,scan_type,target,total_found,verdict FROM scans ORDER BY timestamp DESC LIMIT 8")
    attackers = db_query("SELECT ip_address,attack_count,first_seen,last_seen FROM attackers")
    return render_template("report.html", findings=findings, scans=scans,
        attackers=attackers, generated=datetime.now().strftime("%B %d, %Y %H:%M"))

@app.route("/clients")
@login_required
def clients():
    all_clients = db_query("SELECT id,name,company,email,status,created_at FROM clients ORDER BY created_at DESC")
    return render_template("clients.html", clients=all_clients)

@app.route("/clients/add", methods=["GET","POST"])
@login_required
def add_client():
    if request.method == "POST":
        name    = request.form.get("name","").strip()
        company = request.form.get("company","").strip()
        email   = request.form.get("email","").strip()
        phone   = request.form.get("phone","").strip()
        notes   = request.form.get("notes","").strip()
        if name:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            db_exec(
                "INSERT INTO clients(name,company,email,phone,notes,created_at,status) VALUES(?,?,?,?,?,?,'active')",
                (name, company, email, phone, notes, ts)
            )
            return redirect("/clients")
    return render_template("add_client.html")

@app.route("/clients/<int:client_id>")
@login_required
def client_detail(client_id):
    cl = db_query("SELECT id,name,company,email,phone,notes,status,created_at FROM clients WHERE id=?", (client_id,))
    if not cl: return redirect("/clients")
    cl       = cl[0]
    scans    = db_query("SELECT timestamp,scan_type,target,total_found,verdict FROM scans WHERE client_id=? ORDER BY timestamp DESC LIMIT 10", (client_id,))
    findings = db_query(
        "SELECT f.timestamp,f.risk_level,f.category,f.target,f.description "
        "FROM findings f JOIN scans s ON f.scan_id=s.id "
        "WHERE s.client_id=? AND f.risk_level IN ('CRITICAL','HIGH') ORDER BY f.timestamp DESC LIMIT 10",
        (client_id,))
    stats      = {"scans":len(scans),"critical":sum(1 for f in findings if f[1]=="CRITICAL"),"high":sum(1 for f in findings if f[1]=="HIGH")}
    ai_summary = ask_ai("Client: "+cl[1]+" ("+str(cl[2])+")\nFindings:\n"+"\n".join("["+f[1]+"] "+f[2]+" on "+f[3] for f in findings[:5])+"\n2-sentence security summary.") if findings else "No critical findings yet. Run a scan to assess their security posture."
    return render_template("client_detail.html", client=cl, scans=scans, findings=findings, stats=stats, ai_summary=ai_summary)

@app.route("/clients/<int:client_id>/delete", methods=["POST"])
@login_required
def delete_client(client_id):
    db_exec("DELETE FROM clients WHERE id=?", (client_id,))
    return redirect("/clients")

@app.route("/pricing")
def pricing():
    return render_template("pricing.html")

if __name__ == "__main__":
    print()
    print("  ================================================")
    print("   BERUSECURITY WEB APP v1.0")
    print("   http://localhost:5000")
    print("  ================================================")
    print()
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
