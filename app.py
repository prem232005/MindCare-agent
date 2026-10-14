"""MindCare Agent - AI agent for mental health screening and support (Flask + SQLite)."""
import json, os, re, sqlite3, urllib.request
from datetime import datetime
from functools import wraps
from flask import Flask, g, jsonify, request, send_from_directory
from itsdangerous import BadSignature, URLSafeTimedSerializer
from werkzeug.security import check_password_hash, generate_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
FRONT = os.path.join(BASE, "..", "frontend")
DB = os.path.join(BASE, "mindcare.db")
app = Flask(__name__, static_folder=FRONT, static_url_path="")
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-secret-in-production")
signer = URLSafeTimedSerializer(app.config["SECRET_KEY"])

# ---------------- Screening instruments ----------------
OPTS = ["Not at all", "Several days", "More than half the days", "Nearly every day"]
PHQ9 = ["Little interest or pleasure in doing things", "Feeling down, depressed, or hopeless",
        "Trouble falling or staying asleep, or sleeping too much", "Feeling tired or having little energy",
        "Poor appetite or overeating", "Feeling bad about yourself, or that you are a failure",
        "Trouble concentrating on things, such as reading or watching TV",
        "Moving or speaking so slowly that others noticed, or being unusually restless",
        "Thoughts that you would be better off dead, or of hurting yourself"]
GAD7 = ["Feeling nervous, anxious, or on edge", "Not being able to stop or control worrying",
        "Worrying too much about different things", "Trouble relaxing", "Being so restless that it is hard to sit still",
        "Becoming easily annoyed or irritable", "Feeling afraid, as if something awful might happen"]
TESTS = {"PHQ9": {"name": "Depression screen (PHQ-9)", "items": PHQ9,
                  "bands": [(4, "Minimal"), (9, "Mild"), (14, "Moderate"), (19, "Moderately severe"), (27, "Severe")]},
         "GAD7": {"name": "Anxiety screen (GAD-7)", "items": GAD7,
                  "bands": [(4, "Minimal"), (9, "Mild"), (14, "Moderate"), (21, "Severe")]}}
ADVICE = {"Minimal": "Your answers suggest few symptoms. Keep up routines that support you: sleep, movement, and time with people you trust.",
          "Mild": "Mild symptoms. Try daily check-ins, regular sleep, light exercise and the coping tools in the chat. Re-screen in 2 weeks.",
          "Moderate": "Moderate symptoms. Consider talking to a counsellor or doctor, and use the coping tools while you arrange support.",
          "Moderately severe": "Symptoms are significant. Please book an appointment with a mental health professional soon.",
          "Severe": "Symptoms are severe. Please contact a mental health professional or helpline today. You do not have to handle this alone."}
HELPLINES = [{"name": "Tele-MANAS (India, 24x7, free)", "number": "14416 or 1800-891-4416"},
             {"name": "KIRAN Mental Health Helpline (India)", "number": "1800-599-0019"},
             {"name": "Emergency services (India)", "number": "112"}]
DISCLAIMER = "This tool is a screening aid, not a diagnosis. It cannot replace a qualified professional."

# ---------------- Database ----------------
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB); g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d: d.close()

def init_db():
    c = sqlite3.connect(DB)
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE, pw TEXT, role TEXT DEFAULT 'user', created TEXT);
    CREATE TABLE IF NOT EXISTS screenings(id INTEGER PRIMARY KEY, uid INTEGER, test TEXT, score INTEGER, severity TEXT, crisis INTEGER, created TEXT);
    CREATE TABLE IF NOT EXISTS moods(id INTEGER PRIMARY KEY, uid INTEGER, mood INTEGER, note TEXT, created TEXT);
    CREATE TABLE IF NOT EXISTS chats(id INTEGER PRIMARY KEY, uid INTEGER, role TEXT, text TEXT, created TEXT);
    """)
    for name, email, pw, role in [("Demo User", "user@mindcare.com", "User@123", "user"),
                                  ("Admin", "admin@mindcare.com", "Admin@123", "admin")]:
        if not c.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
            c.execute("INSERT INTO users(name,email,pw,role,created) VALUES(?,?,?,?,?)",
                      (name, email, generate_password_hash(pw), role, now()))
    c.commit(); c.close()

def now(): return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# ---------------- Auth ----------------
def auth(role=None):
    def deco(f):
        @wraps(f)
        def wrap(*a, **k):
            tok = request.headers.get("Authorization", "").replace("Bearer ", "")
            try: uid = signer.loads(tok, max_age=60 * 60 * 24 * 7)
            except BadSignature: return jsonify(error="Please log in again."), 401
            u = db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
            if not u: return jsonify(error="Account not found."), 401
            if role and u["role"] != role: return jsonify(error="Admin access required."), 403
            g.user = u
            return f(*a, **k)
        return wrap
    return deco

def user_json(u): return {"id": u["id"], "name": u["name"], "email": u["email"], "role": u["role"]}

@app.post("/api/register")
def register():
    d = request.get_json(force=True)
    name, email, pw = d.get("name", "").strip(), d.get("email", "").strip().lower(), d.get("password", "")
    if not name or not re.match(r"[^@\s]+@[^@\s]+\.[^@\s]+$", email) or len(pw) < 6:
        return jsonify(error="Enter a name, a valid email and a password of at least 6 characters."), 400
    try:
        db().execute("INSERT INTO users(name,email,pw,created) VALUES(?,?,?,?)", (name, email, generate_password_hash(pw), now()))
        db().commit()
    except sqlite3.IntegrityError:
        return jsonify(error="This email is already registered."), 409
    return login()

@app.post("/api/login")
def login():
    d = request.get_json(force=True)
    u = db().execute("SELECT * FROM users WHERE email=?", (d.get("email", "").strip().lower(),)).fetchone()
    if not u or not check_password_hash(u["pw"], d.get("password", "")):
        return jsonify(error="Email or password is incorrect."), 401
    return jsonify(token=signer.dumps(u["id"]), user=user_json(u))

@app.get("/api/me")
@auth()
def me(): return jsonify(user_json(g.user))

# ---------------- Screening ----------------
@app.get("/api/tests")
@auth()
def tests():
    return jsonify({k: {"name": v["name"], "items": v["items"]} for k, v in TESTS.items()} | {"options": OPTS})

@app.post("/api/screening")
@auth()
def screening():
    d = request.get_json(force=True); t = TESTS.get(d.get("test")); ans = d.get("answers", [])
    if not t or len(ans) != len(t["items"]) or any(a not in (0, 1, 2, 3) for a in ans):
        return jsonify(error="Answer every question."), 400
    score = sum(ans); sev = next(l for m, l in t["bands"] if score <= m)
    crisis = int(d["test"] == "PHQ9" and ans[8] > 0)
    db().execute("INSERT INTO screenings(uid,test,score,severity,crisis,created) VALUES(?,?,?,?,?,?)",
                 (g.user["id"], d["test"], score, sev, crisis, now())); db().commit()
    return jsonify(score=score, max=len(ans) * 3, severity=sev, advice=ADVICE[sev], crisis=bool(crisis),
                   helplines=HELPLINES if crisis or sev in ("Moderately severe", "Severe") else [], disclaimer=DISCLAIMER)

@app.get("/api/screenings")
@auth()
def screenings():
    r = db().execute("SELECT test,score,severity,crisis,created FROM screenings WHERE uid=? ORDER BY id DESC LIMIT 30", (g.user["id"],))
    return jsonify([dict(x) for x in r])

# ---------------- Mood ----------------
@app.post("/api/mood")
@auth()
def add_mood():
    d = request.get_json(force=True); m = d.get("mood")
    if m not in (1, 2, 3, 4, 5): return jsonify(error="Pick a mood from 1 to 5."), 400
    db().execute("INSERT INTO moods(uid,mood,note,created) VALUES(?,?,?,?)", (g.user["id"], m, d.get("note", "")[:300], now())); db().commit()
    return jsonify(ok=True)

@app.get("/api/moods")
@auth()
def moods():
    r = db().execute("SELECT mood,note,created FROM moods WHERE uid=? ORDER BY id DESC LIMIT 30", (g.user["id"],))
    return jsonify([dict(x) for x in r][::-1])

# ---------------- AI agent ----------------
CRISIS = re.compile(r"\b(suicid\w*|kill myself|end my life|want to die|better off dead|self[- ]?harm|hurt myself|cut myself|no reason to live)\b", re.I)
EMOTIONS = {
    "anxiety": (r"\b(anxious|anxiety|panic|worried|worry|nervous|stress\w*|overwhelm\w*|afraid|scared)\b",
                "That sounds really stressful. Let's slow things down together with a grounding exercise (5-4-3-2-1): name 5 things you see, 4 you can touch, 3 you hear, 2 you smell, 1 you taste. Then breathe in for 4 counts, hold 4, out for 6. What is the main thing on your mind right now?"),
    "sadness": (r"\b(sad|depress\w*|hopeless|empty|lonely|alone|cry\w*|worthless|numb)\b",
                "I'm sorry you're carrying this. Feeling low is hard, and reaching out matters. One gentle step: do one small thing today (a short walk, water, a message to someone you trust). Would you like to tell me what has been weighing on you most?"),
    "anger": (r"\b(angry|furious|irritat\w*|annoy\w*|frustrat\w*|rage)\b",
              "Frustration is a valid signal. Try pausing for a slow breath, then ask: what do I need right now? If you like, tell me what happened and we can look at it together."),
    "sleep": (r"\b(sleep|insomnia|tired|exhausted|nightmare\w*|awake)\b",
              "Sleep and mood affect each other. Try a fixed wake-up time, no screens 30 minutes before bed, and writing tomorrow's worries on paper. How many hours have you been sleeping lately?"),
    "positive": (r"\b(happy|good|great|better|grateful|calm|relaxed|proud)\b",
                 "I'm glad to hear that! Noticing what helped makes it repeatable. What contributed to feeling this way?"),
}
DEFAULT = "Thank you for sharing. I'm here to listen. Can you tell me more about how this has affected your days, sleep or relationships? You can also take the PHQ-9 or GAD-7 screening from the Screening tab."

def agent_reply(uid, text):
    if CRISIS.search(text):
        lines = "\n".join(f"- {h['name']}: {h['number']}" for h in HELPLINES)
        return ("I'm really glad you told me, and I'm concerned about your safety. You deserve support right now. "
                "Please contact one of these immediately, or go to the nearest person you trust:\n" + lines +
                "\nIf you are in immediate danger, call 112. I'll stay here with you. Are you safe at this moment?"), True
    ctx = db().execute("SELECT test,severity FROM screenings WHERE uid=? ORDER BY id DESC LIMIT 1", (uid,)).fetchone()
    key = os.environ.get("ANTHROPIC_API_KEY")
    if key:
        try:
            hist = [{"role": "assistant" if r["role"] == "bot" else "user", "content": r["text"]} for r in
                    db().execute("SELECT role,text FROM chats WHERE uid=? ORDER BY id DESC LIMIT 8", (uid,))][::-1]
            hist = [m for i, m in enumerate(hist) if i == 0 or m["role"] != hist[i - 1]["role"]]
            while hist and hist[0]["role"] != "user": hist.pop(0)
            body = json.dumps({"model": os.environ.get("CLAUDE_MODEL", "claude-sonnet-4-6"), "max_tokens": 400,
                               "system": "You are MindCare, a warm supportive mental health companion. Use brief, empathetic replies, "
                                         "evidence-based coping skills (CBT, grounding, breathing), never diagnose or prescribe, and encourage "
                                         "professional help when appropriate." + (f" Latest screening: {ctx['test']} {ctx['severity']}." if ctx else ""),
                               "messages": hist + [{"role": "user", "content": text}]}).encode()
            rq = urllib.request.Request("https://api.anthropic.com/v1/messages", body,
                                        {"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"})
            return json.load(urllib.request.urlopen(rq, timeout=20))["content"][0]["text"], False
        except Exception:
            pass  # fall back to the built-in agent
    reply = next((r for p, r in EMOTIONS.values() if re.search(p, text, re.I)), DEFAULT)
    if ctx and ctx["severity"] in ("Moderately severe", "Severe"):
        reply += f"\n\nYour latest {ctx['test']} result was {ctx['severity'].lower()}. Please consider speaking with a professional soon."
    return reply, False

@app.post("/api/chat")
@auth()
def chat():
    text = request.get_json(force=True).get("message", "").strip()[:1000]
    if not text: return jsonify(error="Type a message first."), 400
    reply, crisis = agent_reply(g.user["id"], text)
    for role, t in (("user", text), ("bot", reply)):
        db().execute("INSERT INTO chats(uid,role,text,created) VALUES(?,?,?,?)", (g.user["id"], role, t, now()))
    db().commit()
    return jsonify(reply=reply, crisis=crisis)

@app.get("/api/chat")
@auth()
def chat_history():
    r = db().execute("SELECT role,text FROM chats WHERE uid=? ORDER BY id DESC LIMIT 40", (g.user["id"],))
    return jsonify([dict(x) for x in r][::-1])

# ---------------- Admin ----------------
@app.get("/api/admin/stats")
@auth("admin")
def stats():
    q = lambda s: [dict(x) for x in db().execute(s)]
    return jsonify(users=q("SELECT COUNT(*) n FROM users WHERE role='user'")[0]["n"],
                   screenings=q("SELECT COUNT(*) n FROM screenings")[0]["n"],
                   crisis=q("SELECT COUNT(*) n FROM screenings WHERE crisis=1")[0]["n"],
                   by_severity=q("SELECT test,severity,COUNT(*) n FROM screenings GROUP BY test,severity"),
                   recent=q("SELECT u.name,u.email,s.test,s.score,s.severity,s.crisis,s.created FROM screenings s JOIN users u ON u.id=s.uid ORDER BY s.id DESC LIMIT 15"))

@app.get("/")
def index(): return send_from_directory(FRONT, "index.html")

init_db()
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
