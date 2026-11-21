"""School Analytics API - single-file FastAPI backend (Neon PostgreSQL).
Env vars: DATABASE_URL (Neon), SECRET_KEY, CORS_ORIGINS (comma separated, default *)
Run: uvicorn main:app --host 0.0.0.0 --port $PORT
"""
import os, hashlib, hmac, secrets, datetime as dt
import jwt
from fastapi import FastAPI, Depends, HTTPException, Header, Body
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import inspect, text, create_engine, Column, Integer, String, Float, Date, DateTime, Text, Date as SADate
from sqlalchemy.orm import declarative_base, sessionmaker

DB = os.getenv("DATABASE_URL", "sqlite:///./dev.db")
if DB.startswith("postgres://"): DB = DB.replace("postgres://", "postgresql+psycopg2://", 1)
elif DB.startswith("postgresql://"): DB = DB.replace("postgresql://", "postgresql+psycopg2://", 1)
SECRET = os.getenv("SECRET_KEY", "change-me-in-render")
engine = create_engine(DB, pool_pre_ping=True, pool_recycle=300)
Session = sessionmaker(bind=engine, autoflush=False)
Base = declarative_base()

class B(Base):
    __abstract__ = True
    id = Column(Integer, primary_key=True)
    def d(self):
        out = {}
        for c in self.__table__.columns:
            v = getattr(self, c.name)
            out[c.name] = v.isoformat() if hasattr(v, "isoformat") else v
        return out

class School(B):
    __tablename__ = "school"; name = Column(String(200))
class User(B):
    __tablename__ = "users"; name = Column(String(150)); email = Column(String(150), unique=True); pw = Column(String(200)); role = Column(String(20), default="teacher"); teacher_id = Column(Integer)
class Teacher(B):
    __tablename__ = "teachers"; name = Column(String(150)); email = Column(String(150)); phone = Column(String(40)); subject = Column(String(100))
class Stream(B):  # a class stream e.g. Senior 1 East
    __tablename__ = "streams"; level = Column(Integer); name = Column(String(60)); teacher_id = Column(Integer)
class Student(B):
    __tablename__ = "students"; name = Column(String(150)); adm_no = Column(String(40)); gender = Column(String(10)); stream_id = Column(Integer); guardian_phone = Column(String(40))
class Exam(B):
    __tablename__ = "exams"; name = Column(String(150)); term = Column(Integer); year = Column(Integer); level = Column(Integer); date = Column(Date)
class Mark(B):
    __tablename__ = "marks"; exam_id = Column(Integer, index=True); student_id = Column(Integer, index=True); subject = Column(String(100)); score = Column(Float)
class Attendance(B):
    __tablename__ = "attendance"; student_id = Column(Integer, index=True); date = Column(Date, index=True); status = Column(String(15))
class Comment(B):
    __tablename__ = "comments"; student_id = Column(Integer); author = Column(String(150)); text = Column(Text); created = Column(DateTime, default=dt.datetime.utcnow)
class Message(B):
    __tablename__ = "messages"; sender = Column(String(150)); recipient = Column(String(150)); body = Column(Text); created = Column(DateTime, default=dt.datetime.utcnow)
class Event(B):
    __tablename__ = "events"; title = Column(String(200)); date = Column(Date)

class Assignment(B):  # teacher account -> class + subject they may enter marks for
    __tablename__ = "assignments"; user_id = Column(Integer, index=True); stream_id = Column(Integer); subject = Column(String(100))

Base.metadata.create_all(engine)
if "teacher_id" not in {c["name"] for c in inspect(engine).get_columns("users")}:  # upgrade older databases
    with engine.begin() as c: c.execute(text("ALTER TABLE users ADD COLUMN teacher_id INTEGER"))

app = FastAPI(title="School Analytics API")
app.add_middleware(CORSMiddleware, allow_origins=os.getenv("CORS_ORIGINS", "*").split(","), allow_methods=["*"], allow_headers=["*"])

def get_db():
    db = Session()
    try: yield db
    finally: db.close()

def hash_pw(p, salt=None):
    salt = salt or secrets.token_hex(8)
    return salt + "$" + hashlib.pbkdf2_hmac("sha256", p.encode(), salt.encode(), 100_000).hex()
def check_pw(p, h):
    salt = h.split("$")[0]; return hmac.compare_digest(hash_pw(p, salt), h)
def token(u): return jwt.encode({"sub": str(u.id), "exp": dt.datetime.utcnow() + dt.timedelta(days=7)}, SECRET, "HS256")

def current(authorization: str = Header(None), db=Depends(get_db)):
    try:
        uid = int(jwt.decode(authorization.split()[1], SECRET, ["HS256"])["sub"])
        u = db.get(User, uid)
        if u: return u
    except Exception: pass
    raise HTTPException(401, "Not authenticated")

# ---------- RBAC ----------
ALL = ["students", "streams", "teachers", "exams", "marks", "comments", "messages", "events", "attendance", "users", "assignments"]
PERMS = {  # r = read, w = write
    "admin": {k: "rw" for k in ALL},
    "staff": {"students": "rw", "streams": "r", "teachers": "r", "exams": "r", "marks": "r", "comments": "r", "messages": "rw", "events": "rw", "attendance": "rw"},
    "teacher": {"students": "r", "streams": "r", "teachers": "r", "exams": "r", "marks": "rw", "comments": "rw", "messages": "rw", "events": "r", "attendance": "rw"},
}
def can(u, res, act="r"):
    if act not in PERMS.get(u.role, {}).get(res, ""): raise HTTPException(403, "You don't have permission to do that")

def scope(u, db):
    asg = {(a.stream_id, (a.subject or "").strip().lower()) for a in db.query(Assignment).filter_by(user_id=u.id)}
    cls = {s.id for s in db.query(Stream).filter(Stream.teacher_id == u.teacher_id)} if u.teacher_id else set()
    return asg, cls

def own(u, o):
    if u.role == "admin": return
    for f in ("author", "sender"):
        if hasattr(o, f) and getattr(o, f) != u.name: raise HTTPException(403, "You can only change your own entries")

def chk_pw(p):
    if len(p or "") < 8: raise HTTPException(400, "Password must be at least 8 characters")

# ---------- auth ----------
@app.get("/")
def root(): return {"ok": True}

@app.get("/auth/status")
def status(db=Depends(get_db)):
    s = db.query(School).first()
    return {"setup_needed": db.query(User).count() == 0, "school": s.name if s else None}

@app.post("/auth/setup")
def setup(b: dict = Body(...), db=Depends(get_db)):
    if db.query(User).count(): raise HTTPException(403, "Already set up")
    chk_pw(b.get("password"))
    db.add(School(name=b["school"].upper()))
    u = User(name=b["name"], email=b["email"].lower(), pw=hash_pw(b["password"]), role="admin")
    db.add(u); db.commit()
    return {"token": token(u)}

@app.post("/auth/login")
def login(b: dict = Body(...), db=Depends(get_db)):
    u = db.query(User).filter(User.email == b.get("email", "").lower()).first()
    if not u or not check_pw(b.get("password", ""), u.pw): raise HTTPException(400, "Wrong email or password")
    return {"token": token(u)}

def udict(u): return {"id": u.id, "name": u.name, "email": u.email, "role": u.role, "teacher_id": u.teacher_id}

@app.get("/me")
def me(u=Depends(current), db=Depends(get_db)):
    s = db.query(School).first()
    asg = [{"stream_id": a.stream_id, "subject": a.subject} for a in db.query(Assignment).filter_by(user_id=u.id)]
    cls = [x.id for x in db.query(Stream).filter(Stream.teacher_id == u.teacher_id)] if u.teacher_id else []
    return {**udict(u), "school": s.name if s else "", "perms": PERMS[u.role], "assignments": asg, "class_streams": cls}

@app.post("/me/password")
def my_password(b: dict = Body(...), u=Depends(current), db=Depends(get_db)):
    if not check_pw(b.get("old", ""), u.pw): raise HTTPException(400, "Current password is wrong")
    chk_pw(b.get("new")); u.pw = hash_pw(b["new"]); db.commit(); return {"ok": True}

# ---------- user accounts (admin) ----------
def email_free(db, email, exclude=None):
    q = db.query(User).filter(User.email == email.lower())
    if exclude: q = q.filter(User.id != exclude)
    if q.first(): raise HTTPException(400, "That email is already in use")

@app.get("/users")
def users(u=Depends(current), db=Depends(get_db)):
    can(u, "users"); return [udict(x) for x in db.query(User).order_by(User.id)]

@app.post("/users")
def add_user(b: dict = Body(...), u=Depends(current), db=Depends(get_db)):
    can(u, "users", "w"); role = b.get("role") or "teacher"
    if role not in PERMS: raise HTTPException(400, "Unknown role")
    chk_pw(b.get("password")); email_free(db, b["email"])
    n = User(name=b["name"], email=b["email"].lower(), pw=hash_pw(b["password"]), role=role, teacher_id=b.get("teacher_id") or None)
    db.add(n); db.commit(); return udict(n)

@app.put("/users/{i}")
def upd_user(i: int, b: dict = Body(...), u=Depends(current), db=Depends(get_db)):
    can(u, "users", "w"); n = db.get(User, i)
    if not n: raise HTTPException(404, "Not found")
    if b.get("role"):
        if b["role"] not in PERMS: raise HTTPException(400, "Unknown role")
        if n.id == u.id and b["role"] != "admin": raise HTTPException(400, "You can't remove your own admin role")
        n.role = b["role"]
    if b.get("name"): n.name = b["name"]
    if b.get("email"): email_free(db, b["email"], i); n.email = b["email"].lower()
    if "teacher_id" in b: n.teacher_id = b["teacher_id"] or None
    if b.get("password"): chk_pw(b["password"]); n.pw = hash_pw(b["password"])
    db.commit(); return udict(n)

@app.delete("/users/{i}")
def del_user(i: int, u=Depends(current), db=Depends(get_db)):
    can(u, "users", "w")
    if i == u.id: raise HTTPException(400, "You can't delete your own account")
    db.query(Assignment).filter_by(user_id=i).delete()
    n = db.get(User, i)
    if n: db.delete(n)
    db.commit(); return {"ok": True}

# ---------- generic CRUD (permission + ownership checked) ----------
def save(obj, b):
    for c in obj.__table__.columns:
        if c.name in b and c.name != "id":
            v = b[c.name]
            if isinstance(c.type, SADate) and isinstance(v, str): v = dt.date.fromisoformat(v[:10]) if v else None
            if isinstance(c.type, DateTime): continue
            setattr(obj, c.name, v)

def crud(path, M):
    def lst(db=Depends(get_db), u=Depends(current)):
        can(u, path); rows = db.query(M).order_by(M.id.desc()).all()
        if M is Message: rows = [r for r in rows if u.name in (r.sender, r.recipient) or (r.recipient or "").strip().lower() == "all"]
        return [r.d() for r in rows]
    def add(b: dict = Body(...), db=Depends(get_db), u=Depends(current)):
        can(u, path, "w"); o = M(); save(o, b)
        if M is Comment: o.author = u.name
        if M is Message: o.sender = u.name
        db.add(o); db.commit(); return o.d()
    def upd(i: int, b: dict = Body(...), db=Depends(get_db), u=Depends(current)):
        can(u, path, "w"); o = db.get(M, i)
        if not o: raise HTTPException(404, "Not found")
        own(u, o); save(o, {k: v for k, v in b.items() if k not in ("author", "sender")}); db.commit(); return o.d()
    def rm(i: int, db=Depends(get_db), u=Depends(current)):
        can(u, path, "w"); o = db.get(M, i)
        if o: own(u, o); db.delete(o); db.commit()
        return {"ok": True}
    app.add_api_route(f"/{path}", lst, methods=["GET"], name=f"list_{path}")
    app.add_api_route(f"/{path}", add, methods=["POST"], name=f"add_{path}")
    app.add_api_route(f"/{path}/{{i}}", upd, methods=["PUT"], name=f"upd_{path}")
    app.add_api_route(f"/{path}/{{i}}", rm, methods=["DELETE"], name=f"rm_{path}")

for p, M in [("teachers", Teacher), ("streams", Stream), ("students", Student), ("exams", Exam),
             ("comments", Comment), ("messages", Message), ("events", Event), ("assignments", Assignment)]:
    crud(p, M)

# ---------- dashboard ----------
@app.get("/dashboard")
def dashboard(u=Depends(current), db=Depends(get_db)):
    streams = db.query(Stream).all(); students = db.query(Student).all()
    levels = []
    for lv in (1, 2, 3, 4):
        ids = {s.id for s in streams if s.level == lv}
        levels.append({"level": lv, "streams": len(ids), "students": sum(1 for st in students if st.stream_id in ids)})
    return {"teachers": db.query(Teacher).count(), "students": len(students),
            "staff": db.query(User).filter(User.role == "staff").count(), "streams": len(streams), "levels": levels}

# ---------- exams: marks, results, analytics ----------
def grade(s):
    for cut, g in [(80, "D1"), (70, "D2"), (65, "C3"), (60, "C4"), (55, "C5"), (50, "C6"), (45, "P7"), (40, "P8")]:
        if s >= cut: return g
    return "F9"

@app.get("/exams/{eid}/marks")
def get_marks(eid: int, u=Depends(current), db=Depends(get_db)):
    can(u, "marks"); return [m.d() for m in db.query(Mark).filter(Mark.exam_id == eid).all()]

@app.post("/exams/{eid}/marks")
def put_marks(eid: int, b: dict = Body(...), u=Depends(current), db=Depends(get_db)):
    """body: {rows:[{student_id, subject, score}]}. Teachers may only save marks for classes/subjects they are assigned."""
    can(u, "marks", "w")
    asg, cls = scope(u, db)
    studs = {s.id: s for s in db.query(Student).filter(Student.id.in_([r["student_id"] for r in b["rows"]]))}
    clean = []
    for r in b["rows"]:
        if r.get("score") in (None, ""): continue
        sc = float(r["score"]); st = studs.get(r["student_id"]); subj = (r.get("subject") or "").strip()
        if not 0 <= sc <= 100 or not st or not subj: raise HTTPException(400, "Invalid marks")
        if u.role == "teacher" and st.stream_id not in cls and (st.stream_id, subj.lower()) not in asg:
            raise HTTPException(403, f"You are not assigned to enter {subj} marks for this class")
        clean.append((st.id, subj, sc))
    for sid, subj, sc in clean:
        m = db.query(Mark).filter_by(exam_id=eid, student_id=sid, subject=subj).first() or Mark(exam_id=eid, student_id=sid, subject=subj)
        m.score = sc; db.add(m)
    db.commit(); return {"ok": True}

@app.get("/exams/{eid}/results")
def results(eid: int, u=Depends(current), db=Depends(get_db)):
    can(u, "marks")
    marks = db.query(Mark).filter(Mark.exam_id == eid).all()
    studs = {s.id: s for s in db.query(Student).all()}
    streams = {s.id: s for s in db.query(Stream).all()}
    by = {}
    for m in marks: by.setdefault(m.student_id, {})[m.subject] = m.score
    rows = []
    for sid, subs in by.items():
        st = studs.get(sid)
        if not st: continue
        mean = sum(subs.values()) / len(subs); sm = streams.get(st.stream_id)
        rows.append({"student_id": sid, "name": st.name, "adm_no": st.adm_no, "stream_id": st.stream_id,
                     "stream": f"Senior {sm.level} {sm.name}" if sm else "-", "subjects": subs,
                     "total": round(sum(subs.values()), 1), "mean": round(mean, 1), "grade": grade(mean)})
    rows.sort(key=lambda r: -r["mean"])
    for i, r in enumerate(rows, 1): r["position"] = i
    subj = {}
    for m in marks: subj.setdefault(m.subject, []).append(m.score)
    return {"rows": rows, "analytics": {
        "subject_means": {k: round(sum(v) / len(v), 1) for k, v in subj.items()},
        "grade_distribution": {g: sum(1 for r in rows if r["grade"] == g) for g in ["D1", "D2", "C3", "C4", "C5", "C6", "P7", "P8", "F9"]},
        "class_mean": round(sum(r["mean"] for r in rows) / len(rows), 1) if rows else 0}}

# ---------- attendance ----------
@app.get("/attendance")
def get_att(date: str, u=Depends(current), db=Depends(get_db)):
    can(u, "attendance"); return [a.d() for a in db.query(Attendance).filter(Attendance.date == dt.date.fromisoformat(date)).all()]

@app.post("/attendance/bulk")
def att_bulk(b: dict = Body(...), u=Depends(current), db=Depends(get_db)):
    can(u, "attendance", "w"); d = dt.date.fromisoformat(b["date"])
    if u.role == "teacher":
        asg, cls = scope(u, db); ok = cls | {a[0] for a in asg}
        studs = db.query(Student).filter(Student.id.in_([r["student_id"] for r in b["rows"]])).all()
        if any(s.stream_id not in ok for s in studs): raise HTTPException(403, "You can only mark attendance for your own classes")
    for r in b["rows"]:
        if r["status"] not in ("Present", "Absent", "Late"): raise HTTPException(400, "Invalid status")
        a = db.query(Attendance).filter_by(student_id=r["student_id"], date=d).first() or Attendance(student_id=r["student_id"], date=d)
        a.status = r["status"]; db.add(a)
    db.commit(); return {"ok": True}
