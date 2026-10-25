from flask import Flask, request, redirect, session, render_template_string
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(32).hex())
DB = "trustvault.db"

def connect():
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    return db

def setup():
    with connect() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY, username TEXT UNIQUE,
            password TEXT, role TEXT)""")
        db.execute("""CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY, name TEXT, owner_id INTEGER,
            content TEXT)""")
        db.execute("""CREATE TABLE IF NOT EXISTS permissions (
            user_id INTEGER, document_id INTEGER,
            access TEXT, UNIQUE(user_id, document_id))""")
        db.execute("""CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY, username TEXT,
            action TEXT, detail TEXT, time DEFAULT CURRENT_TIMESTAMP)""")
        for username, password, role in [
            ("admin", "AdminDemo123!", "admin"),
            ("owner", "OwnerDemo123!", "owner"),
            ("viewer", "ViewerDemo123!", "viewer")
        ]:
            found = db.execute(
                "SELECT id FROM users WHERE username=?", (username,)
            ).fetchone()
            if not found:
                db.execute(
                    "INSERT INTO users(username,password,role) VALUES(?,?,?)",
                    (username, generate_password_hash(password), role)
                )
setup()
def log(db, action, detail=""):
    db.execute("INSERT INTO audit(username,action,detail) VALUES(?,?,?)",
               (session.get("user"), action, detail))

PAGE = """
<h1>🔐 TrustVault</h1>
<p>Secure document-sharing assessment prototype</p>
{% if user %}
<p>Logged in as <b>{{ user }}</b> ({{ role }})</p>
<p><a href="/documents">Documents</a> | <a href="/audit">Audit log</a> |
<a href="/logout">Logout</a></p>
{% else %}
<h2>Login</h2>
<form method="post" action="/login">
<input name="username" placeholder="Username" required>
<input name="password" type="password" placeholder="Password" required>
<button>Login</button>
</form>
<p>Demo users: admin, owner, viewer (use the passwords provided in setup notes)</p>
{% endif %}
<p>{{ message }}</p>
"""

@app.route("/")
def home():
    if not session.get("user"):
        return render_template_string(PAGE, user=None, role=None, message="")
    return render_template_string(PAGE, user=session["user"],
                                  role=session["role"], message="")

@app.route("/login", methods=["POST"])
def login():
    with connect() as db:
        user = db.execute(
            "SELECT * FROM users WHERE username=?", (request.form["username"],)
        ).fetchone()
        if user and check_password_hash(user["password"], request.form["password"]):
            session.clear()
            session["user"] = user["username"]
            session["role"] = user["role"]
            log(db, "LOGIN", "Successful login")
            return redirect("/")
        db.execute("INSERT INTO audit(username,action,detail) VALUES(?,?,?)",
                   (request.form["username"], "LOGIN_DENIED", "Invalid login"))
    return render_template_string(PAGE, user=None, role=None,
                                  message="Login failed"), 401

@app.route("/logout")
def logout():
    with connect() as db:
        log(db, "LOGOUT")
    session.clear()
    return redirect("/")

@app.route("/documents")
def documents():
    if not session.get("user"):
        return redirect("/")
    with connect() as db:
        user = db.execute("SELECT id FROM users WHERE username=?",
                          (session["user"],)).fetchone()
        if session["role"] == "admin":
            docs = db.execute(
                "SELECT documents.*, users.username AS owner FROM documents "
                "JOIN users ON users.id=documents.owner_id"
            ).fetchall()
        else:
            docs = db.execute(
                "SELECT DISTINCT documents.*, users.username AS owner "
                "FROM documents JOIN users ON users.id=documents.owner_id "
                "LEFT JOIN permissions p ON p.document_id=documents.id "
                "WHERE documents.owner_id=? OR p.user_id=?",
                (user["id"], user["id"])
            ).fetchall()
    return render_template_string("""
    <h1>Documents</h1><a href="/">Home</a>
    <h2>Upload a text document</h2>
    <form method="post" action="/upload">
      <input name="name" placeholder="Document name" required>
      <textarea name="content" placeholder="Document content" required></textarea>
      <button>Save</button>
    </form>
    <ul>{% for d in docs %}
    <li>{{ d.name }} — owner: {{ d.owner }} —
    <a href="/documents/{{ d.id }}">Open</a></li>
    {% else %}<li>No documents yet</li>{% endfor %}</ul>
    """, docs=docs)

@app.route("/upload", methods=["POST"])
def upload():
    if not session.get("user"):
        return redirect("/")
    with connect() as db:
        owner = db.execute("SELECT id FROM users WHERE username=?",
                           (session["user"],)).fetchone()
        cur = db.execute(
            "INSERT INTO documents(name,owner_id,content) VALUES(?,?,?)",
            (request.form["name"][:120], owner["id"], request.form["content"])
        )
        log(db, "UPLOAD", f"Document {cur.lastrowid} uploaded")
    return redirect("/documents")

@app.route("/documents/<int:doc_id>", methods=["GET", "POST"])
def document_detail(doc_id):
    if not session.get("user"):
        return redirect("/")
    with connect() as db:
        me = db.execute("SELECT id FROM users WHERE username=?",
                        (session["user"],)).fetchone()
        doc = db.execute("SELECT * FROM documents WHERE id=?", (doc_id,)).fetchone()
        permitted = bool(doc and (
            session["role"] == "admin" or doc["owner_id"] == me["id"] or
            db.execute("SELECT 1 FROM permissions WHERE user_id=? AND document_id=?",
                       (me["id"], doc_id)).fetchone()
        ))
        if not permitted:
            log(db, "ACCESS_DENIED", f"Document {doc_id}")
            return "Access denied", 403
        if request.method == "POST":
            if doc["owner_id"] != me["id"]:
                log(db, "EDIT_DENIED", f"Document {doc_id}")
                return "Only the owner can edit this document", 403
            db.execute("UPDATE documents SET content=? WHERE id=?",
                       (request.form["content"], doc_id))
            log(db, "EDIT", f"Document {doc_id}")
            doc = db.execute("SELECT * FROM documents WHERE id=?",
                             (doc_id,)).fetchone()
    return render_template_string("""
    <h1>{{ doc.name }}</h1><a href="/documents">Back</a>
    <p>Content: {{ doc.content }}</p>
    {% if owner %}
    <form method="post"><textarea name="content" required>{{ doc.content }}</textarea>
    <button>Update content</button></form>
    <h2>Grant viewer access</h2>
    <form method="post" action="/grant/{{ doc.id }}">
    <input name="username" placeholder="Viewer username" required>
    <button>Grant read access</button></form>
    <h2>Revoke viewer access</h2>
    <form method="post" action="/revoke/{{ doc.id }}">
    <input name="username" placeholder="Viewer username" required>
    <button>Revoke access</button></form>
    {% endif %}
    """, doc=doc, owner=doc["owner_id"] == me["id"])

@app.route("/grant/<int:doc_id>", methods=["POST"])
def grant(doc_id):
    if not session.get("user"):
        return redirect("/")
    with connect() as db:
        me = db.execute("SELECT id FROM users WHERE username=?",
                        (session["user"],)).fetchone()
        doc = db.execute("SELECT * FROM documents WHERE id=?", (doc_id,)).fetchone()
        target = db.execute("SELECT id FROM users WHERE username=?",
                            (request.form["username"],)).fetchone()
        if not doc or doc["owner_id"] != me["id"] or not target:
            log(db, "GRANT_DENIED", f"Document {doc_id}")
            return "Only the owner can grant access to an existing user", 403
        db.execute("INSERT OR REPLACE INTO permissions VALUES(?,?,?)",
                   (target["id"], doc_id, "read"))
        log(db, "GRANT", f"Document {doc_id} to {request.form['username']}")
    return redirect(f"/documents/{doc_id}")



@app.route("/revoke/<int:doc_id>", methods=["POST"])
def revoke(doc_id):
    if not session.get("user"):
        return redirect("/")
    with connect() as db:
        me = db.execute(
            "SELECT id FROM users WHERE username=?",
            (session["user"],)
        ).fetchone()
        doc = db.execute(
            "SELECT * FROM documents WHERE id=?", (doc_id,)
        ).fetchone()
        username = request.form["username"]
        target = db.execute(
            "SELECT id FROM users WHERE username=?", (username,)
        ).fetchone()

        if not doc or doc["owner_id"] != me["id"] or not target:
            log(db, "REVOKE_DENIED", f"Document {doc_id}")
            return "Only the owner can revoke access from an existing user", 403

        db.execute(
            "DELETE FROM permissions WHERE user_id=? AND document_id=?",
            (target["id"], doc_id)
        )
        log(db, "REVOKE", f"Document {doc_id} from {username}")

    return redirect(f"/documents/{doc_id}")


@app.route("/audit")
def audit():
    if session.get("role") != "admin":
        return "Admin only", 403
    with connect() as db:
        events = db.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 200").fetchall()
    return render_template_string("""
    <h1>Recent audit events</h1><a href="/">Home</a>
    <ul>{% for e in events %}
    <li>{{ e.time }} — {{ e.username }} — {{ e.action }} — {{ e.detail }}</li>
    {% endfor %}</ul>
    """, events=events)

if __name__ == "__main__":
    setup()
    app.run(debug=True)
