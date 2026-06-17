import os
import sqlite3
from datetime import datetime, timedelta
from flask import (
    Flask, request, jsonify, render_template,
    session, redirect, url_for, send_from_directory
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ─── App Setup ────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-in-prod-xyz987")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB
app.config["UPLOAD_FOLDER"] = os.path.join(os.path.dirname(__file__), "uploads")

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp", "pdf", "txt", "zip", "mp4", "mp3"}

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# ─── Database ─────────────────────────────────────────────────────────────────
DB_PATH = os.path.join(os.path.dirname(__file__), "database.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                email         TEXT    NOT NULL UNIQUE,
                password_hash TEXT    NOT NULL,
                name          TEXT    NOT NULL
            );

            CREATE TABLE IF NOT EXISTS messages (
                id          INTEGER  PRIMARY KEY AUTOINCREMENT,
                sender_id   INTEGER  NOT NULL,
                receiver_id INTEGER  NOT NULL,
                content     TEXT,
                file_path   TEXT,
                timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sender_id)   REFERENCES users(id),
                FOREIGN KEY (receiver_id) REFERENCES users(id)
            );
        """)


init_db()

# ─── Helpers ──────────────────────────────────────────────────────────────────
TZ_OFFSET = timedelta(hours=-3)   # Argentina UTC-3


def utc_to_argentina(ts_str: str) -> str:
    """Convert an SQLite UTC timestamp string to Argentina local HH:MM."""
    if not ts_str:
        return ""
    try:
        dt = datetime.strptime(ts_str[:19], "%Y-%m-%d %H:%M:%S")
        local = dt + TZ_OFFSET
        return local.strftime("%H:%M")
    except ValueError:
        return ts_str


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def login_required(f):
    from functools import wraps

    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)

    return decorated


# ─── Static / Pages ───────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


# ─── Auth ─────────────────────────────────────────────────────────────────────
@app.route("/api/auth/status")
def auth_status():
    if "user_id" in session:
        with get_db() as conn:
            user = conn.execute(
                "SELECT id, name, email FROM users WHERE id = ?", (session["user_id"],)
            ).fetchone()
        if user:
            return jsonify({"authenticated": True, "user": dict(user)})
    return jsonify({"authenticated": False})


@app.route("/api/auth/register", methods=["POST"])
def register():
    data = request.get_json(force=True)
    name     = (data.get("name") or "").strip()
    email    = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not name or not email or not password:
        return jsonify({"error": "Todos los campos son obligatorios."}), 400
    if len(password) < 6:
        return jsonify({"error": "La contraseña debe tener al menos 6 caracteres."}), 400

    pw_hash = generate_password_hash(password)
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO users (email, password_hash, name) VALUES (?, ?, ?)",
                (email, pw_hash, name),
            )
        return jsonify({"ok": True, "message": "Cuenta creada correctamente."})
    except sqlite3.IntegrityError:
        return jsonify({"error": "Ese email ya está registrado."}), 409


@app.route("/api/auth/login", methods=["POST"])
def login():
    data     = request.get_json(force=True)
    email    = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    with get_db() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE email = ?", (email,)
        ).fetchone()

    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Credenciales incorrectas."}), 401

    session.permanent = True
    session["user_id"] = user["id"]
    return jsonify({"ok": True, "user": {"id": user["id"], "name": user["name"], "email": user["email"]}})


@app.route("/api/auth/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})


# ─── Users ────────────────────────────────────────────────────────────────────
@app.route("/api/users/search")
@login_required
def search_users():
    email = (request.args.get("email") or "").strip().lower()
    if not email:
        return jsonify({"users": []})

    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, name, email FROM users WHERE email = ? AND id != ?",
            (email, session["user_id"]),
        ).fetchall()

    return jsonify({"users": [dict(r) for r in rows]})


# ─── Conversations ─────────────────────────────────────────────────────────────
@app.route("/api/conversations")
@login_required
def conversations():
    uid = session["user_id"]
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT
                u.id         AS other_id,
                u.name       AS other_name,
                u.email      AS other_email,
                m.content    AS last_content,
                m.file_path  AS last_file,
                m.timestamp  AS last_ts,
                m.sender_id  AS last_sender
            FROM (
                SELECT
                    CASE WHEN sender_id = :uid THEN receiver_id ELSE sender_id END AS partner_id,
                    MAX(id) AS max_id
                FROM messages
                WHERE sender_id = :uid OR receiver_id = :uid
                GROUP BY partner_id
            ) AS conv
            JOIN messages m ON m.id = conv.max_id
            JOIN users    u ON u.id = conv.partner_id
            ORDER BY m.timestamp DESC
            """,
            {"uid": uid},
        ).fetchall()

    result = []
    for r in rows:
        r = dict(r)
        r["time_fmt"]  = utc_to_argentina(r["last_ts"])
        r["has_file"]  = bool(r["last_file"])
        r["is_mine"]   = r["last_sender"] == uid
        result.append(r)

    return jsonify({"conversations": result})


# ─── Messages ─────────────────────────────────────────────────────────────────
@app.route("/api/messages/<int:other_id>")
@login_required
def get_messages(other_id):
    uid = session["user_id"]
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT id, sender_id, receiver_id, content, file_path, timestamp
            FROM messages
            WHERE (sender_id = ? AND receiver_id = ?)
               OR (sender_id = ? AND receiver_id = ?)
            ORDER BY id ASC
            """,
            (uid, other_id, other_id, uid),
        ).fetchall()

    msgs = []
    for r in rows:
        r = dict(r)
        r["time_fmt"] = utc_to_argentina(r["timestamp"])
        r["is_mine"]  = r["sender_id"] == uid
        msgs.append(r)

    return jsonify({"messages": msgs})


@app.route("/api/messages/send", methods=["POST"])
@login_required
def send_message():
    uid         = session["user_id"]
    receiver_id = request.form.get("receiver_id", type=int)
    content     = (request.form.get("content") or "").strip()
    file_path   = None

    if not receiver_id:
        return jsonify({"error": "Destinatario inválido."}), 400

    # Verify receiver exists
    with get_db() as conn:
        target = conn.execute("SELECT id FROM users WHERE id = ?", (receiver_id,)).fetchone()
    if not target:
        return jsonify({"error": "Usuario destinatario no encontrado."}), 404

    # Handle optional file
    if "file" in request.files:
        f = request.files["file"]
        if f and f.filename and allowed_file(f.filename):
            filename  = secure_filename(f.filename)
            save_name = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}_{filename}"
            f.save(os.path.join(app.config["UPLOAD_FOLDER"], save_name))
            file_path = save_name

    if not content and not file_path:
        return jsonify({"error": "El mensaje no puede estar vacío."}), 400

    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO messages (sender_id, receiver_id, content, file_path) VALUES (?, ?, ?, ?)",
            (uid, receiver_id, content or None, file_path),
        )
        msg_id = cur.lastrowid
        msg = conn.execute(
            "SELECT id, sender_id, receiver_id, content, file_path, timestamp FROM messages WHERE id = ?",
            (msg_id,),
        ).fetchone()

    msg = dict(msg)
    msg["time_fmt"] = utc_to_argentina(msg["timestamp"])
    msg["is_mine"]  = True
    return jsonify({"ok": True, "message": msg})


# ─── Entry point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
