import os
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash


BASE_DIR = Path(__file__).resolve().parent
DATABASE = Path(os.environ.get("DATABASE_PATH", BASE_DIR / "data" / "app.db"))
UPLOAD_DIR = Path(os.environ.get("UPLOAD_DIR", BASE_DIR / "uploads"))
ALLOWED_EXTENSIONS = {"mp4", "webm", "mov", "m4v"}

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "ganti-secret-key-ini"),
    MAX_CONTENT_LENGTH=500 * 1024 * 1024,
)


def now_utc():
    return datetime.now(timezone.utc)


def db():
    if "db" not in g:
        DATABASE.parent.mkdir(parents=True, exist_ok=True)
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


@app.context_processor
def provide_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return {"csrf_token": session["csrf_token"]}


@app.before_request
def protect_post_requests():
    if request.method == "POST":
        submitted_token = request.form.get("csrf_token", "")
        session_token = session.get("csrf_token", "")
        if not session_token or not secrets.compare_digest(submitted_token, session_token):
            abort(400)


def initialize_database():
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    DATABASE.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE)
    connection.execute("PRAGMA foreign_keys = ON")
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('admin', 'customer')),
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS videos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            filename TEXT NOT NULL,
            uploaded_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS access_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            video_id INTEGER NOT NULL REFERENCES videos(id) ON DELETE CASCADE,
            message TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending', 'approved', 'rejected')),
            requested_at TEXT NOT NULL,
            reviewed_at TEXT
        );
        CREATE UNIQUE INDEX IF NOT EXISTS one_pending_request_per_video
            ON access_requests(user_id, video_id) WHERE status = 'pending';
        CREATE TABLE IF NOT EXISTS video_permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER NOT NULL REFERENCES access_requests(id) ON DELETE CASCADE,
            starts_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        );
        """
    )
    admin_email = os.environ.get("ADMIN_EMAIL", "admin@example.com").strip().lower()
    admin_password = os.environ.get("ADMIN_PASSWORD", "admin12345")
    exists = connection.execute(
        "SELECT id FROM users WHERE email = ?", (admin_email,)
    ).fetchone()
    if not exists:
        connection.execute(
            "INSERT INTO users (name, email, password_hash, role, created_at) "
            "VALUES (?, ?, ?, 'admin', ?)",
            (
                "Administrator",
                admin_email,
                generate_password_hash(admin_password),
                now_utc().isoformat(),
            ),
        )
    connection.commit()
    connection.close()


def login_required(role=None):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login"))
            if role and session.get("role") != role:
                abort(403)
            return view(*args, **kwargs)

        return wrapped

    return decorator


def allowed_video(filename):
    return Path(filename).suffix.lower().lstrip(".") in ALLOWED_EXTENSIONS


def video_extension(filename):
    return Path(filename).suffix.lower().lstrip(".")


def remove_video_file(filename):
    if filename:
        path = UPLOAD_DIR / filename
        if path.is_file():
            path.unlink()


@app.errorhandler(413)
def file_too_large(_error):
    flash("Ukuran file maksimal 500 MB.", "error")
    return redirect(request.referrer or url_for("admin_videos"))


@app.route("/")
def home():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return redirect(url_for("admin_dashboard" if session["role"] == "admin" else "customer_dashboard"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        user = db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["name"] = user["name"]
            session["role"] = user["role"]
            return redirect(url_for("home"))
        flash("Email atau kata sandi salah.", "error")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/admin")
@login_required("admin")
def admin_dashboard():
    connection = db()
    stats = {
        "customers": connection.execute(
            "SELECT COUNT(*) FROM users WHERE role = 'customer'"
        ).fetchone()[0],
        "videos": connection.execute("SELECT COUNT(*) FROM videos").fetchone()[0],
        "pending": connection.execute(
            "SELECT COUNT(*) FROM access_requests WHERE status = 'pending'"
        ).fetchone()[0],
    }
    return render_template("admin.html", stats=stats)


@app.route("/admin/customers")
@login_required("admin")
def admin_customers():
    customers = db().execute(
        "SELECT id, name, email, created_at FROM users "
        "WHERE role = 'customer' ORDER BY name"
    ).fetchall()
    return render_template("customers.html", customers=customers)


@app.route("/admin/customers/new", methods=["GET", "POST"])
@login_required("admin")
def customer_new():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not name or not email or len(password) < 8:
            flash("Nama, email, dan kata sandi minimal 8 karakter wajib diisi.", "error")
        else:
            try:
                db().execute(
                    "INSERT INTO users (name, email, password_hash, role, created_at) "
                    "VALUES (?, ?, ?, 'customer', ?)",
                    (name, email, generate_password_hash(password), now_utc().isoformat()),
                )
                db().commit()
                flash("Customer berhasil dibuat.", "success")
                return redirect(url_for("admin_customers"))
            except sqlite3.IntegrityError:
                flash("Email tersebut sudah digunakan.", "error")
    return render_template("customer_form.html", customer=None)


@app.route("/admin/customers/<int:user_id>/edit", methods=["GET", "POST"])
@login_required("admin")
def customer_edit(user_id):
    connection = db()
    customer = connection.execute(
        "SELECT id, name, email FROM users WHERE id = ? AND role = 'customer'",
        (user_id,),
    ).fetchone()
    if customer is None:
        abort(404)
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not name or not email or (password and len(password) < 8):
            flash("Nama dan email wajib diisi; kata sandi baru minimal 8 karakter.", "error")
        else:
            try:
                if password:
                    connection.execute(
                        "UPDATE users SET name = ?, email = ?, password_hash = ? WHERE id = ?",
                        (name, email, generate_password_hash(password), user_id),
                    )
                else:
                    connection.execute(
                        "UPDATE users SET name = ?, email = ? WHERE id = ?",
                        (name, email, user_id),
                    )
                connection.commit()
                flash("Data customer berhasil diperbarui.", "success")
                return redirect(url_for("admin_customers"))
            except sqlite3.IntegrityError:
                flash("Email tersebut sudah digunakan.", "error")
    return render_template("customer_form.html", customer=customer)


@app.route("/admin/customers/<int:user_id>/delete", methods=["POST"])
@login_required("admin")
def customer_delete(user_id):
    db().execute("DELETE FROM users WHERE id = ? AND role = 'customer'", (user_id,))
    db().commit()
    flash("Customer berhasil dihapus.", "success")
    return redirect(url_for("admin_customers"))


@app.route("/admin/videos")
@login_required("admin")
def admin_videos():
    videos = db().execute(
        "SELECT v.*, (SELECT COUNT(*) FROM access_requests r WHERE r.video_id = v.id) "
        "AS request_count FROM videos v ORDER BY v.uploaded_at DESC"
    ).fetchall()
    return render_template("videos.html", videos=videos)


@app.route("/admin/videos/new", methods=["GET", "POST"])
@login_required("admin")
def video_new():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        video_file = request.files.get("video")
        if not title or not video_file or not video_file.filename:
            flash("Judul dan file video wajib diisi.", "error")
        elif not allowed_video(video_file.filename):
            flash("Format yang didukung: MP4, WebM, MOV, dan M4V.", "error")
        else:
            extension = video_extension(video_file.filename)
            filename = f"{uuid.uuid4().hex}.{extension}"
            video_file.save(UPLOAD_DIR / filename)
            db().execute(
                "INSERT INTO videos (title, description, filename, uploaded_at) "
                "VALUES (?, ?, ?, ?)",
                (title, description, filename, now_utc().isoformat()),
            )
            db().commit()
            flash("Video berhasil diunggah.", "success")
            return redirect(url_for("admin_videos"))
    return render_template("video_form.html", video=None)


@app.route("/admin/videos/<int:video_id>/edit", methods=["GET", "POST"])
@login_required("admin")
def video_edit(video_id):
    connection = db()
    video = connection.execute("SELECT * FROM videos WHERE id = ?", (video_id,)).fetchone()
    if video is None:
        abort(404)
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        new_file = request.files.get("video")
        if not title:
            flash("Judul video wajib diisi.", "error")
        elif new_file and new_file.filename and not allowed_video(new_file.filename):
            flash("Format yang didukung: MP4, WebM, MOV, dan M4V.", "error")
        else:
            filename = video["filename"]
            if new_file and new_file.filename:
                extension = video_extension(new_file.filename)
                filename = f"{uuid.uuid4().hex}.{extension}"
                new_file.save(UPLOAD_DIR / filename)
            connection.execute(
                "UPDATE videos SET title = ?, description = ?, filename = ? WHERE id = ?",
                (title, description, filename, video_id),
            )
            connection.commit()
            if filename != video["filename"]:
                remove_video_file(video["filename"])
            flash("Data video berhasil diperbarui.", "success")
            return redirect(url_for("admin_videos"))
    return render_template("video_form.html", video=video)


@app.route("/admin/videos/<int:video_id>/delete", methods=["POST"])
@login_required("admin")
def video_delete(video_id):
    connection = db()
    video = connection.execute(
        "SELECT filename FROM videos WHERE id = ?", (video_id,)
    ).fetchone()
    if video:
        connection.execute("DELETE FROM videos WHERE id = ?", (video_id,))
        connection.commit()
        remove_video_file(video["filename"])
        flash("Video dan data permintaannya berhasil dihapus.", "success")
    return redirect(url_for("admin_videos"))


@app.route("/admin/requests")
@login_required("admin")
def admin_requests():
    requests_list = db().execute(
        """
        SELECT r.*, u.name AS customer_name, u.email, v.title AS video_title,
               p.starts_at, p.expires_at
        FROM access_requests r
        JOIN users u ON u.id = r.user_id
        JOIN videos v ON v.id = r.video_id
        LEFT JOIN video_permissions p ON p.request_id = r.id
        ORDER BY CASE r.status WHEN 'pending' THEN 0 ELSE 1 END, r.requested_at DESC
        """
    ).fetchall()
    return render_template("requests.html", requests_list=requests_list)


@app.route("/admin/requests/<int:request_id>/review", methods=["POST"])
@login_required("admin")
def review_request(request_id):
    connection = db()
    access_request = connection.execute(
        "SELECT * FROM access_requests WHERE id = ?", (request_id,)
    ).fetchone()
    if access_request is None or access_request["status"] != "pending":
        flash("Permintaan tidak ditemukan atau sudah ditinjau.", "error")
        return redirect(url_for("admin_requests"))

    decision = request.form.get("decision")
    reviewed_at = now_utc()
    if decision == "approve":
        try:
            hours = float(request.form.get("hours", ""))
        except ValueError:
            hours = 0
        if not 0 < hours <= 8760:
            flash("Durasi akses harus lebih dari 0 dan maksimal 8760 jam.", "error")
            return redirect(url_for("admin_requests"))
        expires_at = reviewed_at + timedelta(hours=hours)
        connection.execute(
            "UPDATE access_requests SET status = 'approved', reviewed_at = ? WHERE id = ?",
            (reviewed_at.isoformat(), request_id),
        )
        connection.execute(
            "INSERT INTO video_permissions (request_id, starts_at, expires_at) VALUES (?, ?, ?)",
            (request_id, reviewed_at.isoformat(), expires_at.isoformat()),
        )
        flash("Permintaan disetujui; akses dimulai sekarang dan berakhir sesuai durasi.", "success")
    elif decision == "reject":
        connection.execute(
            "UPDATE access_requests SET status = 'rejected', reviewed_at = ? WHERE id = ?",
            (reviewed_at.isoformat(), request_id),
        )
        flash("Permintaan ditolak.", "success")
    else:
        abort(400)
    connection.commit()
    return redirect(url_for("admin_requests"))


@app.route("/customer")
@login_required("customer")
def customer_dashboard():
    connection = db()
    videos = connection.execute(
        """
        SELECT v.*,
               (SELECT r.status FROM access_requests r
                WHERE r.video_id = v.id AND r.user_id = ?
                ORDER BY r.requested_at DESC LIMIT 1) AS request_status,
               (SELECT p.expires_at FROM access_requests r
                JOIN video_permissions p ON p.request_id = r.id
                WHERE r.video_id = v.id AND r.user_id = ? AND r.status = 'approved'
                ORDER BY p.expires_at DESC LIMIT 1) AS expires_at
        FROM videos v ORDER BY v.uploaded_at DESC
        """,
        (session["user_id"], session["user_id"]),
    ).fetchall()
    current_time = now_utc()
    return render_template("customer.html", videos=videos, current_time=current_time)


@app.route("/customer/videos/<int:video_id>/request", methods=["POST"])
@login_required("customer")
def request_access(video_id):
    connection = db()
    video = connection.execute("SELECT id FROM videos WHERE id = ?", (video_id,)).fetchone()
    if video is None:
        abort(404)
    current = now_utc().isoformat()
    active = connection.execute(
        """
        SELECT 1 FROM access_requests r JOIN video_permissions p ON p.request_id = r.id
        WHERE r.user_id = ? AND r.video_id = ? AND r.status = 'approved'
          AND p.starts_at <= ? AND p.expires_at > ?
        """,
        (session["user_id"], video_id, current, current),
    ).fetchone()
    pending = connection.execute(
        "SELECT 1 FROM access_requests WHERE user_id = ? AND video_id = ? AND status = 'pending'",
        (session["user_id"], video_id),
    ).fetchone()
    if active:
        flash("Akses video ini masih aktif.", "error")
    elif pending:
        flash("Permintaan akses video ini masih menunggu persetujuan admin.", "error")
    else:
        connection.execute(
            "INSERT INTO access_requests (user_id, video_id, message, status, requested_at) "
            "VALUES (?, ?, ?, 'pending', ?)",
            (
                session["user_id"],
                video_id,
                request.form.get("message", "").strip(),
                now_utc().isoformat(),
            ),
        )
        connection.commit()
        flash("Permintaan akses berhasil dikirim.", "success")
    return redirect(url_for("customer_dashboard"))


@app.route("/customer/videos/<int:video_id>/watch")
@login_required("customer")
def watch_video(video_id):
    current = now_utc().isoformat()
    result = db().execute(
        """
        SELECT v.*, p.expires_at FROM videos v
        JOIN access_requests r ON r.video_id = v.id
        JOIN video_permissions p ON p.request_id = r.id
        WHERE v.id = ? AND r.user_id = ? AND r.status = 'approved'
          AND p.starts_at <= ? AND p.expires_at > ?
        ORDER BY p.expires_at DESC LIMIT 1
        """,
        (video_id, session["user_id"], current, current),
    ).fetchone()
    if result is None:
        abort(403)
    return render_template("watch.html", video=result)


@app.route("/media/<int:video_id>")
@login_required()
def serve_video(video_id):
    if session.get("role") == "admin":
        record = db().execute(
            "SELECT filename FROM videos WHERE id = ?", (video_id,)
        ).fetchone()
    else:
        current = now_utc().isoformat()
        record = db().execute(
            """
            SELECT v.filename FROM videos v
            JOIN access_requests r ON r.video_id = v.id
            JOIN video_permissions p ON p.request_id = r.id
            WHERE v.id = ? AND r.user_id = ? AND r.status = 'approved'
              AND p.starts_at <= ? AND p.expires_at > ?
            ORDER BY p.expires_at DESC LIMIT 1
            """,
            (video_id, session["user_id"], current, current),
        ).fetchone()
    if record is None:
        abort(403)
    path = UPLOAD_DIR / record["filename"]
    if not path.is_file():
        abort(404)
    return send_file(path, conditional=True)


@app.errorhandler(403)
def forbidden(_error):
    return render_template("error.html", code=403, message="Anda tidak memiliki akses ke halaman atau video ini."), 403


@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", code=404, message="Halaman atau data tidak ditemukan."), 404


initialize_database()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
