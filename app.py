import os
import sqlite3
from functools import wraps
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "logistics.db")

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "replace-this-development-secret")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    with get_db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin','rider','customer')),
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS shipments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tracking_number TEXT NOT NULL UNIQUE,
            customer_id INTEGER NOT NULL,
            rider_id INTEGER,
            recipient_name TEXT NOT NULL,
            recipient_phone TEXT,
            origin TEXT NOT NULL,
            destination TEXT NOT NULL,
            package_description TEXT,
            status TEXT NOT NULL DEFAULT 'Pending',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(customer_id) REFERENCES users(id),
            FOREIGN KEY(rider_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS shipment_updates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            shipment_id INTEGER NOT NULL,
            status TEXT NOT NULL,
            location TEXT,
            note TEXT,
            updated_by INTEGER,
            created_at TEXT NOT NULL,
            FOREIGN KEY(shipment_id) REFERENCES shipments(id) ON DELETE CASCADE,
            FOREIGN KEY(updated_by) REFERENCES users(id)
        );
        """)
        admin = db.execute("SELECT id FROM users WHERE role='admin' LIMIT 1").fetchone()
        if not admin:
            db.execute(
                "INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                ("System Administrator", "admin@logistics.local",
                 generate_password_hash("admin123"), "admin", now())
            )


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def current_user():
    if "user_id" not in session:
        return None
    with get_db() as db:
        return db.execute("SELECT id,name,email,role FROM users WHERE id=?",
                          (session["user_id"],)).fetchone()


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


def roles_required(*roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = current_user()
            if not user:
                return redirect(url_for("login"))
            if user["role"] not in roles:
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return decorator


STATUSES = ["Pending", "Picked Up", "In Transit", "Out for Delivery", "Delivered", "Delivery Failed", "Returned"]


@app.context_processor
def inject_globals():
    return {"logged_user": current_user(), "statuses": STATUSES}


@app.route("/")
def index():
    if current_user():
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not name or not email or len(password) < 8:
            flash("Enter your name, a valid email, and a password of at least 8 characters.", "danger")
            return render_template("register.html")
        try:
            with get_db() as db:
                db.execute(
                    "INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                    (name, email, generate_password_hash(password), "customer", now())
                )
            flash("Account created. You can now log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("That email is already registered.", "danger")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        with get_db() as db:
            user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            flash(f"Welcome, {user['name']}!", "success")
            return redirect(url_for("dashboard"))
        flash("Incorrect email or password.", "danger")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    with get_db() as db:
        if user["role"] == "admin":
            total = db.execute("SELECT COUNT(*) n FROM shipments").fetchone()["n"]
            delivered = db.execute("SELECT COUNT(*) n FROM shipments WHERE status='Delivered'").fetchone()["n"]
            active = db.execute("SELECT COUNT(*) n FROM shipments WHERE status NOT IN ('Delivered','Returned','Delivery Failed')").fetchone()["n"]
            failed = db.execute("SELECT COUNT(*) n FROM shipments WHERE status IN ('Returned','Delivery Failed')").fetchone()["n"]
            recent = db.execute("""SELECT s.*, u.name customer_name FROM shipments s
                JOIN users u ON u.id=s.customer_id ORDER BY s.created_at DESC LIMIT 8""").fetchall()
        elif user["role"] == "rider":
            total = db.execute("SELECT COUNT(*) n FROM shipments WHERE rider_id=?", (user["id"],)).fetchone()["n"]
            delivered = db.execute("SELECT COUNT(*) n FROM shipments WHERE rider_id=? AND status='Delivered'", (user["id"],)).fetchone()["n"]
            active = db.execute("SELECT COUNT(*) n FROM shipments WHERE rider_id=? AND status NOT IN ('Delivered','Returned','Delivery Failed')", (user["id"],)).fetchone()["n"]
            failed = db.execute("SELECT COUNT(*) n FROM shipments WHERE rider_id=? AND status IN ('Returned','Delivery Failed')", (user["id"],)).fetchone()["n"]
            recent = db.execute("""SELECT s.*, u.name customer_name FROM shipments s
                JOIN users u ON u.id=s.customer_id WHERE s.rider_id=? ORDER BY s.created_at DESC LIMIT 8""", (user["id"],)).fetchall()
        else:
            total = db.execute("SELECT COUNT(*) n FROM shipments WHERE customer_id=?", (user["id"],)).fetchone()["n"]
            delivered = db.execute("SELECT COUNT(*) n FROM shipments WHERE customer_id=? AND status='Delivered'", (user["id"],)).fetchone()["n"]
            active = db.execute("SELECT COUNT(*) n FROM shipments WHERE customer_id=? AND status NOT IN ('Delivered','Returned','Delivery Failed')", (user["id"],)).fetchone()["n"]
            failed = db.execute("SELECT COUNT(*) n FROM shipments WHERE customer_id=? AND status IN ('Returned','Delivery Failed')", (user["id"],)).fetchone()["n"]
            recent = db.execute("SELECT * FROM shipments WHERE customer_id=? ORDER BY created_at DESC LIMIT 8", (user["id"],)).fetchall()
    return render_template("dashboard.html", total=total, delivered=delivered, active=active, failed=failed, recent=recent)


@app.route("/shipments")
@login_required
def shipments():
    user = current_user()
    with get_db() as db:
        if user["role"] == "admin":
            rows = db.execute("""SELECT s.*, c.name customer_name, r.name rider_name
                FROM shipments s JOIN users c ON c.id=s.customer_id
                LEFT JOIN users r ON r.id=s.rider_id ORDER BY s.created_at DESC""").fetchall()
        elif user["role"] == "rider":
            rows = db.execute("""SELECT s.*, c.name customer_name, r.name rider_name
                FROM shipments s JOIN users c ON c.id=s.customer_id
                LEFT JOIN users r ON r.id=s.rider_id WHERE s.rider_id=? ORDER BY s.created_at DESC""", (user["id"],)).fetchall()
        else:
            rows = db.execute("SELECT * FROM shipments WHERE customer_id=? ORDER BY created_at DESC", (user["id"],)).fetchall()
    return render_template("shipments.html", shipments=rows)


@app.route("/shipments/new", methods=["GET", "POST"])
@roles_required("admin")
def new_shipment():
    with get_db() as db:
        customers = db.execute("SELECT id,name,email FROM users WHERE role='customer' ORDER BY name").fetchall()
        riders = db.execute("SELECT id,name,email FROM users WHERE role='rider' ORDER BY name").fetchall()
    if request.method == "POST":
        customer_id = request.form.get("customer_id", type=int)
        rider_id = request.form.get("rider_id", type=int) or None
        recipient = request.form.get("recipient_name", "").strip()
        origin = request.form.get("origin", "").strip()
        destination = request.form.get("destination", "").strip()
        if not customer_id or not recipient or not origin or not destination:
            flash("Customer, recipient, origin, and destination are required.", "danger")
            return render_template("shipment_form.html", customers=customers, riders=riders)
        tracking = "LGS" + datetime.now().strftime("%y%m%d%H%M%S") + str(os.urandom(2).hex()).upper()
        with get_db() as db:
            cur = db.execute("""INSERT INTO shipments
                (tracking_number,customer_id,rider_id,recipient_name,recipient_phone,origin,destination,package_description,status,created_at,updated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (tracking, customer_id, rider_id, recipient, request.form.get("recipient_phone","").strip(),
                 origin, destination, request.form.get("package_description","").strip(), "Pending", now(), now()))
            shipment_id = cur.lastrowid
            db.execute("""INSERT INTO shipment_updates(shipment_id,status,location,note,updated_by,created_at)
                VALUES(?,?,?,?,?,?)""", (shipment_id, "Pending", origin, "Shipment record created.", session["user_id"], now()))
        flash(f"Shipment created. Tracking number: {tracking}", "success")
        return redirect(url_for("shipment_detail", shipment_id=shipment_id))
    return render_template("shipment_form.html", customers=customers, riders=riders)


@app.route("/shipments/<int:shipment_id>")
@login_required
def shipment_detail(shipment_id):
    user = current_user()
    with get_db() as db:
        shipment = db.execute("""SELECT s.*, c.name customer_name, c.email customer_email,
            r.name rider_name FROM shipments s JOIN users c ON c.id=s.customer_id
            LEFT JOIN users r ON r.id=s.rider_id WHERE s.id=?""", (shipment_id,)).fetchone()
        if not shipment:
            abort(404)
        if user["role"] == "customer" and shipment["customer_id"] != user["id"]:
            abort(403)
        if user["role"] == "rider" and shipment["rider_id"] != user["id"]:
            abort(403)
        updates = db.execute("""SELECT u.*, a.name updater_name FROM shipment_updates u
            LEFT JOIN users a ON a.id=u.updated_by WHERE u.shipment_id=? ORDER BY u.created_at DESC""",
            (shipment_id,)).fetchall()
        riders = db.execute("SELECT id,name FROM users WHERE role='rider' ORDER BY name").fetchall() if user["role"] == "admin" else []
    return render_template("shipment_detail.html", shipment=shipment, updates=updates, riders=riders)


@app.route("/shipments/<int:shipment_id>/update", methods=["POST"])
@roles_required("admin", "rider")
def update_shipment(shipment_id):
    user = current_user()
    status = request.form.get("status", "")
    location = request.form.get("location", "").strip()
    note = request.form.get("note", "").strip()
    with get_db() as db:
        shipment = db.execute("SELECT * FROM shipments WHERE id=?", (shipment_id,)).fetchone()
        if not shipment:
            abort(404)
        if user["role"] == "rider" and shipment["rider_id"] != user["id"]:
            abort(403)
        if status not in STATUSES:
            flash("Choose a valid shipment status.", "danger")
            return redirect(url_for("shipment_detail", shipment_id=shipment_id))
        db.execute("UPDATE shipments SET status=?, updated_at=? WHERE id=?", (status, now(), shipment_id))
        db.execute("""INSERT INTO shipment_updates(shipment_id,status,location,note,updated_by,created_at)
            VALUES(?,?,?,?,?,?)""", (shipment_id, status, location, note, user["id"], now()))
    flash("Shipment status updated.", "success")
    return redirect(url_for("shipment_detail", shipment_id=shipment_id))


@app.route("/shipments/<int:shipment_id>/assign", methods=["POST"])
@roles_required("admin")
def assign_rider(shipment_id):
    rider_id = request.form.get("rider_id", type=int) or None
    with get_db() as db:
        if rider_id and not db.execute("SELECT id FROM users WHERE id=? AND role='rider'", (rider_id,)).fetchone():
            flash("Selected rider is invalid.", "danger")
            return redirect(url_for("shipment_detail", shipment_id=shipment_id))
        db.execute("UPDATE shipments SET rider_id=?, updated_at=? WHERE id=?", (rider_id, now(), shipment_id))
    flash("Rider assignment saved.", "success")
    return redirect(url_for("shipment_detail", shipment_id=shipment_id))


@app.route("/track", methods=["GET", "POST"])
def track():
    tracking = request.values.get("tracking_number", "").strip().upper()
    shipment = None
    updates = []
    if tracking:
        with get_db() as db:
            shipment = db.execute("""SELECT tracking_number,recipient_name,origin,destination,status,created_at,updated_at
                FROM shipments WHERE tracking_number=?""", (tracking,)).fetchone()
            if shipment:
                updates = db.execute("""SELECT status,location,note,created_at FROM shipment_updates
                    WHERE shipment_id=(SELECT id FROM shipments WHERE tracking_number=?)
                    ORDER BY created_at DESC""", (tracking,)).fetchall()
            else:
                flash("No shipment found. Check the tracking number and try again.", "warning")
    return render_template("track.html", shipment=shipment, updates=updates, tracking=tracking)


@app.route("/admin/users", methods=["GET", "POST"])
@roles_required("admin")
def manage_users():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "")
        if not name or not email or len(password) < 8 or role not in ("admin", "rider", "customer"):
            flash("Complete all fields. Password must be at least 8 characters.", "danger")
        else:
            try:
                with get_db() as db:
                    db.execute("INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                               (name,email,generate_password_hash(password),role,now()))
                flash("User account created.", "success")
            except sqlite3.IntegrityError:
                flash("Email already exists.", "danger")
        return redirect(url_for("manage_users"))
    with get_db() as db:
        users = db.execute("SELECT id,name,email,role,created_at FROM users ORDER BY created_at DESC").fetchall()
    return render_template("users.html", users=users)


@app.route("/reports")
@roles_required("admin")
def reports():
    with get_db() as db:
        counts = db.execute("SELECT status,COUNT(*) total FROM shipments GROUP BY status ORDER BY total DESC").fetchall()
        recent = db.execute("""SELECT date(created_at) day, COUNT(*) total FROM shipments
            GROUP BY date(created_at) ORDER BY day DESC LIMIT 7""").fetchall()
    return render_template("reports.html", counts=counts, recent=recent)


@app.errorhandler(403)
def forbidden(_):
    return render_template("error.html", code=403, message="You don't have permission to access this page."), 403


@app.errorhandler(404)
def not_found(_):
    return render_template("error.html", code=404, message="The page or shipment you're looking for was not found."), 404


init_db()

if __name__ == "__main__":
    app.run(debug=True)
