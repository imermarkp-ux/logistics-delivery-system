
        else:

            try:

                with get_db() as db:

                    db.execute("""
                        INSERT INTO users (
                            name, email, password_hash,
                            role, created_at
                        )
                        VALUES (?, ?, ?, ?, ?)
                    """, (
                        name,
                        email,
                        generate_password_hash(password),
                        role,
                        now()
                    ))

                flash("User account created.", "success")

            except sqlite3.IntegrityError:

                flash("Email already exists.", "danger")

        return redirect(url_for("manage_users"))

    with get_db() as db:

        users = db.execute("""
            SELECT id, name, email, role, created_at
            FROM users
            ORDER BY created_at DESC
        """).fetchall()

    return render_template(
        "users.html",
        users=users
    )


# ==========================================
# ADMIN REPORTS
# ==========================================

@app.route("/reports")
@roles_required("admin")
def reports():

    with get_db() as db:

        counts = db.execute("""
            SELECT status, COUNT(*) total
            FROM shipments
            GROUP BY status
            ORDER BY total DESC
        """).fetchall()

        recent = db.execute("""
            SELECT date(created_at) day, COUNT(*) total
            FROM shipments
            GROUP BY date(created_at)
            ORDER BY day DESC
            LIMIT 7
        """).fetchall()

    return render_template(
        "reports.html",
        counts=counts,
        recent=recent
    )


# ==========================================
# ERROR HANDLERS
# ==========================================

@app.errorhandler(403)
def forbidden(_):

    return render_template(
        "error.html",
        code=403,
        message="You don't have permission to access this page."
    ), 403


@app.errorhandler(404)
def not_found(_):

    return render_template(
        "error.html",
        code=404,
        message="The page or shipment you're looking for was not found."
    ), 404


@app.errorhandler(500)
def server_error(_):

    return render_template(
        "error.html",
        code=500,
        message="Something went wrong. Please try again later."
    ), 500


# ==========================================
# INITIALIZE DATABASE
# ==========================================

init_db()


# ==========================================
# LOCAL DEVELOPMENT
# ==========================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=int(os.environ.get("PORT", 5000)),
        debug=not IS_VERCEL
    )
