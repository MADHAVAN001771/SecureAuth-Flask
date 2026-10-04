import os
import re
import sqlite3
from datetime import timedelta

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for
)
from flask_bcrypt import Bcrypt


app = Flask(__name__)

# --------------------------------------------------
# Flask configuration
# --------------------------------------------------

# In production, store this in an environment variable.
app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "change-this-development-secret-key"
)

app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)

# Prevent browser-side caching of sensitive pages.
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# For HTTPS production deployment, enable this:
# app.config["SESSION_COOKIE_SECURE"] = True

bcrypt = Bcrypt(app)

DATABASE = "database.db"


# --------------------------------------------------
# Database connection
# --------------------------------------------------

def get_db_connection():
    """
    Create a SQLite database connection.

    row_factory allows us to access columns using
    column names instead of numeric indexes.
    """
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


# --------------------------------------------------
# Initialize database
# --------------------------------------------------

def init_database():
    connection = get_db_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.commit()
    connection.close()


# --------------------------------------------------
# Input validation
# --------------------------------------------------

def validate_username(username):
    """
    Username:
    - 3 to 30 characters
    - letters, numbers and underscore only
    """
    pattern = r"^[A-Za-z0-9_]{3,30}$"
    return re.fullmatch(pattern, username) is not None


def validate_email(email):
    """
    Basic email format validation.
    """
    pattern = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
    return re.fullmatch(pattern, email) is not None


def validate_password(password):
    """
    Password requirements:
    - minimum 8 characters
    - at least one uppercase letter
    - at least one lowercase letter
    - at least one number
    - at least one special character
    """

    if len(password) < 8:
        return False

    if not re.search(r"[A-Z]", password):
        return False

    if not re.search(r"[a-z]", password):
        return False

    if not re.search(r"\d", password):
        return False

    if not re.search(r"[^A-Za-z0-9]", password):
        return False

    return True


# --------------------------------------------------
# Home page
# --------------------------------------------------

@app.route("/")
def home():

    if "user_id" in session:
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


# --------------------------------------------------
# Registration
# --------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():

    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # -------------------------------
        # Validate username
        # -------------------------------

        if not validate_username(username):
            flash(
                "Username must contain 3-30 characters using only letters, numbers or underscore.",
                "danger"
            )
            return render_template("register.html")

        # -------------------------------
        # Validate email
        # -------------------------------

        if not validate_email(email):
            flash("Please enter a valid email address.", "danger")
            return render_template("register.html")

        # -------------------------------
        # Validate password
        # -------------------------------

        if not validate_password(password):
            flash(
                "Password must contain at least 8 characters, "
                "one uppercase letter, one lowercase letter, "
                "one number and one special character.",
                "danger"
            )
            return render_template("register.html")

        # -------------------------------
        # Confirm password
        # -------------------------------

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("register.html")

        connection = get_db_connection()

        try:

            # Parameterized SQL query prevents SQL injection.
            existing_user = connection.execute(
                """
                SELECT id
                FROM users
                WHERE username = ? OR email = ?
                """,
                (username, email)
            ).fetchone()

            if existing_user:
                flash(
                    "Username or email is already registered.",
                    "danger"
                )
                return render_template("register.html")

            # -------------------------------
            # Hash password using bcrypt
            # -------------------------------

            password_hash = bcrypt.generate_password_hash(
                password
            ).decode("utf-8")

            # Store only the password hash.
            connection.execute(
                """
                INSERT INTO users
                (username, email, password_hash)
                VALUES (?, ?, ?)
                """,
                (username, email, password_hash)
            )

            connection.commit()

            flash(
                "Registration successful. You can now log in.",
                "success"
            )

            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            connection.rollback()

            flash(
                "Username or email is already registered.",
                "danger"
            )

        finally:
            connection.close()

    return render_template("register.html")


# --------------------------------------------------
# Login
# --------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash(
                "Username and password are required.",
                "danger"
            )
            return render_template("login.html")

        connection = get_db_connection()

        try:

            # Parameterized query protects against SQL injection.
            user = connection.execute(
                """
                SELECT id, username, email, password_hash
                FROM users
                WHERE username = ?
                """,
                (username,)
            ).fetchone()

        finally:
            connection.close()

        # Verify password against bcrypt hash.
        if user and bcrypt.check_password_hash(
            user["password_hash"],
            password
        ):

            # Remove any previous session data.
            session.clear()

            # Create a new authenticated session.
            session["user_id"] = user["id"]
            session["username"] = user["username"]

            session.permanent = True

            flash(
                "Login successful.",
                "success"
            )

            return redirect(url_for("dashboard"))

        # Don't reveal whether username or password was wrong.
        flash(
            "Invalid username or password.",
            "danger"
        )

    return render_template("login.html")


# --------------------------------------------------
# Dashboard
# --------------------------------------------------

@app.route("/dashboard")
def dashboard():

    # Authentication check.
    if "user_id" not in session:
        flash(
            "Please log in to access the dashboard.",
            "danger"
        )
        return redirect(url_for("login"))

    connection = get_db_connection()

    try:

        user = connection.execute(
            """
            SELECT id, username, email, created_at
            FROM users
            WHERE id = ?
            """,
            (session["user_id"],)
        ).fetchone()

    finally:
        connection.close()

    if user is None:
        session.clear()

        flash(
            "Your account could not be found.",
            "danger"
        )

        return redirect(url_for("login"))

    return render_template(
        "dashboard.html",
        user=user
    )


# --------------------------------------------------
# Logout
# --------------------------------------------------

@app.route("/logout")
def logout():

    # Remove authentication/session data.
    session.clear()

    flash(
        "You have been logged out successfully.",
        "success"
    )

    return redirect(url_for("login"))


# --------------------------------------------------
# Error handlers
# --------------------------------------------------

@app.errorhandler(404)
def page_not_found(error):

    return """
    <h1>404 - Page Not Found</h1>
    <p>The requested page does not exist.</p>
    """, 404


@app.errorhandler(500)
def internal_server_error(error):

    return """
    <h1>500 - Internal Server Error</h1>
    <p>An unexpected error occurred.</p>
    """, 500


# --------------------------------------------------
# Application startup
# --------------------------------------------------

if __name__ == "__main__":

    init_database()

    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )