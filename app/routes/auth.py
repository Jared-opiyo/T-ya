import secrets
import sqlite3
from app.database import connect_database
from contextlib import closing
from hmac import compare_digest

from flask import (
    Blueprint,
    current_app,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash

auth_bp = Blueprint("auth", __name__)


@auth_bp.app_context_processor
def inject_auth_navigation():
    if session.get("user_id") and "logout_csrf" not in session:
        session["logout_csrf"] = secrets.token_urlsafe(32)

    return {
        "logout_csrf_token": session.get("logout_csrf", "")
    }


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        if session.get("user_role") == "admin":
            return redirect(url_for("admin.index"))
        return redirect(url_for("auth.dashboard"))

    if "login_csrf" not in session:
        session["login_csrf"] = secrets.token_urlsafe(32)

    errors = {}
    email_value = ""

    if request.method == "POST":
        submitted_token = request.form.get("csrf_token", "")
        expected_token = session.get("login_csrf", "")

        if not expected_token or not compare_digest(
            submitted_token, expected_token
        ):
            errors["form"] = (
                "Your login form expired. Please reload and try again."
            )
            session.pop("login_csrf", None)
        else:
            email_value = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")

            if not email_value or not password:
                errors["form"] = "Enter your email address and password."
            else:
                database_path = current_app.config["DATABASE_PATH"]

                with closing(connect_database(database_path)) as connection:
                    connection.row_factory = sqlite3.Row
                    user = connection.execute(
                        """
                        SELECT id, first_name, last_name, email,
                               password_hash, status, role
                        FROM users
                        WHERE email = ?
                        """,
                        (email_value,),
                    ).fetchone()

                if not user or not check_password_hash(
                    user["password_hash"], password
                ):
                    errors["form"] = (
                        "Invalid email or password. Please try again."
                    )
                elif user["status"] != "active":
                    if user["status"] == "pending":
                        errors["form"] = (
                            "Your account is awaiting approval. "
                            "You can sign in once it has been activated."
                        )
                    else:
                        errors["form"] = (
                            "This account is not currently available "
                            "for sign-in. Please contact T-YA support."
                        )
                else:
                    # Clear any pre-login session data before signing in.
                    session.clear()
                    session["user_id"] = user["id"]
                    session["user_role"] = user["role"]
                    session["user_name"] = (
                        f"{user['first_name']} {user['last_name']}"
                    )
                    session.permanent = True

                    if user["role"] == "admin":
                        return redirect(url_for("admin.index"))
                    return redirect(url_for("auth.dashboard"))

    return render_template(
        "auth/login.html",
        errors=errors,
        email=email_value,
        csrf_token=session.get("login_csrf", ""),
    ), (400 if errors else 200)


@auth_bp.get("/dashboard")
def dashboard():
    user_id = session.get("user_id")

    if not user_id:
        return redirect(url_for("auth.login"))

    database_path = current_app.config["DATABASE_PATH"]

    with closing(connect_database(database_path)) as connection:
        connection.row_factory = sqlite3.Row
        member = connection.execute(
            """
            SELECT
                u.id,
                u.first_name,
                u.last_name,
                u.email,
                u.status AS account_status,
                m.id AS membership_id,
                m.status AS membership_status,
                m.registration_fee_kes,
                m.monthly_contribution_kes,
                m.created_at AS membership_created_at,
                p.name AS plan_name,
                p.category AS plan_category,
                p.grace_period_months
            FROM users AS u
            LEFT JOIN memberships AS m ON m.user_id = u.id
            LEFT JOIN membership_plans AS p ON p.id = m.plan_id
            WHERE u.id = ?
            ORDER BY m.id DESC
            LIMIT 1
            """,
            (user_id,),
        ).fetchone()

    if not member or member["account_status"] != "active":
        session.clear()
        return redirect(url_for("auth.login"))

    return render_template("dashboard.html", member=member)


@auth_bp.post("/logout")
def logout():
    submitted_token = request.form.get("csrf_token", "")
    expected_token = session.get("logout_csrf", "")

    if not expected_token or not compare_digest(
        submitted_token, expected_token
    ):
        return (
            "Your logout request could not be verified. "
            "Return to the dashboard and try again.",
            400,
        )

    session.clear()
    return redirect(url_for("public.home"))
