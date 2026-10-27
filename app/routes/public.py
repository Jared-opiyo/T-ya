import re
import secrets
import sqlite3
from contextlib import closing

from app.database import (
    connect_database,
    inserted_id,
    integrity_error_types,
    using_postgresql,
)
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
from werkzeug.security import generate_password_hash

public_bp = Blueprint("public", __name__)


def load_membership_data():
    database_path = current_app.config["DATABASE_PATH"]

    with closing(connect_database(database_path)) as connection:
        connection.row_factory = sqlite3.Row

        plans = connection.execute("""
            SELECT
                id,
                name,
                category AS type,
                contribution_kes AS contribution,
                grace_period_months AS grace,
                eligibility AS description
            FROM membership_plans
            WHERE is_active = 1
            ORDER BY id
        """).fetchall()

        setting = connection.execute("""
            SELECT setting_value
            FROM app_settings
            WHERE setting_key = 'registration_fee_kes'
        """).fetchone()

    registration_fee = int(setting["setting_value"]) if setting else 224
    return plans, registration_fee


def registration_page(errors=None, form_data=None):
    plans, registration_fee = load_membership_data()

    if "registration_csrf" not in session:
        session["registration_csrf"] = secrets.token_urlsafe(32)

    return render_template(
        "auth/register.html",
        plans=plans,
        registration_fee=registration_fee,
        errors=errors or {},
        form_data=form_data or {},
        csrf_token=session["registration_csrf"],
    )


@public_bp.get("/")
def home():
    return render_template("home.html")


@public_bp.get("/about")
def about():
    return render_template("about.html")


@public_bp.get("/membership")
def membership():
    plans, registration_fee = load_membership_data()
    return render_template(
        "membership.html",
        plans=plans,
        registration_fee=registration_fee,
    )


@public_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return registration_page(
            form_data={"plan_id": request.args.get("plan_id", "")}
        )

    errors = {}

    submitted_token = request.form.get("csrf_token", "")
    expected_token = session.get("registration_csrf", "")

    if not expected_token or not compare_digest(
        submitted_token, expected_token
    ):
        errors["form"] = (
            "Your form session expired. Please reload the page and try again."
        )
        session.pop("registration_csrf", None)
        return registration_page(errors, request.form)

    first_name = request.form.get("first_name", "").strip()
    last_name = request.form.get("last_name", "").strip()
    email = request.form.get("email", "").strip().lower()
    phone = request.form.get("phone", "").strip()
    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")
    plan_id_text = request.form.get("plan_id", "").strip()

    if not first_name or len(first_name) > 80:
        errors["first_name"] = "Enter a first name of up to 80 characters."

    if not last_name or len(last_name) > 80:
        errors["last_name"] = "Enter a last name of up to 80 characters."

    if (
        len(email) > 254
        or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email)
    ):
        errors["email"] = "Enter a valid email address."

    if not phone or len(phone) > 30:
        errors["phone"] = "Enter a valid contact phone number."

    if not 8 <= len(password) <= 128:
        errors["password"] = "Password must contain 8–128 characters."

    if password != confirm_password:
        errors["confirm_password"] = "The passwords do not match."

    try:
        plan_id = int(plan_id_text)
        if plan_id < 1:
            raise ValueError
    except (ValueError, TypeError):
        plan_id = None
        errors["plan_id"] = "Choose a valid membership plan."

    plans, registration_fee = load_membership_data()

    if plan_id is not None and not any(
        plan["id"] == plan_id for plan in plans
    ):
        errors["plan_id"] = "That plan is unavailable. Choose an active plan."

    form_data = {
        "first_name": first_name,
        "last_name": last_name,
        "email": email,
        "phone": phone,
        "plan_id": plan_id_text,
    }

    if errors:
        return registration_page(errors, form_data), 400

    database_path = current_app.config["DATABASE_PATH"]

    try:
        with connect_database(database_path) as connection:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.row_factory = sqlite3.Row

            existing_user = connection.execute(
                "SELECT id FROM users WHERE email = ?",
                (email,),
            ).fetchone()

            if existing_user:
                errors["email"] = (
                    "An account with this email already exists."
                )
                return registration_page(errors, form_data), 400

            plan = connection.execute("""
                SELECT id, name, contribution_kes
                FROM membership_plans
                WHERE id = ? AND is_active = 1
            """, (plan_id,)).fetchone()

            if not plan:
                errors["plan_id"] = (
                    "That plan is no longer available. Please select another."
                )
                return registration_page(errors, form_data), 400

            fee_row = connection.execute("""
                SELECT setting_value
                FROM app_settings
                WHERE setting_key = 'registration_fee_kes'
            """).fetchone()

            fee = int(fee_row["setting_value"]) if fee_row else 224
            full_name = f"{first_name} {last_name}"

            user_sql = """
                INSERT INTO users (
                    first_name, last_name, email, phone,
                    password_hash, status
                )
                VALUES (?, ?, ?, ?, ?, 'pending')
            """
            if using_postgresql():
                user_sql = user_sql.replace(
                    "VALUES (?, ?, ?, ?, ?, 'pending')",
                    "VALUES (%s, %s, %s, %s, %s, 'pending') RETURNING id",
                )
            cursor = connection.execute(user_sql, (
                first_name,
                last_name,
                email,
                phone,
                generate_password_hash(password),
            ))
            user_id = inserted_id(cursor)

            membership_sql = """
                INSERT INTO memberships (
                    user_id, member_name, member_email, member_phone,
                    plan_id, registration_fee_kes,
                    monthly_contribution_kes, status
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')
            """
            if using_postgresql():
                membership_sql = membership_sql.replace(
                    "VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')",
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, 'pending') RETURNING id",
                )
            membership_cursor = connection.execute(membership_sql, (
                user_id,
                full_name,
                email,
                phone,
                plan["id"],
                fee,
                plan["contribution_kes"],
            ))
            membership_id = inserted_id(membership_cursor)

        session.pop("registration_csrf", None)
        session["registration_confirmation"] = {
            "reference": membership_id,
            "plan_name": plan["name"],
            "registration_fee": fee,
            "monthly_contribution": plan["contribution_kes"],
        }

        return redirect(url_for("public.registration_confirmation"))

    except integrity_error_types():
        errors["email"] = (
            "We could not create this account. The email may already be registered."
        )
        return registration_page(errors, form_data), 400


@public_bp.get("/register/confirmation")
def registration_confirmation():
    confirmation = session.pop("registration_confirmation", None)

    if not confirmation:
        return redirect(url_for("public.membership"))

    return render_template(
        "auth/registration_success.html",
        confirmation=confirmation,
    )
