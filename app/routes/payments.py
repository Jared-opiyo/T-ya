import json
import secrets
import sqlite3
from contextlib import closing

from app.database import (
    connect_database,
    inserted_id,
    integrity_error_types,
    using_postgresql,
)
from datetime import date
from hmac import compare_digest

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    session,
    url_for,
)

from flask import request

payments_bp = Blueprint("payments", __name__)


def _member_and_membership(connection, user_id):
    """Return an active member and their latest linked membership."""
    user = connection.execute(
        """
        SELECT id, first_name, status, role
        FROM users
        WHERE id = ?
        """,
        (user_id,),
    ).fetchone()

    if not user or user["status"] != "active" or user["role"] != "member":
        return None, None

    membership = connection.execute(
        """
        SELECT
            m.id,
            m.member_name,
            m.status AS membership_status,
            m.registration_fee_kes,
            m.monthly_contribution_kes,
            p.name AS plan_name
        FROM memberships AS m
        LEFT JOIN membership_plans AS p ON p.id = m.plan_id
        WHERE m.user_id = ?
        ORDER BY m.id DESC
        LIMIT 1
        """,
        (user_id,),
    ).fetchone()

    return user, membership


@payments_bp.route("/payments", methods=["GET", "POST"])
def payment_page():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("auth.login"))

    if session.get("user_role") == "admin":
        return redirect(url_for("admin.index"))

    if "payment_csrf" not in session:
        session["payment_csrf"] = secrets.token_urlsafe(32)

    errors = {}
    form_data = {
        "payment_type": "registration_fee",
        "payment_method": "mpesa",
        "payment_date": date.today().isoformat(),
    }

    database_path = current_app.config["DATABASE_PATH"]

    with closing(connect_database(database_path)) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")

        user, membership = _member_and_membership(connection, user_id)

        if not user:
            session.clear()
            return redirect(url_for("auth.login"))

        if request.method == "POST":
            submitted_token = request.form.get("csrf_token", "")
            expected_token = session.get("payment_csrf", "")

            if not expected_token or not compare_digest(
                submitted_token, expected_token
            ):
                errors["form"] = (
                    "Your payment form expired. Reload the page and try again."
                )
                session.pop("payment_csrf", None)
            elif not membership:
                errors["form"] = (
                    "There is no membership linked to your account yet."
                )
            else:
                payment_type = request.form.get("payment_type", "").strip()
                amount_text = request.form.get("amount_kes", "").strip()
                payment_method = request.form.get("payment_method", "").strip()
                reference = request.form.get(
                    "transaction_reference", ""
                ).strip()[:100]
                payment_date = request.form.get("payment_date", "").strip()
                member_note = request.form.get("member_note", "").strip()[:500]

                form_data = {
                    "payment_type": payment_type,
                    "amount_kes": amount_text,
                    "payment_method": payment_method,
                    "transaction_reference": reference,
                    "payment_date": payment_date,
                    "member_note": member_note,
                }

                if payment_type not in {
                    "registration_fee", "monthly_contribution"
                }:
                    errors["payment_type"] = "Choose a valid payment type."

                try:
                    amount = int(amount_text)
                    if amount <= 0:
                        raise ValueError
                except (ValueError, TypeError):
                    amount = None
                    errors["amount_kes"] = (
                        "Enter a whole amount in Kenyan shillings greater than zero."
                    )

                if payment_method not in {"mpesa", "bank", "cash", "other"}:
                    errors["payment_method"] = "Choose a valid payment method."

                if len(reference) < 3:
                    errors["transaction_reference"] = (
                        "Enter a valid transaction or receipt reference."
                    )

                try:
                    parsed_date = date.fromisoformat(payment_date)
                    if parsed_date > date.today():
                        raise ValueError
                except (ValueError, TypeError):
                    parsed_date = None
                    errors["payment_date"] = (
                        "Enter a valid payment date that is not in the future."
                    )

                if not errors:
                    expected_amount = (
                        membership["registration_fee_kes"]
                        if payment_type == "registration_fee"
                        else membership["monthly_contribution_kes"]
                    )

                    if amount != expected_amount:
                        errors["amount_kes"] = (
                            f"For this payment type, the expected amount is "
                            f"KSh {expected_amount:,}. Contact T-YA management "
                            "if your payment arrangement differs."
                        )

                if not errors and payment_type == "registration_fee":
                    existing = connection.execute(
                        """
                        SELECT status FROM payments
                        WHERE membership_id = ?
                          AND payment_type = 'registration_fee'
                          AND status IN ('pending', 'verified')
                        LIMIT 1
                        """,
                        (membership["id"],),
                    ).fetchone()

                    if existing:
                        errors["form"] = (
                            "A registration-fee report is already pending or "
                            "verified for this membership. Check your payment "
                            "history or contact management."
                        )

                if not errors:
                    try:
                        with connection:
                            payment_sql = """
                                INSERT INTO payments (
                                    membership_id, user_id, payment_type,
                                    amount_kes, payment_method,
                                    transaction_reference, payment_date,
                                    status, member_note
                                )
                                VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?)
                                """
                            if using_postgresql():
                                payment_sql = payment_sql.replace(
                                    "VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?)",
                                    "VALUES (%s, %s, %s, %s, %s, %s, %s, 'pending', %s) RETURNING id",
                                )
                            cursor = connection.execute(
                                payment_sql,
                                (
                                    membership["id"],
                                    user_id,
                                    payment_type,
                                    amount,
                                    payment_method,
                                    reference,
                                    parsed_date.isoformat(),
                                    member_note or None,
                                ),
                            )

                            payment_id = inserted_id(cursor)

                            connection.execute(
                                """
                                INSERT INTO audit_logs (
                                    actor_user_id, action, target_type,
                                    target_id, details_json
                                )
                                VALUES (?, ?, ?, ?, ?)
                                """,
                                (
                                    user_id,
                                    "payment_submitted",
                                    "payment",
                                    payment_id,
                                    json.dumps({
                                        "payment_type": payment_type,
                                        "amount_kes": amount,
                                        "payment_method": payment_method,
                                    }),
                                ),
                            )

                        session.pop("payment_csrf", None)
                        flash(
                            "Payment details submitted for review. "
                            "This submission is not confirmation that funds "
                            "have been received.",
                            "success",
                        )
                        return redirect(url_for("payments.payment_page"))

                    except integrity_error_types():
                        errors["transaction_reference"] = (
                            "This transaction reference has already been "
                            "reported for that payment method, or the record "
                            "could not be saved. Check the details and try again."
                        )

        history = []
        if membership:
            history = connection.execute(
                """
                SELECT id, payment_type, amount_kes, payment_method,
                       transaction_reference, payment_date, status,
                       member_note, review_note, created_at
                FROM payments
                WHERE user_id = ? AND membership_id = ?
                ORDER BY created_at DESC, id DESC
                """,
                (user_id, membership["id"]),
            ).fetchall()

    return render_template(
        "payments.html",
        member=user,
        membership=membership,
        history=history,
        errors=errors,
        form_data=form_data,
        csrf_token=session.get("payment_csrf", ""),
        today=date.today().isoformat(),
    )
