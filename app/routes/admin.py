import json
import secrets
import sqlite3
from app.database import connect_database
from contextlib import closing
from hmac import compare_digest

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

admin_bp = Blueprint("admin", __name__)


def _require_admin():
    """Verify administrator privileges against the live database."""
    user_id = session.get("user_id")

    if not user_id:
        return None, redirect(url_for("auth.login"))

    database_path = current_app.config["DATABASE_PATH"]

    with closing(connect_database(database_path)) as connection:
        connection.row_factory = sqlite3.Row
        user = connection.execute(
            "SELECT id, first_name, status, role FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()

    if not user or user["status"] != "active":
        session.clear()
        return None, redirect(url_for("auth.login"))

    if user["role"] != "admin":
        abort(403)

    return user, None


def _valid_csrf():
    submitted = request.form.get("csrf_token", "")
    expected = session.get("admin_csrf", "")

    return bool(expected) and compare_digest(submitted, expected)


def _return_to_admin():
    return redirect(url_for("admin.index"))


def _write_audit(connection, action, target_type, target_id, details=None):
    """Write an audit entry using the caller's current transaction."""
    import json

    connection.execute(
        """
        INSERT INTO audit_logs
            (actor_user_id, action, target_type, target_id, details_json)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            session.get("user_id"),
            action,
            target_type,
            target_id,
            json.dumps(details or {}, sort_keys=True),
        ),
    )


@admin_bp.get("/admin")
def index():
    admin, response = _require_admin()
    if response:
        return response

    if "admin_csrf" not in session:
        session["admin_csrf"] = secrets.token_urlsafe(32)

    database_path = current_app.config["DATABASE_PATH"]

    with closing(connect_database(database_path)) as connection:
        connection.row_factory = sqlite3.Row

        stats = {
            "total_users": connection.execute(
                "SELECT COUNT(*) FROM users"
            ).fetchone()[0],
            "active_users": connection.execute(
                "SELECT COUNT(*) FROM users WHERE status = 'active'"
            ).fetchone()[0],
            "pending_accounts": connection.execute(
                """
                SELECT COUNT(*) FROM users
                WHERE status = 'pending' AND role = 'member'
                """
            ).fetchone()[0],
            "total_memberships": connection.execute(
                "SELECT COUNT(*) FROM memberships"
            ).fetchone()[0],
            "pending_memberships": connection.execute(
                "SELECT COUNT(*) FROM memberships WHERE status = 'pending'"
            ).fetchone()[0],
            "pending_payments": connection.execute(
                "SELECT COUNT(*) FROM payments WHERE status = 'pending'"
            ).fetchone()[0],
            "active_plans": connection.execute(
                "SELECT COUNT(*) FROM membership_plans WHERE is_active = 1"
            ).fetchone()[0],
        }

        pending_accounts = connection.execute(
            """
            SELECT id, first_name, last_name, email, phone, created_at
            FROM users
            WHERE status = 'pending' AND role = 'member'
            ORDER BY created_at, id
            """
        ).fetchall()

        pending_memberships = connection.execute(
            """
            SELECT
                m.id AS membership_id,
                m.user_id,
                m.member_name,
                m.member_email,
                m.member_phone,
                m.registration_fee_kes,
                m.monthly_contribution_kes,
                m.status AS membership_status,
                CASE
                    WHEN EXISTS (
                        SELECT 1 FROM payments pay
                        WHERE pay.membership_id = m.id
                          AND pay.user_id = m.user_id
                          AND pay.payment_type = 'registration_fee'
                          AND pay.amount_kes = m.registration_fee_kes
                          AND pay.status = 'verified'
                    ) THEN 'verified'
                    WHEN EXISTS (
                        SELECT 1 FROM payments pay
                        WHERE pay.membership_id = m.id
                          AND pay.user_id = m.user_id
                          AND pay.payment_type = 'registration_fee'
                          AND pay.amount_kes = m.registration_fee_kes
                          AND pay.status = 'pending'
                    ) THEN 'pending'
                    WHEN EXISTS (
                        SELECT 1 FROM payments pay
                        WHERE pay.membership_id = m.id
                          AND pay.user_id = m.user_id
                          AND pay.payment_type = 'registration_fee'
                          AND pay.amount_kes = m.registration_fee_kes
                          AND pay.status = 'rejected'
                    ) THEN 'rejected'
                    ELSE 'not_submitted'
                END AS registration_fee_payment_status,
                CASE
                    WHEN EXISTS (
                        SELECT 1 FROM payments pay
                        WHERE pay.membership_id = m.id
                          AND pay.user_id = m.user_id
                          AND pay.payment_type = 'monthly_contribution'
                          AND pay.amount_kes = m.monthly_contribution_kes
                          AND pay.status = 'verified'
                    ) THEN 'verified'
                    WHEN EXISTS (
                        SELECT 1 FROM payments pay
                        WHERE pay.membership_id = m.id
                          AND pay.user_id = m.user_id
                          AND pay.payment_type = 'monthly_contribution'
                          AND pay.amount_kes = m.monthly_contribution_kes
                          AND pay.status = 'pending'
                    ) THEN 'pending'
                    WHEN EXISTS (
                        SELECT 1 FROM payments pay
                        WHERE pay.membership_id = m.id
                          AND pay.user_id = m.user_id
                          AND pay.payment_type = 'monthly_contribution'
                          AND pay.amount_kes = m.monthly_contribution_kes
                          AND pay.status = 'rejected'
                    ) THEN 'rejected'
                    ELSE 'not_submitted'
                END AS monthly_payment_status,
                m.created_at,
                p.name AS plan_name,
                p.category AS plan_category,
                u.status AS account_status
            FROM memberships AS m
            LEFT JOIN membership_plans AS p ON p.id = m.plan_id
            LEFT JOIN users AS u ON u.id = m.user_id
            WHERE m.status = 'pending'
            ORDER BY m.created_at, m.id
            """
        ).fetchall()

        recent_activity = connection.execute(
            """
            SELECT
                a.id,
                a.action,
                a.target_type,
                a.target_id,
                a.created_at,
                u.first_name AS actor_first_name,
                u.last_name AS actor_last_name
            FROM audit_logs AS a
            LEFT JOIN users AS u ON u.id = a.actor_user_id
            ORDER BY a.id DESC
            LIMIT 8
            """
        ).fetchall()

    return render_template(
        "admin/dashboard.html",
        admin=admin,
        stats=stats,
        pending_accounts=pending_accounts,
        pending_memberships=pending_memberships,
        recent_activity=recent_activity,
        admin_csrf_token=session["admin_csrf"],
    )




@admin_bp.get("/admin/members")
def members():
    """Search and filter member accounts."""
    admin, response = _require_admin()
    if response:
        return response

    if "admin_csrf" not in session:
        session["admin_csrf"] = secrets.token_urlsafe(32)

    search = request.args.get("q", "").strip()[:100]
    status_filter = request.args.get("status", "").strip()
    allowed_statuses = {"", "pending", "active", "suspended"}

    if status_filter not in allowed_statuses:
        status_filter = ""

    conditions = ["u.role = 'member'"]
    parameters = []

    if status_filter:
        conditions.append("u.status = ?")
        parameters.append(status_filter)

    if search:
        conditions.append("""
            (
                u.first_name LIKE ? OR
                u.last_name LIKE ? OR
                (u.first_name || ' ' || u.last_name) LIKE ? OR
                u.email LIKE ? OR
                u.phone LIKE ?
            )
        """)
        pattern = f"%{search}%"
        parameters.extend([pattern] * 5)

    query = """
        SELECT
            u.id, u.first_name, u.last_name, u.email, u.phone,
            u.status, u.created_at,
            (
                SELECT p.name
                FROM memberships AS m
                LEFT JOIN membership_plans AS p ON p.id = m.plan_id
                WHERE m.user_id = u.id
                ORDER BY m.created_at DESC, m.id DESC
                LIMIT 1
            ) AS plan_name,
            (
                SELECT m.status
                FROM memberships AS m
                WHERE m.user_id = u.id
                ORDER BY m.created_at DESC, m.id DESC
                LIMIT 1
            ) AS membership_status
        FROM users AS u
        WHERE """ + " AND ".join(conditions) + """
        ORDER BY u.created_at DESC, u.id DESC
        LIMIT 200
    """

    with closing(connect_database(current_app.config["DATABASE_PATH"])) as connection:
        connection.row_factory = sqlite3.Row
        member_rows = connection.execute(query, parameters).fetchall()

        total_members = connection.execute(
            "SELECT COUNT(*) FROM users WHERE role = 'member'"
        ).fetchone()[0]

    return render_template(
        "admin/members.html",
        admin=admin,
        members=member_rows,
        total_members=total_members,
        search=search,
        status_filter=status_filter,
        admin_csrf_token=session["admin_csrf"],
    )


@admin_bp.post("/admin/accounts/<int:user_id>/status")
def change_account_status(user_id):
    """Suspend or reactivate a member account."""
    admin, response = _require_admin()
    if response:
        return response

    if not _valid_csrf():
        abort(400, description="The form could not be verified. Reload the page.")

    action = request.form.get("action", "")
    target_status = {
        "suspend": "suspended",
        "reactivate": "active",
    }.get(action)

    if target_status is None:
        abort(400, description="Invalid account action.")

    if user_id == session.get("user_id"):
        flash("You cannot change your own administrator account here.", "warning")
        return redirect(url_for("admin.members"))

    database_path = current_app.config["DATABASE_PATH"]

    with closing(connect_database(database_path)) as connection:
        connection.execute("BEGIN IMMEDIATE")

        target = connection.execute(
            "SELECT id, role, status FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()

        expected_status = "active" if action == "suspend" else "suspended"

        if (
            target is None
            or target[1] != "member"
            or target[2] != expected_status
        ):
            connection.rollback()
            flash(
                "Account unchanged. It may already have a different status "
                "or may not be a member account.",
                "warning",
            )
        else:
            result = connection.execute(
                """
                UPDATE users
                SET status = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ? AND role = 'member' AND status = ?
                """,
                (target_status, user_id, expected_status),
            )

            if result.rowcount == 1:
                _write_audit(
                    connection,
                    "member_account_suspended" if action == "suspend"
                    else "member_account_reactivated",
                    "user",
                    user_id,
                    {"previous_status": expected_status, "new_status": target_status},
                )
                connection.commit()
                flash(
                    "Member account suspended. Membership records were not changed."
                    if action == "suspend"
                    else "Member account reactivated. Membership approval and payment "
                         "verification remain separate.",
                    "success",
                )
            else:
                connection.rollback()
                flash("Account status was not changed. Please reload the page.", "warning")

    search = request.form.get("q", "").strip()[:100]
    status_filter = request.form.get("status", "").strip()
    if status_filter not in {"", "pending", "active", "suspended"}:
        status_filter = ""

    return redirect(url_for(
        "admin.members",
        q=search,
        status=status_filter,
    ))

@admin_bp.post("/admin/accounts/<int:user_id>/approve")
def approve_account(user_id):
    admin, response = _require_admin()
    if response:
        return response

    if not _valid_csrf():
        abort(400, description="The approval form could not be verified. Reload the page.")

    database_path = current_app.config["DATABASE_PATH"]

    with closing(connect_database(database_path)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("BEGIN IMMEDIATE")

        result = connection.execute(
            """
            UPDATE users
            SET status = 'active',
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
              AND role = 'member'
              AND status = 'pending'
            """,
            (user_id,),
        )

        if result.rowcount == 1:
            _write_audit(
                connection,
                "member_account_approved",
                "user",
                user_id,
                {"new_status": "active"},
            )
            connection.commit()
            flash(
                "Member account approved. Membership approval and payment "
                "verification remain separate.",
                "success",
            )
        else:
            connection.rollback()
            flash(
                "Account was not changed. It may already be active, "
                "not pending, or unavailable.",
                "warning",
            )

    return _return_to_admin()


def _try_activate_membership(connection, membership_id, actor_user_id):
    """Activate only after approval and both required payments are verified."""
    membership = connection.execute(
        """
        SELECT m.id, m.user_id, m.status, m.registration_fee_kes,
               m.monthly_contribution_kes, u.status AS account_status
        FROM memberships AS m
        JOIN users AS u ON u.id = m.user_id
        WHERE m.id = ?
        """,
        (membership_id,),
    ).fetchone()

    if (
        membership is None
        or membership["status"] != "pending"
        or membership["account_status"] != "active"
    ):
        return False

    approval = connection.execute(
        """
        SELECT 1
        FROM audit_logs
        WHERE action = 'membership_approval_granted'
          AND target_type = 'membership'
          AND target_id = ?
        LIMIT 1
        """,
        (membership_id,),
    ).fetchone()

    if approval is None:
        return False

    registration_paid = connection.execute(
        """
        SELECT 1 FROM payments
        WHERE membership_id = ?
          AND user_id = ?
          AND payment_type = 'registration_fee'
          AND amount_kes = ?
          AND status = 'verified'
        LIMIT 1
        """,
        (
            membership_id,
            membership["user_id"],
            membership["registration_fee_kes"],
        ),
    ).fetchone()

    contribution_paid = connection.execute(
        """
        SELECT 1 FROM payments
        WHERE membership_id = ?
          AND user_id = ?
          AND payment_type = 'monthly_contribution'
          AND amount_kes = ?
          AND status = 'verified'
        LIMIT 1
        """,
        (
            membership_id,
            membership["user_id"],
            membership["monthly_contribution_kes"],
        ),
    ).fetchone()

    if registration_paid is None or contribution_paid is None:
        return False

    result = connection.execute(
        """
        UPDATE memberships
        SET status = 'active', updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND status = 'pending'
        """,
        (membership_id,),
    )

    if result.rowcount != 1:
        return False

    _write_audit(
        connection,
        "membership_activated",
        "membership",
        membership_id,
        {
            "previous_status": "pending",
            "new_status": "active",
            "user_id": membership["user_id"],
            "activated_by_admin_id": actor_user_id,
            "requirements": [
                "membership_approval_granted",
                "verified_registration_fee",
                "verified_first_monthly_contribution",
            ],
        },
    )
    return True


@admin_bp.post("/admin/memberships/<int:membership_id>/approve")
def approve_membership(membership_id):
    admin, response = _require_admin()
    if response:
        return response

    if not _valid_csrf():
        abort(400, description="The approval form could not be verified. Reload the page.")

    database_path = current_app.config["DATABASE_PATH"]

    with closing(connect_database(database_path)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.row_factory = sqlite3.Row
        connection.execute("BEGIN IMMEDIATE")

        membership = connection.execute(
            """
            SELECT m.id, m.user_id, m.status AS membership_status,
                   u.status AS account_status
            FROM memberships AS m
            LEFT JOIN users AS u ON u.id = m.user_id
            WHERE m.id = ?
            """,
            (membership_id,),
        ).fetchone()

        if (
            membership is None
            or membership["membership_status"] != "pending"
            or membership["user_id"] is None
            or membership["account_status"] != "active"
        ):
            connection.rollback()
            flash(
                "Membership was not approved. Confirm that it is pending "
                "and its associated account is active.",
                "warning",
            )
            return _return_to_admin()

        _write_audit(
            connection,
            "membership_approval_granted",
            "membership",
            membership_id,
            {
                "user_id": membership["user_id"],
                "membership_status_remains": "pending_until_requirements_met",
            },
        )

        activated = _try_activate_membership(
            connection, membership_id, session["user_id"]
        )
        connection.commit()

    if activated:
        flash(
            "Membership approved and activated. Both required payments "
            "have been verified.",
            "success",
        )
    else:
        flash(
            "Membership approval recorded. It will activate automatically "
            "once the registration fee and first monthly contribution "
            "are verified.",
            "success",
        )

    return _return_to_admin()


@admin_bp.get("/admin/payments")
def payments():
    """Show reported payments for administrator review."""
    admin, response = _require_admin()
    if response:
        return response

    if "admin_csrf" not in session:
        session["admin_csrf"] = secrets.token_urlsafe(32)

    status_filter = request.args.get("status", "").strip().lower()
    if status_filter not in {"", "pending", "verified", "rejected"}:
        status_filter = ""

    database_path = current_app.config["DATABASE_PATH"]
    conditions = []
    parameters = []

    if status_filter:
        conditions.append("p.status = ?")
        parameters.append(status_filter)

    where_clause = (
        "WHERE " + " AND ".join(conditions) if conditions else ""
    )

    with closing(connect_database(database_path)) as connection:
        connection.row_factory = sqlite3.Row
        records = connection.execute(
            f"""
            SELECT
                p.id, p.membership_id, p.user_id, p.payment_type,
                p.amount_kes, p.payment_method, p.transaction_reference,
                p.payment_date, p.status, p.member_note, p.review_note,
                p.created_at, p.reviewed_at,
                u.first_name, u.last_name, u.email,
                m.member_name, m.member_email,
                mp.name AS plan_name,
                reviewer.first_name AS reviewer_first_name,
                reviewer.last_name AS reviewer_last_name
            FROM payments AS p
            JOIN users AS u ON u.id = p.user_id
            JOIN memberships AS m ON m.id = p.membership_id
            LEFT JOIN membership_plans AS mp ON mp.id = m.plan_id
            LEFT JOIN users AS reviewer ON reviewer.id = p.reviewed_by
            {where_clause}
            ORDER BY
                CASE p.status WHEN 'pending' THEN 0 ELSE 1 END,
                p.created_at DESC, p.id DESC
            LIMIT 200
            """,
            parameters,
        ).fetchall()

    return render_template(
        "admin/payments.html",
        admin=admin,
        payments=records,
        status_filter=status_filter,
        admin_csrf_token=session["admin_csrf"],
    )


@admin_bp.post("/admin/payments/<int:payment_id>/review")
def review_payment(payment_id):
    """Verify or reject a pending payment and audit the decision."""
    admin, response = _require_admin()
    if response:
        return response

    if not _valid_csrf():
        abort(400, description="The review form could not be verified. Reload the page.")

    decision = request.form.get("decision", "").strip().lower()
    review_note = request.form.get("review_note", "").strip()[:500]

    if decision not in {"verify", "reject"}:
        abort(400, description="Choose a valid payment-review decision.")

    if decision == "reject" and not review_note:
        flash("Please provide a reason when rejecting a payment.", "warning")
        return redirect(url_for("admin.payments", status="pending"))

    new_status = "verified" if decision == "verify" else "rejected"
    action = "payment_verified" if decision == "verify" else "payment_rejected"

    database_path = current_app.config["DATABASE_PATH"]

    with closing(connect_database(database_path)) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("BEGIN IMMEDIATE")

        payment = connection.execute(
            """
            SELECT id, user_id, membership_id, payment_type,
                   amount_kes, payment_method, transaction_reference, status
            FROM payments
            WHERE id = ?
            """,
            (payment_id,),
        ).fetchone()

        if not payment or payment["status"] != "pending":
            connection.rollback()
            flash(
                "Payment was not changed. It may already have been reviewed "
                "or may no longer be available.",
                "warning",
            )
            return redirect(url_for("admin.payments"))

        result = connection.execute(
            """
            UPDATE payments
            SET status = ?,
                reviewed_by = ?,
                reviewed_at = CURRENT_TIMESTAMP,
                review_note = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status = 'pending'
            """,
            (
                new_status,
                session["user_id"],
                review_note or None,
                payment_id,
            ),
        )

        if result.rowcount != 1:
            connection.rollback()
            flash("Payment review could not be saved. Please try again.", "warning")
            return redirect(url_for("admin.payments"))

        _write_audit(
            connection,
            action,
            "payment",
            payment_id,
            {
                "previous_status": "pending",
                "new_status": new_status,
                "user_id": payment["user_id"],
                "membership_id": payment["membership_id"],
                "payment_type": payment["payment_type"],
                "amount_kes": payment["amount_kes"],
                "payment_method": payment["payment_method"],
                "transaction_reference": payment["transaction_reference"],
                "review_note": review_note or None,
            },
        )
        activated = False
        if decision == "verify":
            activated = _try_activate_membership(
                connection, payment["membership_id"], session["user_id"]
            )

        connection.commit()

    if decision == "reject":
        flash("Payment rejected. Membership status was not changed.", "success")
    elif activated:
        flash(
            "Payment verified. All activation requirements are satisfied; "
            "the membership is now active.",
            "success",
        )
    else:
        flash(
            "Payment verified. The membership remains pending until "
            "approval and both required payments are satisfied.",
            "success",
        )

    return redirect(url_for("admin.payments"))


@admin_bp.get("/admin/audit-logs")
def audit_logs():
    """Display a read-only, paginated audit history for administrators."""
    admin, response = _require_admin()
    if response:
        return response

    database_path = current_app.config["DATABASE_PATH"]

    action_filter = request.args.get("action", "").strip()[:80]
    target_filter = request.args.get("target_type", "").strip().lower()
    allowed_targets = {"", "user", "membership", "payment"}

    if target_filter not in allowed_targets:
        target_filter = ""

    try:
        page = max(1, int(request.args.get("page", "1")))
    except (TypeError, ValueError):
        page = 1

    per_page = 25
    conditions = []
    parameters = []

    if action_filter:
        conditions.append("a.action LIKE ?")
        parameters.append("%" + action_filter + "%")

    if target_filter:
        conditions.append("a.target_type = ?")
        parameters.append(target_filter)

    where_clause = (
        "WHERE " + " AND ".join(conditions)
        if conditions else ""
    )

    with closing(connect_database(database_path)) as connection:
        connection.row_factory = sqlite3.Row

        total_entries = connection.execute(
            f"SELECT COUNT(*) FROM audit_logs AS a {where_clause}",
            parameters,
        ).fetchone()[0]

        total_pages = max(1, (total_entries + per_page - 1) // per_page)
        page = min(page, total_pages)
        offset = (page - 1) * per_page

        entries = connection.execute(
            f"""
            SELECT
                a.id,
                a.action,
                a.target_type,
                a.target_id,
                a.details_json,
                a.created_at,
                a.actor_user_id,
                u.first_name AS actor_first_name,
                u.last_name AS actor_last_name,
                u.email AS actor_email
            FROM audit_logs AS a
            LEFT JOIN users AS u ON u.id = a.actor_user_id
            {where_clause}
            ORDER BY a.id DESC
            LIMIT ? OFFSET ?
            """,
            parameters + [per_page, offset],
        ).fetchall()

    # Parse JSON defensively; templates display the resulting text escaped.
    safe_entries = []
    for entry in entries:
        item = dict(entry)
        try:
            parsed_details = json.loads(item["details_json"] or "{}")
            item["details_display"] = json.dumps(
                parsed_details,
                indent=2,
                ensure_ascii=False,
                sort_keys=True,
            )
        except (TypeError, ValueError):
            item["details_display"] = "Stored details are not valid JSON."
        safe_entries.append(item)

    return render_template(
        "admin/audit_logs.html",
        admin=admin,
        entries=safe_entries,
        action_filter=action_filter,
        target_filter=target_filter,
        page=page,
        total_pages=total_pages,
        total_entries=total_entries,
    )
