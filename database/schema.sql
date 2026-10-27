PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS app_settings (
    setting_key TEXT PRIMARY KEY,
    setting_value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO app_settings (setting_key, setting_value)
VALUES
    ('platform_name', 'T-YA'),
    ('platform_tagline', 'Trust. Integrity. You. Always.'),
    ('currency', 'KES'),
    ('registration_fee_kes', '224');

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    email TEXT NOT NULL COLLATE NOCASE UNIQUE,
    phone TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'active', 'suspended')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    role TEXT NOT NULL DEFAULT 'member'
        CHECK (role IN ('member', 'admin'))
);

CREATE TABLE IF NOT EXISTS membership_plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    category TEXT NOT NULL,
    contribution_kes INTEGER NOT NULL CHECK (contribution_kes >= 0),
    grace_period_months INTEGER NOT NULL CHECK (grace_period_months >= 0),
    eligibility TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS memberships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    member_name TEXT NOT NULL,
    member_email TEXT NOT NULL,
    member_phone TEXT,
    plan_id INTEGER NOT NULL,
    registration_fee_kes INTEGER NOT NULL DEFAULT 224,
    monthly_contribution_kes INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'active', 'suspended', 'cancelled')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (plan_id) REFERENCES membership_plans(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_memberships_email
    ON memberships(member_email);

CREATE INDEX IF NOT EXISTS idx_memberships_plan
    ON memberships(plan_id);

CREATE INDEX IF NOT EXISTS idx_memberships_status
    ON memberships(status);

INSERT OR IGNORE INTO membership_plans
    (name, category, contribution_kes, grace_period_months, eligibility)
VALUES
    (
        'T-YA HOPE',
        'Individual',
        124,
        4,
        'One member aged below 65 at joining.'
    ),
    (
        'T-YA LOVE',
        'Couple',
        199,
        4,
        'Husband and wife, both below 65.'
    ),
    (
        'T-YA UNITY',
        'Family',
        249,
        4,
        'Father and mother below 65, with children aged 1â€“17.'
    ),
    (
        'T-YA CARE',
        'Extended Family',
        299,
        4,
        'Immediate family and eligible biological/paternal parents; confirm full rules with management.'
    ),
    (
        'T-YA COMPASSION',
        'Extended Family Plus',
        399,
        5,
        'Expanded extended family and in-laws below 65, subject to confirmed terms.'
    ),
    (
        'T-YA DIGNITY',
        'Senior Parent',
        399,
        5,
        'Includes parents aged 67â€“77 under the supplied plan description.'
    ),
    (
        'T-YA PEACE',
        'Senior Parent Plus',
        499,
        5,
        'Includes parents aged 79â€“90 under the supplied plan description.'
    ),
    (
        'T-YA LEGACY',
        'Legacy Parent',
        624,
        7,
        'Includes parents aged 90â€“100 under the supplied plan description.'
    );

-- Administrative audit trail

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_user_id INTEGER,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id INTEGER,
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (actor_user_id)
        REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_actor
    ON audit_logs(actor_user_id);

CREATE INDEX IF NOT EXISTS idx_audit_logs_created
    ON audit_logs(created_at);

CREATE INDEX IF NOT EXISTS idx_audit_logs_target
    ON audit_logs(target_type, target_id);

-- Payment tracking table and indexes
CREATE TABLE IF NOT EXISTS payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    membership_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    payment_type TEXT NOT NULL
        CHECK (payment_type IN ('registration_fee', 'monthly_contribution')),
    amount_kes INTEGER NOT NULL CHECK (amount_kes > 0),
    payment_method TEXT NOT NULL
        CHECK (payment_method IN ('mpesa', 'bank', 'cash', 'other')),
    transaction_reference TEXT NOT NULL COLLATE NOCASE,
    payment_date TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'verified', 'rejected')),
    member_note TEXT,
    reviewed_by INTEGER,
    reviewed_at TEXT,
    review_note TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (membership_id) REFERENCES memberships(id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (reviewed_by) REFERENCES users(id),
    UNIQUE (payment_method, transaction_reference)
);

CREATE INDEX IF NOT EXISTS idx_payments_membership
    ON payments(membership_id);

CREATE INDEX IF NOT EXISTS idx_payments_user
    ON payments(user_id);

CREATE INDEX IF NOT EXISTS idx_payments_status
    ON payments(status);

CREATE INDEX IF NOT EXISTS idx_payments_created
    ON payments(created_at);
