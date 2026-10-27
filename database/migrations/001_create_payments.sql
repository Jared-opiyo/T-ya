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
