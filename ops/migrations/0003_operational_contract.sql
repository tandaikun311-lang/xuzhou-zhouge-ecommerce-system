CREATE TABLE IF NOT EXISTS team13_schema_contract(
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    contract_version INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

INSERT OR REPLACE INTO team13_schema_contract(singleton, contract_version, updated_at)
VALUES(1, 3, CAST(strftime('%s','now') AS INTEGER));

CREATE INDEX IF NOT EXISTS idx_v2_reimbursement_event_purchase_report
ON ecom_v2_reimbursement_events(purchase_id, report_id);
