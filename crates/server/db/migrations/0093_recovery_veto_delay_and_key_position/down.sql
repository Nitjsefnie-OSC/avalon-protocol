ALTER TABLE recovery_requests ADD COLUMN delay_ends_at TIMESTAMPTZ;
DROP INDEX recovery_approvals_id_idx;
ALTER TABLE recovery_approvals DROP COLUMN withdrawal_signature;
ALTER TABLE recovery_approvals DROP COLUMN withdrawal_prev_hash;
ALTER TABLE recovery_approvals DROP COLUMN withdrawal_seq;
ALTER TABLE recovery_approvals DROP COLUMN withdrawal_signing_key_id;
ALTER TABLE recovery_approvals DROP COLUMN guardian_prev_hash;
ALTER TABLE recovery_approvals DROP COLUMN guardian_seq;
ALTER TABLE recovery_approvals DROP COLUMN id;
ALTER TABLE recovery_requests DROP COLUMN request_event_id;
ALTER TABLE recovery_requests DROP COLUMN request_signature;
ALTER TABLE recovery_requests DROP COLUMN config_event_hash;
DELETE FROM indexer_applied_events a USING indexer_applied_events b
    WHERE a.ctid < b.ctid AND a.event_id = b.event_id AND a.shard_id = b.shard_id;
ALTER TABLE indexer_applied_events DROP CONSTRAINT indexer_applied_events_claim_key;
ALTER TABLE indexer_applied_events DROP COLUMN claim_key;
ALTER TABLE indexer_applied_events ADD PRIMARY KEY (event_id, shard_id);
ALTER TABLE indexer_identity_signing_keys DROP COLUMN inception;
