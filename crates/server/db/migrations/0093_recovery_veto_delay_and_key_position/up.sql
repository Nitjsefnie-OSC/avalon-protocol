-- An inception key is the only key an identity's chain does not carry; key validity by chain
-- position starts from it.
ALTER TABLE indexer_identity_signing_keys ADD COLUMN inception BOOLEAN NOT NULL DEFAULT false;

-- A chained event is claimed by its chain hash (which covers its content and position), so a hostile
-- node cannot pre-claim a genuine event by reusing its client-chosen id. Other events keep one claim
-- per event id and shard.
ALTER TABLE indexer_applied_events ADD COLUMN claim_key TEXT;
UPDATE indexer_applied_events SET claim_key = event_id::text || ':' || shard_id;
ALTER TABLE indexer_applied_events ALTER COLUMN claim_key SET NOT NULL;
ALTER TABLE indexer_applied_events DROP CONSTRAINT indexer_applied_events_pkey;
ALTER TABLE indexer_applied_events ADD CONSTRAINT indexer_applied_events_claim_key UNIQUE (claim_key);

-- The request names the configuration it relies on and is signed by the new key; its marker's ledger
-- event is what guardians bind and the delay is measured from.
ALTER TABLE recovery_requests ADD COLUMN config_event_hash TEXT;
ALTER TABLE recovery_requests ADD COLUMN request_signature TEXT;
ALTER TABLE recovery_requests ADD COLUMN request_event_id UUID;

-- An approval carries the guardian's chain position, and may carry the guardian's signed withdrawal.
ALTER TABLE recovery_approvals ADD COLUMN id UUID NOT NULL DEFAULT gen_random_uuid();
ALTER TABLE recovery_approvals ADD COLUMN guardian_seq BIGINT;
ALTER TABLE recovery_approvals ADD COLUMN guardian_prev_hash TEXT;
ALTER TABLE recovery_approvals ADD COLUMN withdrawal_signing_key_id UUID;
ALTER TABLE recovery_approvals ADD COLUMN withdrawal_seq BIGINT;
ALTER TABLE recovery_approvals ADD COLUMN withdrawal_prev_hash TEXT;
ALTER TABLE recovery_approvals ADD COLUMN withdrawal_signature TEXT;
CREATE UNIQUE INDEX recovery_approvals_id_idx ON recovery_approvals (id);
