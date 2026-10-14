//! Which signing keys of an identity were valid at a position of its chain: a key signs the event at
//! `P` only if the chain below `P` added it and did not revoke it. Pure logic, no I/O.

use base64::Engine as _;
use uuid::Uuid;

use crate::event_payloads::{
    IdentityRecoveredPayload, IdentitySigningKeyAddedPayload, IdentitySigningKeyRevokedPayload,
};
use crate::events::ProtocolEvent;

/// One key of an identity and where its chain added and revoked it. `added_seq` 0 is an inception key,
/// which the chain does not carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRecord {
    pub signing_key_id: Uuid,
    pub public_key: [u8; 32],
    pub added_seq: u64,
    pub revoked_seq: Option<u64>,
}

/// The key records an accepted chain yields: a grant adds a key, a revocation ends one, and
/// `identity.recovered` ends every active key and adds its new one (key id = request id).
pub fn key_records(inception: &[(Uuid, [u8; 32])], accepted: &[ProtocolEvent]) -> Vec<KeyRecord> {
    let mut records: Vec<KeyRecord> = inception
        .iter()
        .map(|(id, key)| KeyRecord {
            signing_key_id: *id,
            public_key: *key,
            added_seq: 0,
            revoked_seq: None,
        })
        .collect();
    let decode_key = |b64: &str| -> Option<[u8; 32]> {
        base64::engine::general_purpose::STANDARD
            .decode(b64)
            .ok()?
            .try_into()
            .ok()
    };
    for event in accepted {
        let Some(seq) = event.identity_chain.as_ref().map(|p| p.seq) else {
            continue;
        };
        match event.kind.as_str() {
            "identity.signing_key_added" => {
                let Ok(added) =
                    serde_json::from_value::<IdentitySigningKeyAddedPayload>(event.payload.clone())
                else {
                    continue;
                };
                if let Some(public_key) = decode_key(&added.public_key) {
                    records.push(KeyRecord {
                        signing_key_id: added.signing_key_id,
                        public_key,
                        added_seq: seq,
                        revoked_seq: None,
                    });
                }
            }
            "identity.signing_key_revoked" => {
                let Ok(revoked) = serde_json::from_value::<IdentitySigningKeyRevokedPayload>(
                    event.payload.clone(),
                ) else {
                    continue;
                };
                for record in records
                    .iter_mut()
                    .filter(|r| r.signing_key_id == revoked.signing_key_id)
                {
                    record.revoked_seq.get_or_insert(seq);
                }
            }
            "identity.recovered" => {
                let Ok(recovered) =
                    serde_json::from_value::<IdentityRecoveredPayload>(event.payload.clone())
                else {
                    continue;
                };
                for record in records.iter_mut() {
                    record.revoked_seq.get_or_insert(seq);
                }
                if let Some(public_key) = decode_key(&recovered.new_signing_public_key) {
                    records.push(KeyRecord {
                        signing_key_id: recovered.request_id,
                        public_key,
                        added_seq: seq,
                        revoked_seq: None,
                    });
                }
            }
            _ => {}
        }
    }
    records
}

/// How a key stood at a chain position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAt {
    /// Added below the position and not revoked below it.
    Valid([u8; 32]),
    /// Added below the position but revoked below it.
    Revoked,
    /// Not added below the position (or never).
    Unknown,
}

/// Judges a key at `position` (the signed event's `seq`; a guardian's next `seq` for an approval): valid
/// iff the chain below it added and did not revoke it, so a key can revoke itself.
pub fn key_at(records: &[KeyRecord], signing_key_id: Uuid, position: u64) -> KeyAt {
    let Some(record) = records
        .iter()
        .find(|r| r.signing_key_id == signing_key_id && r.added_seq < position)
    else {
        return KeyAt::Unknown;
    };
    match record.revoked_seq {
        Some(revoked) if revoked < position => KeyAt::Revoked,
        _ => KeyAt::Valid(record.public_key),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::IdentityChainPosition;
    use crate::ids::GlobalId;
    use time::OffsetDateTime;

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    fn event(kind: &str, seq: u64, payload: serde_json::Value) -> ProtocolEvent {
        let id = crate::identity_id::IdentityId::random_for_tests();
        let gid = GlobalId::new("identity", &id.to_string(), "self", "x");
        ProtocolEvent {
            id: Uuid::new_v4(),
            kind: kind.to_string(),
            issuer: gid.clone(),
            subject: gid,
            payload,
            timestamp: OffsetDateTime::UNIX_EPOCH,
            version: 2,
            identity_chain: Some(IdentityChainPosition::current(seq, None)),
        }
    }

    fn added(key_id: Uuid, key: [u8; 32], seq: u64) -> ProtocolEvent {
        event(
            "identity.signing_key_added",
            seq,
            serde_json::json!({
                "signing_key_id": key_id,
                "public_key": b64(&key),
                "approved_by_signing_key_id": Uuid::nil(),
                "identity_id": crate::identity_id::IdentityId::random_for_tests(),
                "kind": "device_grant",
            }),
        )
    }

    fn revoked(key_id: Uuid, seq: u64) -> ProtocolEvent {
        event(
            "identity.signing_key_revoked",
            seq,
            serde_json::json!({
                "signing_key_id": key_id,
                "identity_id": crate::identity_id::IdentityId::random_for_tests(),
                "revoked_by_signing_key_id": Uuid::nil(),
                "signature": b64(&[0u8; 64]),
            }),
        )
    }

    #[test]
    fn a_key_signs_only_above_the_event_that_added_it_and_below_its_revocation() {
        let (inception, grant) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let chain = [
            added(grant, [2; 32], 2),
            revoked(grant, 5),
            revoked(inception, 7),
        ];
        let records = key_records(&[(inception, [1; 32])], &chain);
        assert_eq!(key_at(&records, inception, 1), KeyAt::Valid([1; 32]));
        assert_eq!(key_at(&records, grant, 2), KeyAt::Unknown);
        assert_eq!(key_at(&records, grant, 3), KeyAt::Valid([2; 32]));
        assert_eq!(key_at(&records, grant, 5), KeyAt::Valid([2; 32]));
        assert_eq!(key_at(&records, grant, 6), KeyAt::Revoked);
        assert_eq!(key_at(&records, inception, 7), KeyAt::Valid([1; 32]));
        assert_eq!(key_at(&records, inception, 8), KeyAt::Revoked);
        assert_eq!(key_at(&records, Uuid::from_u128(9), 3), KeyAt::Unknown);
    }

    #[test]
    fn a_genuine_older_event_stays_valid_after_its_key_is_revoked_later() {
        let (inception, grant) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let chain = [added(grant, [2; 32], 1), revoked(grant, 4)];
        let records = key_records(&[(inception, [1; 32])], &chain);
        assert_eq!(key_at(&records, grant, 3), KeyAt::Valid([2; 32]));
        assert_eq!(key_at(&records, grant, 9), KeyAt::Revoked);
    }

    #[test]
    fn a_recovery_ends_every_earlier_key_and_adds_the_new_one() {
        let (inception, new_key) = (Uuid::from_u128(1), Uuid::from_u128(3));
        let recovered = event(
            "identity.recovered",
            3,
            serde_json::json!({
                "request_id": new_key,
                "device_label": null,
                "new_signing_public_key": b64(&[3; 32]),
                "request": {
                    "request_id": new_key, "threshold": 2,
                    "new_signing_public_key": b64(&[3; 32]),
                    "config_event_hash": "00".repeat(32), "signature": "",
                },
                "request_entry_hash": "00".repeat(32),
                "approvals": [],
            }),
        );
        let records = key_records(&[(inception, [1; 32])], &[recovered]);
        assert_eq!(key_at(&records, inception, 3), KeyAt::Valid([1; 32]));
        assert_eq!(key_at(&records, inception, 4), KeyAt::Revoked);
        assert_eq!(key_at(&records, new_key, 3), KeyAt::Unknown);
        assert_eq!(key_at(&records, new_key, 4), KeyAt::Valid([3; 32]));
    }
}
