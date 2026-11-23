use super::preserve_revocations;
use serde_json::json;

#[test]
fn promotion_cannot_remove_or_change_observed_revocations() {
    let older = json!({"revocations": [
        {"appId": "rentnerproxy.greeting", "version": "1.0.0", "reason": "fixture"}
    ]});
    let newer = json!({"revocations": [
        {"appId": "rentnerproxy.greeting", "version": "1.0.1", "reason": "second fixture"},
        {"appId": "rentnerproxy.greeting", "version": "1.0.0", "reason": "fixture"}
    ]});
    assert!(preserve_revocations(&older, &newer).is_ok());
    assert!(preserve_revocations(&newer, &older).is_err());
    let mut changed = older.clone();
    changed["revocations"][0]["reason"] = json!("different");
    assert!(preserve_revocations(&older, &changed).is_err());
}
