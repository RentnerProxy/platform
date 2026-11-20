use super::reserve;

#[test]
fn attempts_expire_individually_at_three_hundred_seconds() {
    assert_eq!(reserve(0, &[]).unwrap(), [0]);
    assert_eq!(reserve(7, &[0, 3]).unwrap(), [0, 3, 7]);
    assert!(reserve(399, &[100, 101, 102]).is_err());
    assert_eq!(reserve(400, &[100, 101, 102]).unwrap(), [101, 102, 400]);
    assert!(reserve(9, &[10]).is_err());
    assert!(reserve(10, &[2, 1]).is_err());
}
