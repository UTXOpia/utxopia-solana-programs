// Account-level checks need a runtime AccountView; what is testable here is the byte parse
// that decides who counts as the program's admin.
use super::*;

/// ProgramData: u32 tag(3) + u64 slot + Option<Pubkey>(1 + 32).
fn programdata(tag: u32, has_authority: bool, authority: [u8; 32]) -> Vec<u8> {
    let mut d = tag.to_le_bytes().to_vec();
    d.extend_from_slice(&7u64.to_le_bytes());
    d.push(has_authority as u8);
    d.extend_from_slice(&authority);
    d
}

#[test]
fn reads_the_upgrade_authority() {
    let key = [7u8; 32];
    let data = programdata(3, true, key);
    assert_eq!(programdata_upgrade_authority(&data).unwrap(), key);
}

#[test]
fn rejects_finalized_program() {
    // `set-upgrade-authority --final` clears the Option — nobody is the admin any more, which
    // is what makes finalizing a permanent freeze of every upgrade-authority-gated instruction.
    let data = programdata(3, false, [0u8; 32]);
    assert!(programdata_upgrade_authority(&data).is_err());
}

#[test]
fn rejects_non_programdata_and_truncated_accounts() {
    // Tag 2 is the Program account, tag 1 the Buffer; neither carries an upgrade authority here.
    assert!(programdata_upgrade_authority(&programdata(2, true, [7u8; 32])).is_err());
    assert!(programdata_upgrade_authority(&programdata(3, true, [7u8; 32])[..44]).is_err());
}
