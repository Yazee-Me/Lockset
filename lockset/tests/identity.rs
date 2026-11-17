//! Without a configured identity, the read-only reports still work and `check`
//! says so instead of aborting.

mod common;

use common::{lockset, strings, Repo};

#[test]
fn status_and_who_work_without_an_identity() {
    let repo = Repo::new("status");

    let status = lockset(&repo, &strings(&["status"]));
    let stdout = String::from_utf8_lossy(&status.stdout);
    assert_eq!(status.status.code(), Some(0), "{stdout}");
    assert!(stdout.contains("identity: none"), "{stdout}");

    let who = lockset(&repo, &strings(&["who"]));
    assert_eq!(
        who.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&who.stderr)
    );
}

#[test]
fn check_reports_the_missing_identity_instead_of_aborting() {
    let repo = Repo::new("check");

    let output = lockset(&repo, &strings(&["check"]));
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(1), "{stdout}");
    let identity = stdout
        .lines()
        .find(|line| line.starts_with("identity"))
        .unwrap_or_else(|| panic!("no identity check in: {stdout}"));
    assert!(identity.contains("FAIL"), "{identity}");
    assert!(identity.contains("key import"), "{identity}");
}
