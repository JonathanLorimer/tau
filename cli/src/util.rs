//! Small cross-module helpers.

use std::time::{SystemTime, UNIX_EPOCH};

/// RFC 3339 UTC timestamp with second precision. Formatted manually via
/// `gmtime_r` to avoid pulling in a date crate; second precision is fine
/// for the kinds of events we emit (honeypot hits, audit-log entries).
pub fn iso_timestamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::gmtime_r(&secs, &mut tm) };
    if r.is_null() {
        return String::from("1970-01-01T00:00:00Z");
    }
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_timestamp_has_expected_shape() {
        let ts = iso_timestamp();
        assert_eq!(ts.len(), 20, "got: {ts}");
        assert!(ts.ends_with('Z'), "got: {ts}");
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[10..11], "T");
    }
}
