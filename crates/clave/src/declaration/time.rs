use std::cmp::Ordering;
use wist_core::publisher_time;

pub(super) fn valid(value: &str) -> bool {
    publisher_time::valid(value)
}

pub(super) fn compare(left: &str, right: &str) -> Option<Ordering> {
    publisher_time::compare(left, right)
}

pub(super) fn within_clock_bound(
    value: &str,
    clock: jiff::Timestamp,
    allowance_s: i64,
) -> Option<bool> {
    let nanoseconds = clock.as_nanosecond();
    let fraction = format!("{:09}", nanoseconds.rem_euclid(1_000_000_000));
    publisher_time::within_bound(
        value,
        nanoseconds.div_euclid(1_000_000_000) + i128::from(allowance_s),
        &fraction,
    )
}
