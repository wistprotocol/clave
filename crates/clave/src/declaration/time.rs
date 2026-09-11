use std::cmp::Ordering;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Instant<'a> {
    second: i64,
    fraction: &'a str,
}

fn digits(bytes: &[u8]) -> Option<i16> {
    bytes.iter().try_fold(0i16, |n, b| {
        b.is_ascii_digit().then(|| n * 10 + i16::from(b - b'0'))
    })
}

fn parse(value: &str) -> Option<Instant<'_>> {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !matches!(bytes[10], b'T' | b't')
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }
    let second = digits(&bytes[17..19])?;
    if second > 59 {
        return None;
    }
    let civil = jiff::civil::DateTime::new(
        digits(&bytes[..4])?,
        digits(&bytes[5..7])?.try_into().ok()?,
        digits(&bytes[8..10])?.try_into().ok()?,
        digits(&bytes[11..13])?.try_into().ok()?,
        digits(&bytes[14..16])?.try_into().ok()?,
        second.try_into().ok()?,
        0,
    )
    .ok()?;
    let mut offset_start = 19;
    let fraction = if bytes[19] == b'.' {
        offset_start = 20;
        while bytes.get(offset_start).is_some_and(u8::is_ascii_digit) {
            offset_start += 1;
        }
        if offset_start == 20 {
            return None;
        }
        value[20..offset_start].trim_end_matches('0')
    } else {
        ""
    };
    let offset = match &bytes[offset_start..] {
        [b'Z' | b'z'] => 0,
        [sign @ (b'+' | b'-'), h1, h2, b':', m1, m2] => {
            let hours = digits(&[*h1, *h2])?;
            let minutes = digits(&[*m1, *m2])?;
            if hours > 23 || minutes > 59 {
                return None;
            }
            let magnitude = i64::from(hours) * 3600 + i64::from(minutes) * 60;
            if *sign == b'+' {
                magnitude
            } else {
                -magnitude
            }
        }
        _ => return None,
    };
    let days = civil
        .date()
        .since((jiff::Unit::Day, jiff::civil::date(1970, 1, 1)))
        .ok()?
        .get_days();
    Some(Instant {
        second: i64::from(days) * 86_400
            + i64::from(civil.hour()) * 3600
            + i64::from(civil.minute()) * 60
            + i64::from(civil.second())
            - offset,
        fraction,
    })
}

pub(super) fn valid(value: &str) -> bool {
    parse(value).is_some()
}

pub(super) fn compare(left: &str, right: &str) -> Option<Ordering> {
    Some(parse(left)?.cmp(&parse(right)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_malformed_calendar_and_timestamp_syntax() {
        for invalid in [
            "",
            "2026-08-04",
            "2026-08-04T10:00:00",
            "2026-08-04 10:00:00Z",
            "2026-08-04T10:00:00.Z",
            "2026-08-04T10:00:00,5Z",
            "2026-08-04T10:00:00Z ",
            "2026-08-04T10:00:00+24:00",
            "2026-08-04T10:00:00+00:60",
            "2026-08-04T24:00:00Z",
            "2026-08-04T10:60:00Z",
            "2026-08-04T10:00:61Z",
            "2026-02-29T10:00:00Z",
            "1900-02-29T10:00:00Z",
            "2026-04-31T10:00:00Z",
            "2026-00-04T10:00:00Z",
            "２０２６-08-04T10:00:00Z",
            "2026-08-04T10:00:00.٥Z",
            "2026-08-04T10:00:00+01",
            "2026-08-04T10:00:00[UTC]",
        ] {
            assert_eq!(compare(invalid, "2026-08-04T10:00:00Z"), None, "{invalid}");
        }
    }
}
