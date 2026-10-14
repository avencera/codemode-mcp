//! Dates and times as the calendar and reminders tools read and write them
//!
//! Agents pass ISO 8601 text. A value without an offset is read in the Mac's
//! own time zone, the one Calendar and Reminders show, and times come back in
//! that zone with its offset, so `2026-10-14T09:00` round-trips unchanged

use jiff::{
    SignedDuration, Timestamp, Zoned,
    civil::{Date, DateTime},
    tz::TimeZone,
};

/// A whole day or an exact moment
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum When {
    /// A calendar day with no time, as in all-day events and undated-time
    /// reminders
    Date(Date),
    /// An exact moment
    Time(Timestamp),
}

/// The Mac's time zone; `TZ` overrides it, as everywhere in jiff
pub fn local_zone() -> TimeZone {
    TimeZone::system()
}

impl When {
    /// Reads `YYYY-MM-DD`, a local `YYYY-MM-DDTHH:MM[:SS]` or an RFC 3339
    /// time with an offset; `field` names the argument in the error
    pub fn parse(field: &str, text: &str, zone: &TimeZone) -> Result<Self, String> {
        let text = text.trim();
        // jiff reads `2026-10-14T09:30` as a date too, dropping the time, so
        // only text with no time part is a date
        if !text.contains(['T', 't', ' '])
            && let Ok(date) = text.parse::<Date>()
        {
            return Ok(Self::Date(date));
        }
        if let Ok(time) = text.parse::<Timestamp>() {
            return Ok(Self::Time(time));
        }
        if let Ok(local) = text.parse::<DateTime>() {
            return local
                .to_zoned(zone.clone())
                .map(|zoned| Self::Time(zoned.timestamp()))
                .map_err(|error| format!("`{field}`: {error}"));
        }

        Err(format!(
            "`{field}` must be a date (2026-10-14), a local time (2026-10-14T09:30) or a time \
             with an offset (2026-10-14T09:30:00-05:00), got {text:?}"
        ))
    }

    /// The first moment it covers in `zone`
    pub fn start(self, zone: &TimeZone) -> Result<Timestamp, String> {
        match self {
            Self::Time(time) => Ok(time),
            Self::Date(date) => start_of_day(date, zone),
        }
    }

    /// The moment just after it ends: a date's next midnight, or the time
    /// itself
    pub fn end_exclusive(self, zone: &TimeZone) -> Result<Timestamp, String> {
        match self {
            Self::Time(time) => Ok(time),
            Self::Date(date) => date
                .tomorrow()
                .map_err(|error| error.to_string())
                .and_then(|next| start_of_day(next, zone)),
        }
    }

    /// The text agents see: a bare date, or the time in `zone` with its
    /// offset
    pub fn format(self, zone: &TimeZone) -> String {
        match self {
            Self::Date(date) => date.to_string(),
            Self::Time(time) => format_time(time, zone),
        }
    }
}

/// Midnight starting `date` in `zone`
pub fn start_of_day(date: Date, zone: &TimeZone) -> Result<Timestamp, String> {
    date.to_zoned(zone.clone())
        .map(|zoned| zoned.timestamp())
        .map_err(|error| error.to_string())
}

/// The day `time` falls on in `zone`
pub fn day_of(time: Timestamp, zone: &TimeZone) -> Date {
    time.to_zoned(zone.clone()).date()
}

/// `2026-10-14T09:30:00-05:00`
pub fn format_time(time: Timestamp, zone: &TimeZone) -> String {
    Zoned::new(time, zone.clone())
        .strftime("%Y-%m-%dT%H:%M:%S%:z")
        .to_string()
}

/// The token an update or delete must send back unchanged: UTC with
/// milliseconds, the precision both sides keep
pub fn format_stamp(time: Timestamp) -> String {
    Timestamp::from_millisecond(time.as_millisecond())
        .unwrap_or(time)
        .strftime("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string()
}

/// Whether the token an agent sent matches the item's current one
///
/// Both sides are compared at millisecond precision, so a token the agent
/// re-serialized with another offset still matches
pub fn stamp_matches(sent: Option<&str>, current: Option<Timestamp>) -> bool {
    let millis = |time: Timestamp| time.as_millisecond();

    match (sent, current) {
        (None, None) => true,
        (Some(sent), Some(current)) => sent
            .trim()
            .parse::<Timestamp>()
            .is_ok_and(|sent| millis(sent) == millis(current)),
        _ => false,
    }
}

/// Moments from EventKit's seconds-since-1970 doubles, kept to the
/// millisecond so tokens round-trip exactly
pub fn from_unix_seconds(seconds: f64) -> Timestamp {
    Timestamp::from_millisecond((seconds * 1000.0).round() as i64).unwrap_or(Timestamp::UNIX_EPOCH)
}

/// The inverse of [`from_unix_seconds`]
pub fn to_unix_seconds(time: Timestamp) -> f64 {
    time.as_millisecond() as f64 / 1000.0
}

/// One second before `time`; an all-day event stored as ending at 23:59:59
/// and one ending at the next midnight both end on the same day
pub fn just_before(time: Timestamp) -> Timestamp {
    time.checked_sub(SignedDuration::from_secs(1))
        .unwrap_or(time)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_text_reads_in_the_given_zone_and_formats_back_unchanged()
    -> Result<(), Box<dyn std::error::Error>> {
        let chicago = TimeZone::get("America/Chicago")?;

        let local = When::parse("start", "2026-10-14T09:30", &chicago)?;
        assert_eq!(local.format(&chicago), "2026-10-14T09:30:00-05:00");

        let offset = When::parse("start", "2026-10-14T14:30:00Z", &chicago)?;
        assert_eq!(offset, local);

        let date = When::parse("due", "2026-03-08", &chicago)?;
        assert_eq!(date.format(&chicago), "2026-03-08");
        // the DST change day is 23 hours long
        let length = date.end_exclusive(&chicago)?.as_second() - date.start(&chicago)?.as_second();
        assert_eq!(length, 23 * 3600);

        assert!(When::parse("due", "tomorrow", &chicago).is_err());
        Ok(())
    }

    #[test]
    fn stamps_match_at_millisecond_precision_whatever_the_offset()
    -> Result<(), Box<dyn std::error::Error>> {
        let current = from_unix_seconds(1_792_000_000.123_456);
        let token = format_stamp(current);
        assert_eq!(token, "2026-10-14T17:46:40.123Z");

        assert!(stamp_matches(Some(&token), Some(current)));
        assert!(stamp_matches(
            Some("2026-10-14T12:46:40.123-05:00"),
            Some(current)
        ));
        assert!(!stamp_matches(
            Some("2026-10-14T21:46:40.124Z"),
            Some(current)
        ));
        assert!(!stamp_matches(None, Some(current)));
        assert!(!stamp_matches(Some(&token), None));
        assert!(stamp_matches(None, None));
        Ok(())
    }
}
