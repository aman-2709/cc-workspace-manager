//! Activity classification (REQUIREMENTS.md §5.3): calendar days in the system time zone since the
//! latest meaningful modification. The same day boundaries drive the per-project status, the SQL
//! filters and the summary statistics, so they can never disagree.

use crate::config::ActivityConfig;
use jiff::civil::Date;
use jiff::tz::TimeZone;
use jiff::{Span, Timestamp};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Today,
    Recent,
    Inactive,
    Dormant,
    Unknown,
}

/// Activity filter of `GET /projects` (`week` = today + recent, §5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Filter {
    Today,
    Week,
    Inactive,
    Dormant,
    Unknown,
}

impl Filter {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "today" => Self::Today,
            "week" => Self::Week,
            "inactive" => Self::Inactive,
            "dormant" => Self::Dormant,
            "unknown" => Self::Unknown,
            _ => return None,
        })
    }
}

/// A timestamp range `[from, until)`; `None` ends are open. `unknown` selects rows without a timestamp.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Range {
    pub from: Option<i64>,
    pub until: Option<i64>,
    pub unknown: bool,
}

/// Unix seconds at which each bucket starts, for "now" in one time zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Boundaries {
    /// First instant of today.
    pub today: i64,
    /// First instant of the oldest *recent* day (`inactive_after_days - 1` days ago).
    pub recent: i64,
    /// First instant of the oldest *inactive* day (`dormant_after_days - 1` days ago).
    pub inactive: i64,
}

/// Classifies timestamps relative to "now" in a given time zone.
#[derive(Clone)]
pub struct Classifier {
    tz: TimeZone,
    inactive_after: i64,
    dormant_after: i64,
}

impl Classifier {
    pub fn new(tz: TimeZone, cfg: &ActivityConfig) -> Self {
        Self {
            tz,
            inactive_after: i64::from(cfg.inactive_after_days),
            dormant_after: i64::from(cfg.dormant_after_days),
        }
    }

    /// The same time zone with new thresholds (`PUT /settings`).
    pub fn with_thresholds(&self, cfg: &ActivityConfig) -> Self {
        Self::new(self.tz.clone(), cfg)
    }

    /// The system time zone (`TZ`, `/etc/localtime`), UTC if it cannot be determined.
    pub fn system(cfg: &ActivityConfig) -> Self {
        Self::new(TimeZone::try_system().unwrap_or(TimeZone::UTC), cfg)
    }

    fn date(&self, unix: i64) -> Option<Date> {
        Timestamp::from_second(unix)
            .ok()
            .map(|t| t.to_zoned_datetime(self.tz.clone()).date())
    }

    /// First instant of the local day `days_ago` days before `today`.
    fn start(&self, today: Date, days_ago: i64) -> Option<i64> {
        let day = today.checked_sub(Span::new().days(days_ago)).ok()?;
        let zoned = day.to_zoned_datetime(self.tz.clone()).ok()?;
        Some(zoned.timestamp().as_second())
    }

    /// Whole calendar days from `at` to `now`; negative for future timestamps.
    pub fn days_ago(&self, at: i64, now: i64) -> Option<i64> {
        let (a, n) = (self.date(at)?, self.date(now)?);
        Some(n.duration_since(a).as_secs() / 86_400)
    }

    pub fn status(&self, at: Option<i64>, now: i64) -> Status {
        let Some(days) = at.and_then(|at| self.days_ago(at, now)) else {
            return Status::Unknown;
        };
        if days <= 0 {
            Status::Today // includes timestamps slightly in the future (clock skew)
        } else if days < self.inactive_after {
            Status::Recent
        } else if days < self.dormant_after {
            Status::Inactive
        } else {
            Status::Dormant
        }
    }

    pub fn boundaries(&self, now: i64) -> Option<Boundaries> {
        let today = self.date(now)?;
        Some(Boundaries {
            today: self.start(today, 0)?,
            recent: self.start(today, self.inactive_after - 1)?,
            inactive: self.start(today, self.dormant_after - 1)?,
        })
    }

    pub fn range(&self, filter: Filter, now: i64) -> Option<Range> {
        let b = self.boundaries(now)?;
        let r = |from, until| Range {
            from,
            until,
            unknown: false,
        };
        Some(match filter {
            Filter::Today => r(Some(b.today), None),
            Filter::Week => r(Some(b.recent), None),
            Filter::Inactive => r(Some(b.inactive), Some(b.recent)),
            Filter::Dormant => r(None, Some(b.inactive)),
            Filter::Unknown => Range {
                from: None,
                until: None,
                unknown: true,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// US Eastern with DST rules, independent of the host's tz database.
    fn eastern() -> Classifier {
        Classifier::new(
            TimeZone::posix("EST5EDT,M3.2.0,M11.1.0").unwrap(),
            &ActivityConfig::default(),
        )
    }

    fn ts(s: &str, c: &Classifier) -> i64 {
        let dt: jiff::civil::DateTime = s.parse().unwrap();
        dt.to_zoned_datetime(c.tz.clone())
            .unwrap()
            .timestamp()
            .as_second()
    }

    #[test]
    fn bucket_boundaries_0_1_6_7_29_30() {
        let c = eastern();
        let now = ts("2026-06-30T12:00:00", &c);
        let cases = [
            ("2026-06-30T00:00:00", Status::Today),
            ("2026-06-29T23:59:59", Status::Recent), // 1 day: just before midnight
            ("2026-06-24T00:00:00", Status::Recent), // 6 days
            ("2026-06-23T23:59:59", Status::Inactive), // 7 days
            ("2026-06-01T00:00:00", Status::Inactive), // 29 days
            ("2026-05-31T23:59:59", Status::Dormant), // 30 days
            ("2020-01-01T00:00:00", Status::Dormant),
            ("2026-06-30T23:00:00", Status::Today), // later today (future)
            ("2026-07-02T00:00:00", Status::Today), // clock skew: future days count as today
        ];
        for (when, want) in cases {
            assert_eq!(c.status(Some(ts(when, &c)), now), want, "{when}");
        }
        assert_eq!(c.status(None, now), Status::Unknown);
    }

    /// The real-home report: "6 days ago" shown next to "Inactive". At a non-midnight time a
    /// change 6.5 × 24 h ago is 7 calendar days ago: Inactive, and outside "this week".
    #[test]
    fn the_6_and_7_day_boundary_at_a_non_midnight_time() {
        let c = eastern();
        let now = ts("2026-06-30T10:00:00", &c);
        let seven = ts("2026-06-23T23:00:00", &c); // 155 h = 6.46 × 24 h ago
        assert_eq!((now - seven) / 86_400, 6, "elapsed whole 24-hour periods");
        assert_eq!(c.days_ago(seven, now), Some(7));
        assert_eq!(c.status(Some(seven), now), Status::Inactive);
        let week = c.range(Filter::Week, now).unwrap();
        assert!(seven < week.from.unwrap(), "not in this week");
        let six = ts("2026-06-24T00:30:00", &c); // 6 calendar days, 153.5 h ago
        assert_eq!(c.days_ago(six, now), Some(6));
        assert_eq!(c.status(Some(six), now), Status::Recent);
        assert!(six >= week.from.unwrap(), "in this week");
        // The same at a late-evening "now".
        let now = ts("2026-06-30T23:30:00", &c);
        assert_eq!(c.days_ago(ts("2026-06-24T00:10:00", &c), now), Some(6));
        assert_eq!(c.days_ago(ts("2026-06-23T23:50:00", &c), now), Some(7));
    }

    #[test]
    fn calendar_days_not_24_hour_periods_across_midnight() {
        let c = eastern();
        let now = ts("2026-06-30T00:00:05", &c);
        assert_eq!(
            c.status(Some(ts("2026-06-29T23:59:55", &c)), now),
            Status::Recent,
            "ten seconds ago, but yesterday"
        );
        assert_eq!(c.days_ago(ts("2026-06-29T23:59:55", &c), now), Some(1));
    }

    #[test]
    fn dst_changes_do_not_shift_buckets() {
        let c = eastern();
        // Spring forward on 2026-03-08 (23-hour day), fall back on 2026-11-01 (25-hour day).
        let spring = ts("2026-03-09T00:30:00", &c);
        assert_eq!(c.days_ago(ts("2026-03-08T00:00:00", &c), spring), Some(1));
        assert_eq!(c.days_ago(ts("2026-03-02T00:00:00", &c), spring), Some(7));
        assert_eq!(
            c.status(Some(ts("2026-03-03T00:00:00", &c)), spring),
            Status::Recent
        );
        let fall = ts("2026-11-02T00:30:00", &c);
        assert_eq!(c.days_ago(ts("2026-11-01T23:59:00", &c), fall), Some(1));
        assert_eq!(c.days_ago(ts("2026-11-01T00:00:00", &c), fall), Some(1));
        let b = c.boundaries(fall).unwrap();
        assert_eq!(b.today, ts("2026-11-02T00:00:00", &c));
        assert_eq!(
            b.today - ts("2026-11-01T00:00:00", &c),
            25 * 3600,
            "the fall-back day is 25 hours long"
        );
    }

    #[test]
    fn filter_ranges_agree_with_status_for_every_hour_of_two_months() {
        let c = eastern();
        let now = ts("2026-11-03T09:00:00", &c); // just after a DST change
        let filters = [
            (Filter::Today, &[Status::Today][..]),
            (Filter::Week, &[Status::Today, Status::Recent][..]),
            (Filter::Inactive, &[Status::Inactive][..]),
            (Filter::Dormant, &[Status::Dormant][..]),
        ];
        let mut at = now - 60 * 86_400;
        while at <= now + 3600 {
            let status = c.status(Some(at), now);
            for (f, statuses) in filters {
                let r = c.range(f, now).unwrap();
                let in_range = r.from.is_none_or(|lo| at >= lo) && r.until.is_none_or(|hi| at < hi);
                assert_eq!(
                    in_range,
                    statuses.contains(&status),
                    "{f:?} at {at} ({status:?})"
                );
            }
            at += 1800;
        }
        assert!(c.range(Filter::Unknown, now).unwrap().unknown);
    }

    #[test]
    fn custom_thresholds_and_parse() {
        let c = Classifier::new(
            TimeZone::UTC,
            &ActivityConfig {
                inactive_after_days: 2,
                dormant_after_days: 3,
                events_per_project: 1,
            },
        );
        let now = 10 * 86_400 + 5;
        assert_eq!(c.status(Some(now - 86_400), now), Status::Recent);
        assert_eq!(c.status(Some(now - 2 * 86_400), now), Status::Inactive);
        assert_eq!(c.status(Some(now - 3 * 86_400), now), Status::Dormant);
        assert_eq!(Filter::parse("week"), Some(Filter::Week));
        assert_eq!(Filter::parse("all"), None);
        assert_eq!(Filter::parse("Today"), None);
    }
}
