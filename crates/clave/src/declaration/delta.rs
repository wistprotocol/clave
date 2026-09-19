use serde_json::Value;

pub use wist_core::delta_fields::{
    validate_content_and_prev, validate_fields, validate_static, validate_version,
};

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SizeCaps {
    pub url_cap_bytes: i64,
    pub extract_cap_bytes: i64,
    pub links_cap_bytes: i64,
    pub link_url_cap_bytes: i64,
    pub summary_cap_bytes: i64,
}

impl SizeCaps {
    pub fn from_schedule(schedule: &wist_core::parameters::Schedule, at: i64) -> Self {
        Self {
            url_cap_bytes: schedule.value_at("url_cap_bytes", at).unwrap(),
            extract_cap_bytes: schedule.value_at("extract_cap_bytes", at).unwrap(),
            links_cap_bytes: schedule.value_at("links_cap_bytes", at).unwrap(),
            link_url_cap_bytes: schedule.value_at("link_url_cap_bytes", at).unwrap(),
            summary_cap_bytes: schedule.value_at("summary_cap_bytes", at).unwrap(),
        }
    }

    pub fn validate_delta(&self, envelope: &Value) -> Result<(), &'static str> {
        validate_static(envelope, self.url_cap_bytes, self.commitment_cap())
    }

    fn commitment_cap(&self) -> i128 {
        wist_core::delta_fields::commitment_cap(
            self.extract_cap_bytes,
            self.links_cap_bytes,
            self.summary_cap_bytes,
        )
    }

    pub fn validate_payload_sizes(&self, payload: &Value) -> Result<(), &'static str> {
        let content = &payload["content"];
        for (value, cap) in [
            (&content["extract"], i128::from(self.extract_cap_bytes)),
            (&content["links"], i128::from(self.links_cap_bytes)),
            (&content["summary"], i128::from(self.summary_cap_bytes)),
            (content, self.commitment_cap()),
        ] {
            Self::bounded(value, cap)?;
        }
        if let Some(urls) = content["links"]["urls"].as_array() {
            for url in urls {
                Self::bounded(url, i128::from(self.link_url_cap_bytes))?;
            }
        }
        Ok(())
    }

    fn bounded(value: &Value, cap: i128) -> Result<(), &'static str> {
        if wist_core::jcs::canonicalize(value)
            .map_err(|_| "WIST1-E05")?
            .len() as i128
            > cap
        {
            Err("WIST1-E04")
        } else {
            Ok(())
        }
    }
}

pub(crate) struct AdmissionProfile {
    pub sizes: SizeCaps,
    pub clock_skew_seconds: i64,
}

impl AdmissionProfile {
    pub fn start(
        db: &crate::db::Db,
        data_dir: &std::path::Path,
        clock: jiff::Timestamp,
    ) -> crate::error::Result<Self> {
        let at = clock.as_nanosecond().div_euclid(1_000_000_000) as i64;
        let mut history = crate::history::History::open(db, data_dir, db.last_epoch()?)?;
        while history.next_epoch()?.is_some() {}
        let initial = wist_core::parameters::Schedule::new(at);
        let schedule = history.schedule().unwrap_or(&initial);
        Ok(Self {
            sizes: SizeCaps::from_schedule(schedule, at),
            clock_skew_seconds: schedule.value_at("clock_skew_seconds", at).unwrap(),
        })
    }
}
