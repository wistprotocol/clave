use super::{fetch_stage::ObjectKey, Pull};
use crate::collection::site::{Answer, Object, Request, Site};
use crate::db::Settled;
use crate::error::Result;
use crate::fetch::Octets;

fn kind(object: &Object<'_>) -> &'static str {
    match object {
        Object::Declaration => "declaration",
        Object::Catalog { .. } => "catalog",
        Object::TreeFile { .. } => "tree_file",
        Object::ChangeList { .. } => "change_list",
        Object::Payload { .. } => "payload",
    }
}

impl<C: Fn() -> jiff::Timestamp> Pull<'_, C> {
    fn declaration_answer(&self) -> Result<Answer> {
        let key = ObjectKey::Declaration;
        Ok(
            match self
                .db
                .pull_object(self.run.run_id, key.kind(), &key.name())?
                .and_then(|object| object.raw)
            {
                Some(octets) => Answer::Octets {
                    octets,
                    validator: None,
                },
                None => Answer::Failed,
            },
        )
    }
}

/// WIST-2 §5.2: the bound met first decides, and a per-pull limit in objects suspends before
/// the request it leaves no room for.
impl<C: Fn() -> jiff::Timestamp> Site for Pull<'_, C> {
    fn fetch(&mut self, request: &Request<'_>) -> Result<Answer> {
        if !request.object.metered() {
            return self.declaration_answer();
        }
        if self.run.work_objects == 0 || (self.items_begun > 0 && self.expired()) {
            return Ok(Answer::Suspended);
        }
        let db = self.db;
        let meter = self.meter_at((self.clock)())?;
        let spent = db.ingest_bytes(&meter.unit, &meter.day)?;
        let left = u64::try_from(meter.budget.saturating_sub(spent)).unwrap_or_default();
        let remainder = left.min(self.run.work_bytes);
        let interrupting = remainder < request.bound.saturating_add(1);
        let limit = if interrupting {
            remainder
        } else {
            request.bound
        };
        self.items_begun += 1;
        let mut run = self.run.clone();
        run.work_objects -= 1;
        if limit == 0 && interrupting {
            db.update_pull_run(&run)?;
            self.run = run;
            return Ok(Answer::Interrupted);
        }
        let path = request.object.path();
        let url = format!("{}{path}", self.base);
        let (kind, slot) = (
            kind(&request.object),
            format!("{path}#{}", self.items_begun),
        );
        db.reserve_pull_object(
            run.run_id,
            kind,
            &slot,
            &url,
            &meter.unit,
            &meter.day,
            limit,
        )?;
        let fetched = self
            .client
            .get_octets(&url, &self.scope()?, limit, request.validator);
        let (settled, answer) = match fetched {
            Ok(Octets::NotModified) => (Settled::Read(0), Answer::NotModified),
            Ok(Octets::Read { exceeded: true, .. }) if interrupting => {
                (Settled::Bounded(limit), Answer::Interrupted)
            }
            Ok(Octets::Read { exceeded: true, .. }) => (
                Settled::Failed("the answer exceeds the object's response bound"),
                Answer::Oversized,
            ),
            Ok(Octets::Read {
                octets, validator, ..
            }) => (
                Settled::Read(octets.len() as u64),
                Answer::Octets { octets, validator },
            ),
            Err(error) => {
                let detail = error.to_string();
                let credit =
                    db.settle_pull_object_crediting(&run, kind, &slot, Settled::Failed(&detail))?;
                self.run = run;
                self.credited(credit)?;
                return Ok(Answer::Failed);
            }
        };
        if let Settled::Read(octets) | Settled::Bounded(octets) = settled {
            run.work_bytes = run.work_bytes.saturating_sub(octets);
        }
        let credit = db.settle_pull_object_crediting(&run, kind, &slot, settled)?;
        self.run = run;
        self.credited(credit)?;
        Ok(answer)
    }
}
