use std::{collections::BinaryHeap, time::Duration};

use chrono::{DateTime, Utc};
use color_eyre::eyre;
use openssl::x509::X509Ref;

use crate::utils;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventKind {
    RenewServerCredentials,
    RenewCaCredentials,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub scheduled_time: DateTime<Utc>,
    pub kind: EventKind,
}

impl PartialOrd for Event {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        // inversing the ordering of scheduled time
        // the sooner the time, the greater the event
        // this is supposed to work with the queue, which is a max heap
        other.scheduled_time.partial_cmp(&self.scheduled_time)
    }
}

impl Ord for Event {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // same as PartialCmp
        other.scheduled_time.cmp(&self.scheduled_time)
    }
}

pub struct EventQueue {
    inner: BinaryHeap<Event>,
}

impl EventQueue {
    pub fn new() -> Self {
        let inner = BinaryHeap::new();

        Self { inner }
    }

    pub fn pop(&mut self) -> Option<Event> {
        self.inner.pop()
    }

    pub fn enqueue(&mut self, event: Event) {
        self.inner.push(event)
    }

    pub fn clear(&mut self) {
        self.inner.clear();
    }

    pub fn schedule_renew_server(
        &mut self,
        server_cert: &X509Ref,
        renew_after: Duration,
    ) -> eyre::Result<()> {
        let issued_time = utils::get_issued_datetime(server_cert)?;
        let renew_time = issued_time + renew_after;

        let event = Event {
            scheduled_time: renew_time,
            kind: EventKind::RenewServerCredentials,
        };

        self.enqueue(event);
        Ok(())
    }

    pub fn schedule_renew_root(
        &mut self,
        root_cert: &X509Ref,
        renew_after: Duration,
    ) -> eyre::Result<()> {
        let issued_time = utils::get_issued_datetime(root_cert)?;
        let renew_time = issued_time + renew_after;

        let event = Event {
            scheduled_time: renew_time,
            kind: EventKind::RenewCaCredentials,
        };

        self.enqueue(event);
        Ok(())
    }
}
