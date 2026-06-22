use anyhow::Result;
use aya::maps::RingBuf;
use neurontrace_common::{EventType, NtEvent, PolicyAction};
use tracing::{error, info, warn};

use crate::feedback;

pub async fn consume_events(mut ring_buf: RingBuf<&mut aya::maps::MapData>) -> Result<()> {
    info!("event consumer started — waiting for violations");

    loop {
        while let Some(event_data) = ring_buf.next() {
            let bytes = &*event_data;
            if bytes.len() < core::mem::size_of::<NtEvent>() {
                warn!(len = bytes.len(), "received undersized event, skipping");
                continue;
            }

            let event: &NtEvent = unsafe { &*(bytes.as_ptr() as *const NtEvent) };
            handle_event(event);
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
}

fn handle_event(event: &NtEvent) {
    let event_type = EventType::from(event.event_type);
    let action = PolicyAction::from(event.action_taken);

    match action {
        PolicyAction::Block => {
            warn!(
                pid = event.pid,
                event = %event_type,
                "BLOCKED syscall"
            );
            feedback::report_violation(event);
        }
        PolicyAction::Kill => {
            error!(
                pid = event.pid,
                event = %event_type,
                "KILL signal — sending SIGKILL"
            );
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(event.pid as i32),
                nix::sys::signal::Signal::SIGKILL,
            );
            feedback::report_violation(event);
        }
        PolicyAction::Audit => {
            info!(
                pid = event.pid,
                event = %event_type,
                "AUDIT — allowed but logged"
            );
        }
        PolicyAction::Allow => {}
    }
}
