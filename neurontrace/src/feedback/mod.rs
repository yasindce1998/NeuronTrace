use neurontrace_common::{EventType, NtEvent, PolicyAction};
use tracing::info;

pub fn report_violation(event: &NtEvent) {
    let event_type = EventType::from(event.event_type);
    let action = PolicyAction::from(event.action_taken);
    let path = extract_path(event);

    let message = format!(
        "[NeuronTrace] pid={} event={} action={} path={}",
        event.pid, event_type, action, path,
    );

    info!(violation = %message, "violation reported to agent feedback channel");
}

fn extract_path(event: &NtEvent) -> &str {
    let len = (event.path_len as usize).min(event.path.len());
    core::str::from_utf8(&event.path[..len]).unwrap_or("<invalid utf8>")
}
