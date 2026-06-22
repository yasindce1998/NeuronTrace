use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use neurontrace_common::user::{Severity, ViolationFeedback};
use neurontrace_common::{EventType, NtEvent, PolicyAction};
use tracing::{info, warn};

enum FeedbackOutput {
    Socket(UnixStream),
    File(BufWriter<File>),
}

pub struct FeedbackSender {
    output: FeedbackOutput,
    path: PathBuf,
}

impl FeedbackSender {
    pub fn new(feedback_path: &Path) -> Self {
        match UnixStream::connect(feedback_path) {
            Ok(stream) => {
                info!(path = %feedback_path.display(), "connected to feedback socket");
                Self {
                    output: FeedbackOutput::Socket(stream),
                    path: feedback_path.to_path_buf(),
                }
            }
            Err(_) => {
                let jsonl_path = feedback_path.with_extension("jsonl");
                let file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&jsonl_path)
                    .unwrap_or_else(|_| {
                        let fallback = PathBuf::from("/tmp/neurontrace-feedback.jsonl");
                        OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(&fallback)
                            .expect("failed to open fallback feedback file")
                    });
                info!(path = %jsonl_path.display(), "feedback writing to JSONL file");
                Self {
                    output: FeedbackOutput::File(BufWriter::new(file)),
                    path: jsonl_path,
                }
            }
        }
    }

    pub fn report_violation(&mut self, event: &NtEvent) {
        let event_type = EventType::from(event.event_type);
        let action = PolicyAction::from(event.action_taken);

        let feedback = ViolationFeedback {
            kind: "violation",
            hook: event_type.to_string(),
            target: extract_target(event, event_type),
            effect: format_effect(action),
            rule: format!("default-deny:{}", event_type),
            severity: severity_for(action),
            suggested_retry: action == PolicyAction::Block,
            message: format_message(event_type, action),
        };

        let json = match serde_json::to_string(&feedback) {
            Ok(j) => j,
            Err(e) => {
                warn!(error = %e, "failed to serialize feedback");
                return;
            }
        };

        let line = format!("{}\n", json);
        let write_result = match &mut self.output {
            FeedbackOutput::Socket(stream) => stream.write_all(line.as_bytes()),
            FeedbackOutput::File(writer) => writer.write_all(line.as_bytes()).and_then(|_| writer.flush()),
        };

        if let Err(e) = write_result {
            warn!(error = %e, path = %self.path.display(), "failed to write feedback");
        }
    }
}

fn extract_target(event: &NtEvent, event_type: EventType) -> String {
    let path_len = (event.path_len as usize).min(event.path.len());
    let path_str = core::str::from_utf8(&event.path[..path_len]).unwrap_or("");

    match event_type {
        EventType::Connect => format_sockaddr(&event.path[..path_len]),
        EventType::TaskKill if event.argv_len >= 4 => {
            let target_pid = u32::from_ne_bytes([
                event.argv[0],
                event.argv[1],
                event.argv[2],
                event.argv[3],
            ]);
            format!("pid:{}", target_pid)
        }
        _ => {
            if path_str.is_empty() {
                format!("pid:{}", event.pid)
            } else {
                path_str.to_string()
            }
        }
    }
}

fn format_sockaddr(bytes: &[u8]) -> String {
    if bytes.len() < 4 {
        return "unknown".to_string();
    }
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
    match family {
        2 if bytes.len() >= 8 => {
            // AF_INET: port at offset 2 (big-endian), addr at offset 4
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let addr = format!("{}.{}.{}.{}", bytes[4], bytes[5], bytes[6], bytes[7]);
            format!("{}:{}", addr, port)
        }
        10 if bytes.len() >= 24 => {
            // AF_INET6: port at offset 2 (big-endian), addr at offset 8
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            format!("[ipv6]:{}", port)
        }
        _ => format!("af:{}", family),
    }
}

fn format_effect(action: PolicyAction) -> String {
    match action {
        PolicyAction::Block => "blocked".to_string(),
        PolicyAction::Kill => "process_killed".to_string(),
        PolicyAction::Audit => "audited".to_string(),
        PolicyAction::Allow => "allowed".to_string(),
    }
}

fn severity_for(action: PolicyAction) -> Severity {
    match action {
        PolicyAction::Kill => Severity::Critical,
        PolicyAction::Block => Severity::High,
        PolicyAction::Audit => Severity::Medium,
        PolicyAction::Allow => Severity::Low,
    }
}

fn format_message(event_type: EventType, action: PolicyAction) -> String {
    match action {
        PolicyAction::Block => format!(
            "Operation '{}' was blocked by NeuronTrace policy. Check your allowed operations.",
            event_type
        ),
        PolicyAction::Kill => format!(
            "Process terminated: '{}' violated a critical policy rule.",
            event_type
        ),
        PolicyAction::Audit => format!(
            "Operation '{}' was logged for audit. No action taken.",
            event_type
        ),
        PolicyAction::Allow => String::new(),
    }
}
