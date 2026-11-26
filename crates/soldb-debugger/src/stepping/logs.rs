//! The logs of a run, each at the step that emitted it.
//!
//! A backend reports logs without saying where they happened: a receipt lists the ones
//! that survived, in order, and nothing else. The recording has every `LOG` instruction,
//! so it says where each log was emitted, and what was emitted when the backend reported
//! none at all, as a simulated call on a node does.

use soldb_core::{encode_hex, opcode, ExecutionLog, TransactionTrace};

use super::StepMap;

/// A log and where the run emitted it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacedLog {
    /// The `LOG` instruction that emitted it. `None` when the backend's logs do not line
    /// up with the recording's, and nothing says which instruction emitted which.
    pub step: Option<usize>,
    /// True when a frame that reverted emitted it, or called the one that did: the log
    /// was undone with everything else the frame did.
    pub reverted: bool,
    pub log: ExecutionLog,
}

impl StepMap {
    /// Every log of the run, in the order emitted.
    ///
    /// What a log holds is the backend's word when it reported logs, and the recording
    /// then only places them: a backend that follows the execution reports every log, a
    /// receipt those no revert undid, and the count says which. What a receipt leaves out,
    /// and every log when the backend reported none, is read off the `LOG` instructions.
    #[must_use]
    pub fn logs(&self, trace: &TransactionTrace) -> Vec<PlacedLog> {
        let emitted = trace
            .steps
            .iter()
            .enumerate()
            .filter(|(_, step)| (opcode::LOG0..=opcode::LOG4).contains(&step.op()))
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        let recorded = &trace.artifacts.logs;
        if recorded.is_empty() {
            return emitted
                .iter()
                .filter_map(|&step| Some((step, self.read_log(trace, step)?)))
                .enumerate()
                .map(|(index, (step, log))| PlacedLog {
                    step: Some(step),
                    reverted: self.undone(step),
                    log: ExecutionLog { index, ..log },
                })
                .collect();
        }
        let lines_up = |steps: &[usize]| {
            steps.len() == recorded.len()
                && steps
                    .iter()
                    .zip(recorded)
                    .all(|(step, log)| self.emits(trace, *step, log))
        };
        if recorded.len() == emitted.len() {
            if lines_up(&emitted) {
                return emitted
                    .iter()
                    .zip(recorded)
                    .map(|(&step, log)| PlacedLog {
                        step: Some(step),
                        reverted: self.undone(step),
                        log: log.clone(),
                    })
                    .collect();
            }
        } else {
            let kept = emitted
                .iter()
                .copied()
                .filter(|step| !self.undone(*step))
                .collect::<Vec<_>>();
            if lines_up(&kept) {
                return self.with_undone_logs(trace, &emitted, recorded);
            }
        }
        recorded
            .iter()
            .map(|log| PlacedLog {
                step: None,
                reverted: false,
                log: log.clone(),
            })
            .collect()
    }

    /// The receipt's logs at the steps that emitted them, with the logs a revert undid read
    /// off the recording between them, so a node that reports only a receipt shows what a
    /// backend that follows the execution does. A read log's `index` is its place in the run.
    fn with_undone_logs(
        &self,
        trace: &TransactionTrace,
        emitted: &[usize],
        receipt: &[ExecutionLog],
    ) -> Vec<PlacedLog> {
        let mut receipt = receipt.iter();
        emitted
            .iter()
            .enumerate()
            .filter_map(|(index, &step)| {
                let (reverted, log) = if self.undone(step) {
                    (
                        true,
                        ExecutionLog {
                            index,
                            ..self.read_log(trace, step)?
                        },
                    )
                } else {
                    // The caller checked that the receipt has one log per kept step.
                    (false, receipt.next()?.clone())
                };
                Some(PlacedLog {
                    step: Some(step),
                    reverted,
                    log,
                })
            })
            .collect()
    }

    /// The log the `LOG` instruction at `step` emits, when its stack and memory were
    /// recorded. The emitter is the account whose storage the step writes: the executing
    /// one, or the caller's for a `DELEGATECALL`.
    fn read_log(&self, trace: &TransactionTrace, step: usize) -> Option<ExecutionLog> {
        let (topics, data) = trace.steps.get(step)?.emitted_log()?;
        Some(ExecutionLog {
            index: 0,
            depth: u64::from(self.steps.get(step)?.evm_depth),
            // An emitter the map could not name is left empty rather than guessed.
            address: self.storage_address(step).unwrap_or_default().to_owned(),
            topics: topics
                .iter()
                .map(|topic| format!("0x{}", encode_hex(topic.as_bytes())))
                .collect(),
            data,
        })
    }

    /// Whether the instruction at `step` can have emitted `log`: the topics it read are
    /// the log's. A step whose stack or memory was not recorded contradicts nothing.
    fn emits(&self, trace: &TransactionTrace, step: usize, log: &ExecutionLog) -> bool {
        let Some(read) = self.read_log(trace, step) else {
            return true;
        };
        read.topics.len() == log.topics.len()
            && read
                .topics
                .iter()
                .zip(&log.topics)
                .all(|(read, reported)| read.eq_ignore_ascii_case(reported))
    }

    /// Whether `step` ran in a frame that reverted, or in one it called.
    fn undone(&self, step: usize) -> bool {
        self.reverted
            .iter()
            .any(|(entry, last)| (*entry..=*last).contains(&step))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use soldb_core::{
        Bytes, ExecutionLog, StepSnapshot, TraceArtifacts, TraceStep, TransactionTrace,
    };

    use crate::StepMap;

    const ROOT: &str = "0xaaaa000000000000000000000000000000000001";
    const CALLEE: &str = "0xbbbb000000000000000000000000000000000002";
    const PAID: &str = "0x00000000000000000000000000000000000000000000000000000000000000a1";
    const SENT: &str = "0x00000000000000000000000000000000000000000000000000000000000000b2";

    fn step(depth: u64, op: &str, stack: &[&str]) -> TraceStep {
        let mut step = TraceStep::new(
            0,
            Arc::from(op),
            0,
            0,
            depth,
            None,
            StepSnapshot::new(
                stack.iter().map(|word| Arc::from(*word)).collect(),
                None,
                BTreeMap::new(),
                BTreeMap::new(),
            ),
        );
        step.snapshot.memory = Some(Bytes::copy_from_slice(&[0x11, 0x22, 0x33]));
        step
    }

    /// The root emits `PAID`, calls the callee, which emits `SENT` and halts with
    /// `callee_halt`, and stops.
    fn trace(callee_halt: &str, logs: Vec<ExecutionLog>) -> TransactionTrace {
        let callee = format!("0x{}", CALLEE.trim_start_matches("0x"));
        let steps = vec![
            // LOG1: offset, size, topic from the top; bottom first here.
            step(1, "LOG1", &[PAID, "0x2", "0x1"]),
            step(
                1,
                "CALL",
                &["0x0", "0x0", "0x0", "0x0", "0x0", &callee, "0xffff"],
            ),
            step(2, "LOG1", &[SENT, "0x1", "0x0"]),
            step(2, callee_halt, &["0x0", "0x0"]),
            step(1, "STOP", &[]),
        ];
        let artifacts = TraceArtifacts {
            logs,
            ..Default::default()
        };
        TransactionTrace {
            tx_hash: None,
            from_addr: "0x1".to_owned(),
            to_addr: Some(ROOT.to_owned()),
            value: "0".to_owned(),
            input_data: "0x".to_owned(),
            gas_used: 0,
            output: "0x".to_owned(),
            success: true,
            error: None,
            debug_trace_available: true,
            contract_address: None,
            backend: None,
            capabilities: Default::default(),
            artifacts,
            steps: steps.into(),
        }
    }

    fn reported(index: usize, address: &str, topic: &str) -> ExecutionLog {
        ExecutionLog {
            index,
            depth: 0,
            address: address.to_owned(),
            topics: vec![topic.to_owned()],
            data: "0x".to_owned(),
        }
    }

    /// Each log's step, whether it was undone, and its first topic.
    fn placed(trace: &TransactionTrace) -> Vec<(Option<usize>, bool, String)> {
        StepMap::new(trace, Vec::new())
            .logs(trace)
            .into_iter()
            .map(|placed| (placed.step, placed.reverted, placed.log.topics[0].clone()))
            .collect()
    }

    #[test]
    fn logs_are_read_off_the_recording_when_the_backend_reported_none() {
        let trace = trace("RETURN", Vec::new());
        let logs = StepMap::new(&trace, Vec::new()).logs(&trace);
        assert_eq!(
            logs.iter()
                .map(|placed| (placed.step, placed.log.index, placed.log.address.as_str()))
                .collect::<Vec<_>>(),
            [(Some(0), 0, ROOT), (Some(2), 1, CALLEE)]
        );
        assert_eq!(logs[0].log.topics, [PAID]);
        assert_eq!(logs[0].log.data, "0x2233");
        assert_eq!(logs[1].log.data, "0x11");
        assert_eq!(logs[1].log.depth, 1);
    }

    #[test]
    fn a_log_a_revert_undid_is_marked() {
        let trace = trace("REVERT", Vec::new());
        assert_eq!(
            placed(&trace),
            [
                (Some(0), false, PAID.to_owned()),
                (Some(2), true, SENT.to_owned())
            ]
        );
    }

    #[test]
    fn reported_logs_are_placed_by_how_many_the_backend_kept() {
        // A receipt keeps only the log no revert undid, and it is the root's. The one the
        // callee's revert undid is read off the recording, as a backend that follows the
        // execution reports it.
        let receipt = trace("REVERT", vec![reported(0, ROOT, PAID)]);
        let both = vec![reported(0, ROOT, PAID), reported(1, CALLEE, SENT)];
        let followed = trace("REVERT", both.clone());
        let expected = [
            (Some(0), false, PAID.to_owned()),
            (Some(2), true, SENT.to_owned()),
        ];
        assert_eq!(placed(&receipt), expected);
        assert_eq!(placed(&followed), expected);
        let read = StepMap::new(&receipt, Vec::new()).logs(&receipt);
        assert_eq!(read[0].log, reported(0, ROOT, PAID));
        assert_eq!(read[1].log.address, CALLEE);
        assert_eq!(read[1].log.index, 1);
        // What the backend reported is kept as it reported it.
        let logs = StepMap::new(&followed, Vec::new()).logs(&followed);
        assert_eq!(logs[1].log, both[1]);
    }

    #[test]
    fn logs_that_do_not_line_up_with_the_recording_are_not_placed() {
        // More logs than `LOG` instructions.
        let extra = vec![
            reported(0, ROOT, PAID),
            reported(1, CALLEE, SENT),
            reported(2, CALLEE, SENT),
        ];
        assert!(placed(&trace("RETURN", extra))
            .iter()
            .all(|(step, _, _)| step.is_none()));

        // The right number, but not the topics the instructions read.
        let swapped = vec![reported(0, ROOT, SENT), reported(1, CALLEE, PAID)];
        assert!(placed(&trace("RETURN", swapped))
            .iter()
            .all(|(step, _, _)| step.is_none()));
    }
}
