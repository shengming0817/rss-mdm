//! Pure DiagnosticLog file rules over the pinned Microsoft CSP schema.
//! ref: MicrosoftDocs DiagnosticLog CSP FileDownload/DMChannel; DiagnosticLog.xml.
use super::{Error, Request, Scope, Value, Verb};
use serde::{Deserialize, Serialize};
const ROOT: &str = "./Device/Vendor/MSFT/DiagnosticLog/FileDownload/DMChannel/*/";
/// Immutable input; platform evidence, identities and permissions remain server owned.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Input {
    /// Optional official trigger. Omission reads an already generated native log.
    pub trigger: Option<Request>,
    /// Native registered provider, collector or channel name, never a filesystem path.
    pub file_context: String,
    /// CSP accepts 1–16 KiB; default is 4 KiB.
    #[serde(default = "default_block")]
    pub block_size_kb: u8,
    /// Maximum complete output; further limited by the configured content owner.
    #[serde(default = "default_limit")]
    pub max_bytes: u64,
}
fn default_block() -> u8 {
    4
}
fn default_limit() -> u64 {
    16 * 1024 * 1024
}
impl Input {
    /// Validate bounded input and constrain trigger trees to real native log producers.
    pub fn validate(&self) -> Result<(), Error> {
        if !(1..=16).contains(&self.block_size_kb)
            || self.max_bytes == 0
            || self.max_bytes > default_limit()
            || self.file_context.is_empty()
            || self.file_context.len() > 256
            || self.file_context.chars().any(char::is_control)
        {
            return Err(Error::Value);
        }
        self.node("BlockCount", Verb::Get, None).objects()?;
        if let Some(trigger) = &self.trigger {
            trigger.command_count()?;
            let mut pending = vec![trigger];
            while let Some(request) = pending.pop() {
                match request {
                    Request::Node {
                        operation: Verb::Exec,
                        ..
                    } => {}
                    Request::Sequence { operations } | Request::Atomic { operations } => {
                        pending.extend(operations)
                    }
                    _ => return Err(Error::Unsupported),
                }
            }
            for object in trigger.objects()? {
                let uri = object.key();
                if object.scope() != Scope::Device
                    || !(uri
                        == "./Device/Vendor/MSFT/DiagnosticLog/DeviceStateData/MdmConfiguration"
                        || (uri.starts_with("./Device/Vendor/MSFT/DiagnosticLog/EtwLog/Channels/")
                            && uri.ends_with("/Export"))
                        || (uri
                            .starts_with("./Device/Vendor/MSFT/DiagnosticLog/EtwLog/Collectors/")
                            && uri.ends_with("/TraceControl")))
                {
                    return Err(Error::Unsupported);
                }
            }
        }
        Ok(())
    }
    fn node(&self, leaf: &str, operation: Verb, value: Option<Value>) -> Request {
        Request::Node {
            node: format!("{ROOT}{leaf}"),
            instance: vec![self.file_context.clone()],
            operation,
            value,
        }
    }
    /// Compile the next native step with the existing schema compiler and command allocator.
    pub fn request(&self, step: Step) -> Result<Request, Error> {
        self.validate()?;
        Ok(match step {
            Step::Trigger => self.trigger.clone().ok_or(Error::Value)?,
            Step::Size => self.node(
                "BlockSizeKB",
                Verb::Replace,
                Some(Value::Integer(i64::from(self.block_size_kb))),
            ),
            Step::Count | Step::Verify => self.node("BlockCount", Verb::Get, None),
            Step::Block { index } => Request::Sequence {
                operations: vec![
                    self.node(
                        "BlockIndexToRead",
                        Verb::Replace,
                        Some(Value::Integer(i64::from(index))),
                    ),
                    self.node("BlockIndexToRead", Verb::Get, None),
                    self.node("BlockData", Verb::Get, None),
                ],
            },
            Step::Complete => return Err(Error::Value),
        })
    }
}
/// A native step recorded with the existing attempt; this does not own product settlement.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Step {
    /// Execute the supplied official producer command.
    Trigger,
    /// Negotiate the native file block size.
    Size,
    /// Wait for the generated block count.
    Count,
    /// Select and read one block with its cursor evidence.
    Block {
        /// Zero based file block index.
        index: u32,
    },
    /// Verify that the native block count remained stable.
    Verify,
    /// All blocks and closing evidence were accepted.
    Complete,
}
/// Bounded accumulated native facts. Output bytes remain in protected attempt items.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Progress {
    /// Next native step.
    pub step: Step,
    /// Accepted positive block count.
    pub count: Option<u32>,
    /// Total accepted decoded bytes.
    pub length: u64,
}
impl Progress {
    /// Start without inventing a trigger acknowledgement.
    pub fn new(input: &Input) -> Self {
        Self {
            step: if input.trigger.is_some() {
                Step::Trigger
            } else {
                Step::Size
            },
            count: None,
            length: 0,
        }
    }
    /// Advance only after all matching native receipts and values have been admitted by the caller.
    /// -1/-2 counts are waiting facts; they do not prove an empty or finished file.
    pub fn accept(
        &mut self,
        input: &Input,
        count: Option<i64>,
        index: Option<u32>,
        bytes: Option<&[u8]>,
    ) -> Result<(), Error> {
        self.step = match self.step {
            Step::Trigger => Step::Size,
            Step::Size => Step::Count,
            Step::Count => {
                let n = count.ok_or(Error::MissingEvidence)?;
                if matches!(n, -1 | -2) {
                    return Ok(());
                }
                let n = u32::try_from(n).map_err(|_| Error::Value)?;
                // Every non-final block occupies the negotiated size; the final one is nonempty.
                let minimum = u64::from(n.saturating_sub(1))
                    .checked_mul(u64::from(input.block_size_kb) * 1024)
                    .and_then(|v| v.checked_add(1))
                    .ok_or(Error::Limit)?;
                if n == 0 || minimum > input.max_bytes {
                    return Err(Error::Limit);
                }
                self.count = Some(n);
                Step::Block { index: 0 }
            }
            Step::Block { index: expected } => {
                let n = self.count.ok_or(Error::MissingEvidence)?;
                let bytes = bytes.ok_or(Error::MissingEvidence)?;
                let size = u64::from(input.block_size_kb) * 1024;
                if index != Some(expected)
                    || expected >= n
                    || bytes.is_empty()
                    || bytes.len() as u64 > size
                    || (expected + 1 < n && bytes.len() as u64 != size)
                {
                    return Err(Error::Value);
                }
                self.length = self
                    .length
                    .checked_add(bytes.len() as u64)
                    .ok_or(Error::Limit)?;
                if self.length > input.max_bytes {
                    return Err(Error::Limit);
                }
                if expected + 1 == n {
                    Step::Verify
                } else {
                    Step::Block {
                        index: expected + 1,
                    }
                }
            }
            Step::Verify => {
                if count.and_then(|v| u32::try_from(v).ok()) != self.count {
                    return Err(Error::Value);
                }
                Step::Complete
            }
            Step::Complete => return Err(Error::Value),
        };
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn input() -> Input {
        Input {
            trigger: None,
            file_context: "DeviceManagement".into(),
            block_size_kb: 1,
            max_bytes: 2048,
        }
    }
    #[test]
    fn waits_then_requires_all_blocks_and_final_count() {
        let input = input();
        let mut p = Progress::new(&input);
        p.accept(&input, None, None, None).unwrap();
        p.accept(&input, Some(-2), None, None).unwrap();
        assert_eq!(p.step, Step::Count);
        p.accept(&input, Some(2), None, None).unwrap();
        assert!(p.accept(&input, None, Some(1), Some(&[1; 1024])).is_err());
        p.accept(&input, None, Some(0), Some(&[1; 1024])).unwrap();
        assert_eq!(p.step, Step::Block { index: 1 });
        p.accept(&input, None, Some(1), Some(&[2; 3])).unwrap();
        assert!(p.accept(&input, Some(3), None, None).is_err());
        p.accept(&input, Some(2), None, None).unwrap();
        assert_eq!(p.step, Step::Complete);
        assert_eq!(p.length, 1027);
    }
    #[test]
    fn rejects_unbounded_count_short_middle_and_non_diagnostic_trigger() {
        let input = input();
        let mut p = Progress::new(&input);
        p.accept(&input, None, None, None).unwrap();
        assert!(p.accept(&input, Some(4), None, None).is_err());
        p.accept(&input, Some(2), None, None).unwrap();
        assert!(p.accept(&input, None, Some(0), Some(&[1; 2])).is_err());
        let mut input = input;
        input.trigger = Some(Request::Node {
            node: "./Device/Vendor/MSFT/RemoteWipe/doWipe".into(),
            instance: vec![],
            operation: Verb::Exec,
            value: None,
        });
        assert!(input.validate().is_err());
    }
}
