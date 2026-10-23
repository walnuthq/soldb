//! The memory of every step of a trace.
//!
//! A step's memory is one of the images the trace recorded in full. Consecutive steps that
//! did not change memory share one, so a trace holds a copy per change rather than per
//! step.

use bytes::Bytes;

use crate::same_buffer;

/// Which memory a step has; [`MemoryRef::NONE`] is a step without memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MemoryRef(u32);

impl MemoryRef {
    pub(crate) const NONE: Self = Self(u32::MAX);

    pub(crate) fn is_none(self) -> bool {
        self == Self::NONE
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct MemoryStore {
    images: Vec<Bytes>,
}

impl MemoryStore {
    /// The memory of a step whose memory is `memory` in full.
    pub(crate) fn snapshot(&mut self, memory: Bytes) -> MemoryRef {
        let unchanged = self.images.last().is_some_and(|last| {
            same_buffer(last, &memory) || (last.len() == memory.len() && *last == memory)
        });
        if !unchanged {
            self.images.push(memory);
        }
        // An image per change of memory; `u32::MAX` of them do not fit in memory at all.
        MemoryRef(u32::try_from(self.images.len() - 1).unwrap_or(u32::MAX - 1))
    }

    /// The bytes `memory` refers to.
    pub(crate) fn read(&self, memory: MemoryRef) -> Option<Bytes> {
        if memory.is_none() {
            return None;
        }
        self.images.get(memory.0 as usize).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshots_share_unchanged_memory() {
        let mut store = MemoryStore::default();
        let first = store.snapshot(Bytes::from_static(&[1, 2]));
        let same = store.snapshot(Bytes::from(vec![1, 2]));
        let changed = store.snapshot(Bytes::from_static(&[3]));
        assert_eq!(first, same);
        assert_ne!(first, changed);
        assert_eq!(store.read(first).as_deref(), Some(&[1, 2][..]));
        assert_eq!(store.read(changed).as_deref(), Some(&[3][..]));
        assert_eq!(store.read(MemoryRef::NONE), None);
    }
}
