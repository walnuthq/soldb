//! The memory of every step of a trace, held as what each frame wrote.
//!
//! A step's memory is the memory of its EVM frame after some number of that frame's
//! recorded entries. An entry is either a write (some bytes at an offset, and the size of
//! memory after it) or a full image. A frame recorded write by write takes an image
//! whenever the bytes written since the last one reach the size of its memory, so
//! rebuilding a step's memory never replays more than about one memory's worth of
//! writes. A producer that has every step's memory in full, as a node's `structLogs` or a
//! trace file do, records images only, and then a step's memory is one of them.

use std::sync::Mutex;

use bytes::Bytes;
use thiserror::Error;

use crate::same_buffer;

/// Which memory a step has: its frame and how many of that frame's entries are applied.
/// Packed into one word per step; [`MemoryRef::NONE`] is a step without memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MemoryRef(u64);

impl MemoryRef {
    pub(crate) const NONE: Self = Self(u64::MAX);

    fn new(frame: usize, applied: usize) -> Self {
        // Both are counts of things held in memory, far below `u32::MAX` for any trace
        // that fits in memory at all.
        let frame = u32::try_from(frame).unwrap_or(u32::MAX - 1);
        let applied = u32::try_from(applied).unwrap_or(u32::MAX);
        Self(u64::from(frame) << 32 | u64::from(applied))
    }

    fn frame(self) -> usize {
        (self.0 >> 32) as usize
    }

    fn applied(self) -> usize {
        (self.0 & u64::from(u32::MAX)) as usize
    }

    pub(crate) fn is_none(self) -> bool {
        self == Self::NONE
    }
}

/// Why a memory write cannot be recorded.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MemoryWriteError {
    /// The written bytes end past the size the memory is said to have after the write.
    #[error("{length} bytes written at offset {offset} end past the memory size {size}")]
    PastEnd {
        offset: u64,
        length: usize,
        size: u64,
    },
    /// The memory is said to have shrunk, which EVM memory never does within a frame.
    #[error("memory shrank from {before} to {after} bytes")]
    Shrank { before: u64, after: u64 },
    /// More memory than this platform can address.
    #[error("a memory of {0} bytes does not fit in this platform's address space")]
    TooLarge(u64),
}

#[derive(Debug, Clone)]
enum Entry {
    Image(Bytes),
    Write {
        offset: usize,
        size: usize,
        data: Span,
    },
}

/// Where the bytes of one write are in the [`Arena`].
#[derive(Debug, Clone, Copy)]
struct Span {
    chunk: u32,
    start: u32,
    length: u32,
}

#[derive(Debug, Clone, Default)]
struct Frame {
    entries: Vec<Entry>,
    /// The positions of the image entries, ascending.
    images: Vec<u32>,
    /// The memory as recorded so far, while writes are being recorded into the frame.
    live: Option<Vec<u8>>,
    /// Bytes written since the last image, which decides when to take the next.
    written_since_image: usize,
}

/// The bytes of every write, appended into fixed chunks so that recording never moves
/// what was recorded before.
#[derive(Debug, Clone, Default)]
struct Arena {
    chunks: Vec<Vec<u8>>,
}

const ARENA_CHUNK: usize = 1 << 20;

impl Arena {
    fn push(&mut self, data: &[u8]) -> Span {
        let fits = self
            .chunks
            .last()
            .is_some_and(|chunk| chunk.capacity() - chunk.len() >= data.len());
        if !fits {
            self.chunks
                .push(Vec::with_capacity(ARENA_CHUNK.max(data.len())));
        }
        let index = self.chunks.len() - 1;
        let chunk = &mut self.chunks[index];
        let start = chunk.len();
        chunk.extend_from_slice(data);
        // A chunk holds at most one write larger than `ARENA_CHUNK`, so its offsets and
        // lengths fit in `u32` unless a single write is 4 GiB.
        Span {
            chunk: u32::try_from(index).unwrap_or(u32::MAX),
            start: u32::try_from(start).unwrap_or(u32::MAX),
            length: u32::try_from(data.len()).unwrap_or(u32::MAX),
        }
    }

    fn get(&self, span: Span) -> &[u8] {
        let start = span.start as usize;
        &self.chunks[span.chunk as usize][start..start + span.length as usize]
    }
}

/// The memory last rebuilt, so that reading the steps of a frame in order applies each
/// write once.
#[derive(Debug)]
struct Cached {
    frame: usize,
    applied: usize,
    memory: Vec<u8>,
}

#[derive(Debug, Default)]
pub(crate) struct MemoryStore {
    frames: Vec<Frame>,
    /// The frames writes go to, innermost last.
    active: Vec<usize>,
    /// The frame full images go to.
    snapshots: Option<usize>,
    arena: Arena,
    cache: Mutex<Option<Cached>>,
}

impl Clone for MemoryStore {
    fn clone(&self) -> Self {
        Self {
            frames: self.frames.clone(),
            active: self.active.clone(),
            snapshots: self.snapshots,
            arena: self.arena.clone(),
            cache: Mutex::new(None),
        }
    }
}

impl MemoryStore {
    /// The memory of a step whose memory is `memory` in full.
    pub(crate) fn snapshot(&mut self, memory: Bytes) -> MemoryRef {
        let frame = *self.snapshots.get_or_insert_with(|| {
            self.frames.push(Frame::default());
            self.frames.len() - 1
        });
        let frame_entries = &mut self.frames[frame];
        let unchanged = match frame_entries.entries.last_mut() {
            Some(Entry::Image(last)) if same_buffer(last, &memory) => true,
            Some(Entry::Image(last)) if *last == memory => {
                // Keep the producer's latest buffer so its following shared snapshots
                // compare by pointer rather than comparing the same bytes again.
                *last = memory.clone();
                true
            }
            _ => false,
        };
        if !unchanged {
            let position = frame_entries.entries.len();
            frame_entries.entries.push(Entry::Image(memory));
            frame_entries
                .images
                .push(u32::try_from(position).unwrap_or(u32::MAX));
        }
        MemoryRef::new(frame, frame_entries.entries.len())
    }

    /// Starts recording a new frame, empty, as a call or a creation starts one.
    pub(crate) fn start_frame(&mut self) {
        self.frames.push(Frame {
            live: Some(Vec::new()),
            ..Frame::default()
        });
        self.active.push(self.frames.len() - 1);
    }

    /// Whether a frame is being recorded write by write.
    pub(crate) fn recording(&self) -> bool {
        !self.active.is_empty()
    }

    /// Stops recording the innermost frame; writes go to its caller's again.
    pub(crate) fn end_frame(&mut self) {
        if let Some(frame) = self.active.pop() {
            self.frames[frame].live = None;
        }
    }

    /// Records that `data` was written at `offset` of the innermost frame's memory, which
    /// is `size` bytes long afterwards. A write without data records the memory growing.
    pub(crate) fn write(
        &mut self,
        offset: u64,
        data: &[u8],
        size: u64,
    ) -> Result<(), MemoryWriteError> {
        if self.active.is_empty() {
            self.start_frame();
        }
        let frame_index = *self.active.last().unwrap_or(&0);
        let size_bytes = usize::try_from(size).map_err(|_| MemoryWriteError::TooLarge(size))?;
        let start = usize::try_from(offset).map_err(|_| MemoryWriteError::TooLarge(offset))?;
        let past_end = MemoryWriteError::PastEnd {
            offset,
            length: data.len(),
            size,
        };
        let end = start.checked_add(data.len()).ok_or(past_end.clone())?;
        if end > size_bytes {
            return Err(past_end);
        }
        let before = self.frames[frame_index].live.as_ref().map_or(0, Vec::len);
        if size_bytes < before {
            return Err(MemoryWriteError::Shrank {
                before: before as u64,
                after: size,
            });
        }
        let span = self.arena.push(data);
        let frame = &mut self.frames[frame_index];
        let live = frame.live.get_or_insert_with(Vec::new);
        live.resize(size_bytes, 0);
        live[start..end].copy_from_slice(data);
        frame.entries.push(Entry::Write {
            offset: start,
            size: size_bytes,
            data: span,
        });
        frame.written_since_image += data.len();
        if frame.written_since_image >= live.len() && !live.is_empty() {
            let position = frame.entries.len();
            frame
                .entries
                .push(Entry::Image(Bytes::copy_from_slice(live)));
            frame
                .images
                .push(u32::try_from(position).unwrap_or(u32::MAX));
            frame.written_since_image = 0;
        }
        Ok(())
    }

    /// The memory of a step appended now, as recorded write by write: the innermost
    /// frame's after everything written to it so far, or none when no frame was started.
    pub(crate) fn current(&self) -> MemoryRef {
        self.active.last().map_or(MemoryRef::NONE, |frame| {
            MemoryRef::new(*frame, self.frames[*frame].entries.len())
        })
    }

    /// The bytes `memory` refers to.
    pub(crate) fn read(&self, memory: MemoryRef) -> Option<Bytes> {
        if memory.is_none() {
            return None;
        }
        let frame_index = memory.frame();
        let applied = memory.applied();
        let frame = self.frames.get(frame_index)?;
        if applied == 0 {
            return Some(Bytes::new());
        }
        let images_before = frame
            .images
            .partition_point(|position| (*position as usize) < applied);
        let image = images_before
            .checked_sub(1)
            .map(|index| frame.images[index] as usize);
        if let Some(position) = image {
            if position + 1 == applied {
                if let Entry::Image(bytes) = &frame.entries[position] {
                    return Some(bytes.clone());
                }
            }
        }

        // Rebuild from the image before the step, or from the cached memory when it is the
        // same frame at or past that image and not past the step.
        let replay_from = image.map_or(0, |position| position + 1);
        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let reusable = cache.as_ref().is_some_and(|cached| {
            cached.frame == frame_index
                && cached.applied >= replay_from
                && cached.applied <= applied
        });
        if !reusable {
            let base = match image.map(|position| &frame.entries[position]) {
                Some(Entry::Image(bytes)) => bytes.to_vec(),
                _ => Vec::new(),
            };
            *cache = Some(Cached {
                frame: frame_index,
                applied: replay_from,
                memory: base,
            });
        }
        let cached = cache.as_mut()?;
        for entry in &frame.entries[cached.applied..applied] {
            if let Entry::Write { offset, size, data } = entry {
                let bytes = self.arena.get(*data);
                cached.memory.resize(*size, 0);
                cached.memory[*offset..*offset + bytes.len()].copy_from_slice(bytes);
            }
        }
        cached.applied = applied;
        Some(Bytes::copy_from_slice(&cached.memory))
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

    #[test]
    fn rebuilds_memory_from_writes_and_images() {
        let mut store = MemoryStore::default();
        store.start_frame();
        let empty = store.current();
        store.write(0, &[0xaa; 32], 32).expect("write");
        // 32 bytes written into 32 bytes of memory takes an image.
        let after_first = store.current();
        store.write(40, &[0xbb], 64).expect("write");
        let after_second = store.current();

        // A call's frame does not see the caller's memory, and the caller resumes.
        store.start_frame();
        store.write(0, &[0xcc], 32).expect("write");
        let callee = store.current();
        store.end_frame();
        assert_eq!(store.current(), after_second);

        store.write(0, &[], 96).expect("grow");
        let grown = store.current();

        assert_eq!(store.read(empty).as_deref(), Some(&[][..]));
        assert_eq!(store.read(after_first).as_deref(), Some(&[0xaa; 32][..]));
        let mut expected = vec![0xaa; 32];
        expected.resize(64, 0);
        expected[40] = 0xbb;
        assert_eq!(store.read(after_second).as_deref(), Some(&expected[..]));
        let mut callee_memory = [0; 32];
        callee_memory[0] = 0xcc;
        assert_eq!(store.read(callee).as_deref(), Some(&callee_memory[..]));
        expected.resize(96, 0);
        assert_eq!(store.read(grown).as_deref(), Some(&expected[..]));
        // Reading backwards rebuilds from the image again.
        assert_eq!(store.read(after_second).as_deref(), Some(&expected[..64]));
    }

    #[test]
    fn refuses_writes_that_do_not_fit() {
        let mut store = MemoryStore::default();
        assert_eq!(
            store.write(31, &[1, 2], 32),
            Err(MemoryWriteError::PastEnd {
                offset: 31,
                length: 2,
                size: 32
            })
        );
        store.write(0, &[1], 64).expect("write");
        assert_eq!(
            store.write(0, &[1], 32),
            Err(MemoryWriteError::Shrank {
                before: 64,
                after: 32
            })
        );
    }
}
