// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Receive allocations stay owned until the last parsed message slice is dropped.

use std::io;
use std::ops::Deref;

use bytes::Bytes;
use postgres_protocol::message::backend::Message;
use zeroize::Zeroize;

#[derive(Default)]
struct Allocation {
    bytes: Vec<u8>,
    #[cfg(test)]
    erasures: Option<std::sync::Arc<std::sync::Mutex<Vec<Erasure>>>>,
}

impl Allocation {
    fn replacement(&self, capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
            #[cfg(test)]
            erasures: self.erasures.clone(),
        }
    }
}

impl Drop for Allocation {
    fn drop(&mut self) {
        // Retain the initialized length through erasure. No operation drains or
        // truncates live plaintext, so spare capacity never contains older secrets.
        self.bytes.as_mut_slice().zeroize();
        #[cfg(test)]
        if let Some(log) = &self.erasures {
            if !self.bytes.is_empty() {
                log.lock().unwrap().push(Erasure {
                    length: self.bytes.len(),
                    zero: self.bytes.iter().all(|b| *b == 0),
                });
            }
        }
    }
}

struct Frame {
    allocation: Allocation,
    start: usize,
}

impl AsRef<[u8]> for Frame {
    fn as_ref(&self) -> &[u8] {
        &self.allocation.bytes[self.start..]
    }
}

#[derive(Default)]
pub(super) struct ReceiveBuffer {
    allocation: Allocation,
    start: usize,
}

impl Deref for ReceiveBuffer {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.allocation.bytes[self.start..]
    }
}

impl ReceiveBuffer {
    pub(super) fn append(&mut self, input: &[u8]) {
        let end = self
            .allocation
            .bytes
            .len()
            .checked_add(input.len())
            .expect("receive buffer length");
        if end > self.allocation.bytes.capacity() {
            let needed = self
                .len()
                .checked_add(input.len())
                .expect("receive buffer length");
            let capacity = needed.max(self.allocation.bytes.capacity().saturating_mul(2));
            let mut next = self.allocation.replacement(capacity);
            next.bytes.extend_from_slice(self);
            // Replacing the owner erases the complete previous initialized
            // allocation before releasing it, including its consumed prefix.
            self.allocation = next;
            self.start = 0;
        }
        self.allocation.bytes.extend_from_slice(input);
    }

    pub(super) fn consume(&mut self, count: usize) {
        assert!(count <= self.len());
        let end = self.start + count;
        self.allocation.bytes[self.start..end].zeroize();
        self.start = end;
        if self.start == self.allocation.bytes.len() {
            // Every initialized byte was erased before its length is reset.
            self.allocation.bytes.clear();
            self.start = 0;
        }
    }

    fn frame(&mut self, length: usize) -> Bytes {
        assert!(length <= self.len());
        if length == self.len() {
            let replacement = self.allocation.replacement(0);
            let allocation = std::mem::replace(&mut self.allocation, replacement);
            let start = std::mem::take(&mut self.start);
            return Bytes::from_owner(Frame { allocation, start });
        }
        let mut allocation = self.allocation.replacement(length);
        allocation.bytes.extend_from_slice(&self[..length]);
        self.consume(length);
        Bytes::from_owner(Frame {
            allocation,
            start: 0,
        })
    }

    pub(super) fn message(&mut self) -> io::Result<Option<Message>> {
        if self.len() < 5 {
            return Ok(None);
        }
        let length = u32::from_be_bytes(self[1..5].try_into().unwrap());
        if length < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid message length: parsing u32",
            ));
        }
        let length = usize::try_from(length)
            .ok()
            .and_then(|n| n.checked_add(1))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "message length exceeds address space",
                )
            })?;
        if self.len() < length {
            return Ok(None);
        }
        parse_frame(self.frame(length)).map(Some)
    }
}

fn parse_frame(bytes: Bytes) -> io::Result<Message> {
    Message::parse_owned(bytes)
}

#[cfg(test)]
#[derive(Debug)]
struct Erasure {
    length: usize,
    zero: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use fallible_iterator::FallibleIterator;
    use std::sync::{Arc, Mutex};

    fn observed() -> (ReceiveBuffer, Arc<Mutex<Vec<Erasure>>>) {
        let log = Arc::new(Mutex::new(Vec::new()));
        (
            ReceiveBuffer {
                allocation: Allocation {
                    bytes: Vec::new(),
                    erasures: Some(log.clone()),
                },
                start: 0,
            },
            log,
        )
    }

    fn data_row(value: &[u8]) -> Vec<u8> {
        let mut frame = vec![b'D'];
        frame.extend_from_slice(&(10_u32 + value.len() as u32).to_be_bytes());
        frame.extend_from_slice(&1_u16.to_be_bytes());
        frame.extend_from_slice(&(value.len() as i32).to_be_bytes());
        frame.extend_from_slice(value);
        frame
    }

    #[test]
    fn parsed_row_clones_retain_erasing_frame_owner() {
        let frame = data_row(b"wrapped-credential");
        let (mut buffer, log) = observed();
        buffer.append(&frame);
        let original = buffer.as_ptr() as usize;
        let Message::DataRow(row) = buffer.message().unwrap().unwrap() else {
            panic!("row")
        };
        assert!(buffer.is_empty());
        assert_eq!(
            row.buffer().as_ptr() as usize,
            original + 7,
            "parser retains the original allocation"
        );
        let ranges: Vec<_> = row.ranges().collect().unwrap();
        assert_eq!(
            &row.buffer()[ranges[0].clone().unwrap()],
            b"wrapped-credential"
        );
        let cloned_row = row.clone();
        let slice = row.buffer_bytes().slice(4..);
        drop(row);
        drop(buffer);
        assert!(
            log.lock().unwrap().is_empty(),
            "live slices still own the allocation"
        );
        drop(cloned_row);
        assert!(log.lock().unwrap().is_empty());
        assert_eq!(&slice[..], b"wrapped-credential");
        drop(slice);
        let log = log.lock().unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].length, frame.len());
        assert!(log[0].zero);
    }

    #[test]
    fn receive_allocations_are_erased_on_growth_consume_and_drop() {
        let (mut buffer, log) = observed();
        buffer.append(b"secret-prefix-and-tail");
        buffer.consume(6);
        assert!(buffer.allocation.bytes[..6].iter().all(|b| *b == 0));
        let more = vec![b'x'; buffer.allocation.bytes.capacity() + 1];
        buffer.append(&more);
        assert!(buffer.starts_with(b"-prefix-and-tail"));
        assert_eq!(log.lock().unwrap().len(), 1);
        assert!(log.lock().unwrap()[0].zero);
        buffer.consume(buffer.len());
        assert!(buffer.is_empty());
        buffer.append(b"another-secret");
        drop(buffer);
        let log = log.lock().unwrap();
        assert_eq!(log.len(), 2);
        assert!(log.iter().all(|e| e.zero));
    }

    #[test]
    fn fragmented_and_coalesced_frames_preserve_data_and_wiping_owners() {
        let first = data_row(b"first");
        let second = data_row(b"second");
        let (mut buffer, log) = observed();
        buffer.append(&first[..3]);
        assert!(buffer.message().unwrap().is_none());
        buffer.append(&first[3..]);
        buffer.append(&second);
        let Message::DataRow(a) = buffer.message().unwrap().unwrap() else {
            panic!("first")
        };
        assert!(buffer.allocation.bytes[..first.len()]
            .iter()
            .all(|b| *b == 0));
        let Message::DataRow(b) = buffer.message().unwrap().unwrap() else {
            panic!("second")
        };
        assert_eq!(&a.buffer()[4..], b"first");
        assert_eq!(&b.buffer()[4..], b"second");
        drop((a, b, buffer));
        assert!(log.lock().unwrap().iter().all(|e| e.zero));
    }

    #[test]
    fn cancelling_receive_future_erases_partial_input_and_held_row() {
        use std::future::Future;
        use std::task::{Context, Poll, Waker};

        let (mut buffer, log) = observed();
        let mut future = Box::pin(async move {
            buffer.append(&data_row(b"held-credential"));
            let row = buffer.message().unwrap().unwrap();
            buffer.append(b"D\0\0\0\x30partial-credential");
            std::future::pending::<()>().await;
            drop((row, buffer));
        });
        assert!(matches!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        ));
        assert!(log.lock().unwrap().is_empty());
        drop(future);
        let log = log.lock().unwrap();
        assert_eq!(log.len(), 2);
        assert!(log.iter().all(|e| e.zero));
    }

    #[test]
    fn rejected_owned_frames_erase_their_allocations() {
        for frame in [
            vec![b'D'],
            vec![b'?', 0, 0, 0, 4],
            vec![b'D', 0, 0, 0, 4],
            vec![b'Z', 0, 0, 0, 3],
            vec![b'Z', 0, 0, 0, 5],
            vec![b'Z', 0, 0, 0, 5, b'I', 1],
        ] {
            let (mut buffer, log) = observed();
            buffer.append(&frame);
            let owned = buffer.frame(frame.len());
            assert!(Message::parse_owned(owned).is_err());
            drop(buffer);
            let log = log.lock().unwrap();
            assert_eq!(log.len(), 1);
            assert!(log[0].zero);
        }
    }
}
