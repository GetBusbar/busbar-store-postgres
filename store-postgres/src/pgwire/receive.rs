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
        let capacity = self.allocation.bytes.capacity();
        if end > capacity {
            let live = self.len();
            let needed = live
                .checked_add(input.len())
                .expect("receive buffer length");
            if needed <= capacity && live <= capacity / 2 {
                // Compact in place: move the live tail to the front, then erase every byte past
                // it (the consumed prefix was erased by `consume`; the vacated tail still holds
                // a copy of moved bytes) before shortening, so spare capacity holds no plaintext.
                let (start, len) = (self.start, self.allocation.bytes.len());
                self.allocation.bytes.copy_within(start..len, 0);
                self.allocation.bytes[live..len].zeroize();
                self.allocation.bytes.truncate(live);
                self.start = 0;
            } else {
                // Size from the live bytes, not the old capacity: the consumed prefix is dropped
                // here, so doubling the old capacity would grow with total traffic.
                let mut next = self.allocation.replacement(needed.saturating_mul(2));
                next.bytes.extend_from_slice(self);
                // Replacing the owner erases the complete previous initialized
                // allocation before releasing it, including its consumed prefix.
                self.allocation = next;
                self.start = 0;
            }
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
#[path = "../tests/receive.rs"]
mod tests;
