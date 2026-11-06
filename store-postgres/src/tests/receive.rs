// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Receive-buffer ownership and erasure tests (`pgwire/receive.rs`).

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

#[test]
fn streaming_misaligned_frames_keeps_capacity_proportional_to_live_bytes() {
    // 300-byte rows arriving in 1000-byte chunks never end a chunk on a frame boundary until the
    // very end, so the buffer never drains exactly. Capacity must track the live (unconsumed)
    // bytes, not the total traffic since the last exact drain.
    let row = data_row(&[b'r'; 290]);
    let stream: Vec<u8> = std::iter::repeat_n(row.as_slice(), 4_000)
        .flatten()
        .copied()
        .collect();
    let (mut buffer, _log) = observed();
    let mut rows = 0;
    let mut peak = 0;
    for chunk in stream.chunks(1_000) {
        buffer.append(chunk);
        peak = peak.max(buffer.allocation.bytes.capacity());
        while let Some(message) = buffer.message().unwrap() {
            assert!(matches!(message, Message::DataRow(_)));
            rows += 1;
        }
    }
    assert_eq!(rows, 4_000);
    assert!(
        peak <= 4 * (row.len() + 1_000),
        "receive capacity grew to {peak} bytes over {} bytes of traffic",
        stream.len()
    );
}

#[test]
fn a_mostly_consumed_buffer_compacts_in_place_without_reallocating() {
    let (mut buffer, log) = observed();
    buffer.append(&[b'a'; 100]);
    let capacity = buffer.allocation.bytes.capacity();
    buffer.consume(90);
    let input = vec![b'b'; capacity - 20];
    buffer.append(&input);
    assert!(
        log.lock().unwrap().is_empty(),
        "compaction keeps the owned allocation"
    );
    assert_eq!(buffer.allocation.bytes.capacity(), capacity);
    assert_eq!(&buffer[..10], &[b'a'; 10]);
    assert_eq!(&buffer[10..], &input[..]);
    assert_eq!(buffer.allocation.bytes.len(), 10 + input.len());
}
