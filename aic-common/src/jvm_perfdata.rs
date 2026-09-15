//! Bounded HotSpot PerfData parsing and the internal JVM worker wire format.

const MAX_PERFDATA_BYTES: usize = 1024 * 1024;
const MAX_ENTRIES: usize = 4096;
const MAX_NAME_BYTES: usize = 256;
const MAX_STRING_BYTES: usize = 4096;
const PROLOGUE_LEN: usize = 32;
const ENTRY_HEADER_LEN: usize = 20;
const MAGIC: [u8; 4] = [0xca, 0xfe, 0xc0, 0xc0];
const PROTOCOL_VERSION: u8 = 1;
const REQUEST_BODY_LEN: usize = 62;
const METRICS_RESPONSE_BODY_LEN: usize = 50;
const FAILURE_RESPONSE_BODY_LEN: usize = 3;
const MAX_WORKER_FRAME_BODY: usize = 64 * 1024;

const THREAD_STARTED: &str = "java.threads.started";
const THREAD_LIVE: &str = "java.threads.live";
const THREAD_PEAK: &str = "java.threads.livePeak";
const THREAD_DAEMON: &str = "java.threads.daemon";
const CLASS_LOADED: &str = "java.cls.loadedClasses";
const CLASS_SHARED_LOADED: &str = "java.cls.sharedLoadedClasses";
const CLASS_UNLOADED: &str = "java.cls.unloadedClasses";
const CLASS_SHARED_UNLOADED: &str = "java.cls.sharedUnloadedClasses";

/// A fixed parser failure that never carries PerfData content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    InputTooLarge,
    InvalidMagic,
    UnsupportedFormat,
    Inaccessible,
    Overflow,
    Malformed,
    LimitExceeded,
    MissingMetric,
    DuplicateMetric,
    InvalidMetric,
    InvariantViolation,
}

/// Required JVM service metrics extracted from one bounded snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JvmPerfDataMetrics {
    pub threads_started_total: u64,
    pub threads_live: u64,
    pub threads_peak: u64,
    pub threads_daemon: u64,
    pub classes_loaded: u64,
    pub classes_unloaded_total: u64,
}

#[derive(Clone, Copy)]
enum ByteOrder {
    Big,
    Little,
}

impl ByteOrder {
    fn i32(self, bytes: &[u8]) -> Result<i32, ParseError> {
        let raw: [u8; 4] = bytes.try_into().map_err(|_| ParseError::Malformed)?;
        Ok(match self {
            Self::Big => i32::from_be_bytes(raw),
            Self::Little => i32::from_le_bytes(raw),
        })
    }

    fn i64(self, bytes: &[u8]) -> Result<i64, ParseError> {
        let raw: [u8; 8] = bytes.try_into().map_err(|_| ParseError::Malformed)?;
        Ok(match self {
            Self::Big => i64::from_be_bytes(raw),
            Self::Little => i64::from_le_bytes(raw),
        })
    }
}

#[derive(Default)]
struct RequiredValues {
    values: [Option<u64>; 8],
}

impl RequiredValues {
    fn index(name: &str) -> Option<usize> {
        match name {
            THREAD_STARTED => Some(0),
            THREAD_LIVE => Some(1),
            THREAD_PEAK => Some(2),
            THREAD_DAEMON => Some(3),
            CLASS_LOADED => Some(4),
            CLASS_SHARED_LOADED => Some(5),
            CLASS_UNLOADED => Some(6),
            CLASS_SHARED_UNLOADED => Some(7),
            _ => None,
        }
    }

    fn insert(&mut self, index: usize, value: u64) -> Result<(), ParseError> {
        if self.values[index].replace(value).is_some() {
            return Err(ParseError::DuplicateMetric);
        }
        Ok(())
    }

    fn finish(self) -> Result<JvmPerfDataMetrics, ParseError> {
        let [started, live, peak, daemon, loaded, shared_loaded, unloaded, shared_unloaded] = self
            .values
            .map(|value| value.ok_or(ParseError::MissingMetric));
        let started = started?;
        let live = live?;
        let peak = peak?;
        let daemon = daemon?;
        let loaded_total = loaded?
            .checked_add(shared_loaded?)
            .ok_or(ParseError::InvalidMetric)?;
        let unloaded_total = unloaded?
            .checked_add(shared_unloaded?)
            .ok_or(ParseError::InvalidMetric)?;
        let classes_loaded = loaded_total
            .checked_sub(unloaded_total)
            .ok_or(ParseError::InvalidMetric)?;
        if daemon > live || live > peak {
            return Err(ParseError::InvariantViolation);
        }
        Ok(JvmPerfDataMetrics {
            threads_started_total: started,
            threads_live: live,
            threads_peak: peak,
            threads_daemon: daemon,
            classes_loaded,
            classes_unloaded_total: unloaded_total,
        })
    }
}

/// Parse one complete, copied HotSpot PerfData `v2.0` snapshot.
pub fn parse(input: &[u8]) -> Result<JvmPerfDataMetrics, ParseError> {
    if input.len() > MAX_PERFDATA_BYTES {
        return Err(ParseError::InputTooLarge);
    }
    let prologue = input.get(..PROLOGUE_LEN).ok_or(ParseError::Malformed)?;
    if prologue[..4] != MAGIC {
        return Err(ParseError::InvalidMagic);
    }
    let order = match prologue[4] {
        0 => ByteOrder::Big,
        1 => ByteOrder::Little,
        _ => return Err(ParseError::UnsupportedFormat),
    };
    if prologue[5] != 2 || prologue[6] != 0 {
        return Err(ParseError::UnsupportedFormat);
    }
    if prologue[7] != 1 {
        return Err(ParseError::Inaccessible);
    }
    let used = nonnegative_usize(order.i32(&prologue[8..12])?)?;
    if order.i32(&prologue[12..16])? != 0 {
        return Err(ParseError::Overflow);
    }
    // Validate the timestamp field even though the capture layer compares it.
    let _modification_timestamp = order.i64(&prologue[16..24])?;
    let entry_offset = nonnegative_usize(order.i32(&prologue[24..28])?)?;
    let entry_count = nonnegative_usize(order.i32(&prologue[28..32])?)?;
    if used < PROLOGUE_LEN || used > input.len() || entry_count > MAX_ENTRIES {
        return Err(if entry_count > MAX_ENTRIES {
            ParseError::LimitExceeded
        } else {
            ParseError::Malformed
        });
    }
    if entry_offset < PROLOGUE_LEN || entry_offset > used || entry_offset % 8 != 0 {
        return Err(ParseError::Malformed);
    }

    let mut required = RequiredValues::default();
    let mut cursor = entry_offset;
    for _ in 0..entry_count {
        if cursor % 8 != 0 {
            return Err(ParseError::Malformed);
        }
        let header_end = cursor
            .checked_add(ENTRY_HEADER_LEN)
            .ok_or(ParseError::Malformed)?;
        let header = input.get(cursor..header_end).ok_or(ParseError::Malformed)?;
        let entry_len = nonnegative_usize(order.i32(&header[0..4])?)?;
        let name_offset = nonnegative_usize(order.i32(&header[4..8])?)?;
        let vector_length = order.i32(&header[8..12])?;
        let data_type = header[12];
        let flags = header[13];
        let units = header[14];
        let variability = header[15];
        let data_offset = nonnegative_usize(order.i32(&header[16..20])?)?;
        if entry_len < ENTRY_HEADER_LEN || entry_len % 8 != 0 {
            return Err(ParseError::Malformed);
        }
        let entry_end = cursor.checked_add(entry_len).ok_or(ParseError::Malformed)?;
        if entry_end > used || name_offset < ENTRY_HEADER_LEN || name_offset >= entry_len {
            return Err(ParseError::Malformed);
        }
        let name_start = cursor
            .checked_add(name_offset)
            .ok_or(ParseError::Malformed)?;
        let name_limit = name_start
            .checked_add(MAX_NAME_BYTES)
            .ok_or(ParseError::Malformed)?
            .min(entry_end);
        let name_bytes = input
            .get(name_start..name_limit)
            .ok_or(ParseError::Malformed)?;
        let nul = name_bytes
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(ParseError::LimitExceeded)?;
        let name_end = name_start
            .checked_add(nul + 1)
            .ok_or(ParseError::Malformed)?;
        let name = std::str::from_utf8(&name_bytes[..nul]).map_err(|_| ParseError::Malformed)?;
        if flags > 1 || !(1..=6).contains(&units) || !(1..=3).contains(&variability) {
            return Err(ParseError::Malformed);
        }

        let known_size = primitive_size(data_type);
        let data_range = if let Some(size) = known_size {
            let elements = if vector_length < 0 {
                return Err(ParseError::Malformed);
            } else if vector_length == 0 {
                1
            } else {
                usize::try_from(vector_length).map_err(|_| ParseError::Malformed)?
            };
            let data_len = size.checked_mul(elements).ok_or(ParseError::Malformed)?;
            if data_offset < ENTRY_HEADER_LEN {
                return Err(ParseError::Malformed);
            }
            let data_start = cursor
                .checked_add(data_offset)
                .ok_or(ParseError::Malformed)?;
            let data_end = data_start
                .checked_add(data_len)
                .ok_or(ParseError::Malformed)?;
            if data_end > entry_end || data_start % size != 0 {
                return Err(ParseError::Malformed);
            }
            if ranges_overlap(name_start, name_end, data_start, data_end) {
                return Err(ParseError::Malformed);
            }
            if input
                .get(name_end..data_start)
                .ok_or(ParseError::Malformed)?
                .iter()
                .any(|byte| *byte != 0)
            {
                return Err(ParseError::Malformed);
            }
            if units == 5 {
                if data_len > MAX_STRING_BYTES {
                    return Err(ParseError::LimitExceeded);
                }
                let string = input
                    .get(data_start..data_end)
                    .ok_or(ParseError::Malformed)?;
                if !string.contains(&0) {
                    return Err(ParseError::Malformed);
                }
            }
            Some((data_start, data_end))
        } else {
            // An unknown primitive has no trustworthy element width for full bounds validation.
            return Err(ParseError::Malformed);
        };

        if let Some(index) = RequiredValues::index(name) {
            let expected_units = if index == 1 || index == 2 || index == 3 {
                1
            } else {
                4
            };
            let expected_variability = if index == 1 || index == 2 || index == 3 {
                3
            } else {
                2
            };
            if data_type != b'J'
                || vector_length != 0
                || flags != 1
                || units != expected_units
                || variability != expected_variability
            {
                return Err(ParseError::InvalidMetric);
            }
            let (data_start, data_end) = data_range.ok_or(ParseError::InvalidMetric)?;
            let signed = order.i64(&input[data_start..data_end])?;
            let value = u64::try_from(signed).map_err(|_| ParseError::InvalidMetric)?;
            required.insert(index, value)?;
        }
        cursor = entry_end;
    }
    if cursor != used {
        return Err(ParseError::Malformed);
    }
    required.finish()
}

fn nonnegative_usize(value: i32) -> Result<usize, ParseError> {
    usize::try_from(value).map_err(|_| ParseError::Malformed)
}

fn primitive_size(data_type: u8) -> Option<usize> {
    match data_type {
        b'Z' | b'B' => Some(1),
        b'C' | b'S' => Some(2),
        b'I' | b'F' => Some(4),
        b'J' | b'D' => Some(8),
        _ => None,
    }
}

fn ranges_overlap(
    left_start: usize,
    left_end: usize,
    right_start: usize,
    right_end: usize,
) -> bool {
    left_start < right_end && right_start < left_end
}

/// Fixed input for the isolated JVM worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerRequest {
    pub pid: u32,
    pub start_ticks: u64,
    pub selector_digest_version: u8,
    pub selector_digest: [u8; 32],
    pub opaque_workload_id: [u8; 16],
}

/// Public wire failures deliberately collapse internal parser details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerFailure {
    Unreachable,
    Rejected,
    Malformed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerResponse {
    Metrics(JvmPerfDataMetrics),
    Failure(WorkerFailure),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecError {
    FrameTooLarge,
    Truncated,
    TrailingData,
    UnsupportedVersion,
    InvalidFrame,
}

pub fn encode_request(request: &WorkerRequest) -> Vec<u8> {
    let mut body = Vec::with_capacity(REQUEST_BODY_LEN);
    body.push(PROTOCOL_VERSION);
    body.extend_from_slice(&request.pid.to_be_bytes());
    body.extend_from_slice(&request.start_ticks.to_be_bytes());
    body.push(request.selector_digest_version);
    body.extend_from_slice(&request.selector_digest);
    body.extend_from_slice(&request.opaque_workload_id);
    frame(body)
}

pub fn decode_request(frame: &[u8]) -> Result<WorkerRequest, CodecError> {
    let body = decode_frame_body(frame, REQUEST_BODY_LEN)?;
    if body[0] != PROTOCOL_VERSION {
        return Err(CodecError::UnsupportedVersion);
    }
    Ok(WorkerRequest {
        pid: u32::from_be_bytes(body[1..5].try_into().map_err(|_| CodecError::Truncated)?),
        start_ticks: u64::from_be_bytes(body[5..13].try_into().map_err(|_| CodecError::Truncated)?),
        selector_digest_version: body[13],
        selector_digest: body[14..46].try_into().map_err(|_| CodecError::Truncated)?,
        opaque_workload_id: body[46..62].try_into().map_err(|_| CodecError::Truncated)?,
    })
}

pub fn encode_response(response: &WorkerResponse) -> Vec<u8> {
    let mut body = Vec::with_capacity(METRICS_RESPONSE_BODY_LEN);
    body.push(PROTOCOL_VERSION);
    match response {
        WorkerResponse::Metrics(metrics) => {
            body.push(0);
            for value in [
                metrics.threads_started_total,
                metrics.threads_live,
                metrics.threads_peak,
                metrics.threads_daemon,
                metrics.classes_loaded,
                metrics.classes_unloaded_total,
            ] {
                body.extend_from_slice(&value.to_be_bytes());
            }
        }
        WorkerResponse::Failure(failure) => {
            body.push(1);
            body.push(match failure {
                WorkerFailure::Unreachable => 0,
                WorkerFailure::Rejected => 1,
                WorkerFailure::Malformed => 2,
            });
        }
    }
    frame(body)
}

pub fn decode_response(frame: &[u8]) -> Result<WorkerResponse, CodecError> {
    let body = decode_variable_frame_body(frame)?;
    let version = *body.first().ok_or(CodecError::Truncated)?;
    if version != PROTOCOL_VERSION {
        return Err(CodecError::UnsupportedVersion);
    }
    match body.get(1) {
        Some(0) if body.len() == METRICS_RESPONSE_BODY_LEN => {
            let mut values = [0_u64; 6];
            for (index, slot) in values.iter_mut().enumerate() {
                let start = 2 + index * 8;
                *slot = u64::from_be_bytes(
                    body[start..start + 8]
                        .try_into()
                        .map_err(|_| CodecError::Truncated)?,
                );
            }
            Ok(WorkerResponse::Metrics(JvmPerfDataMetrics {
                threads_started_total: values[0],
                threads_live: values[1],
                threads_peak: values[2],
                threads_daemon: values[3],
                classes_loaded: values[4],
                classes_unloaded_total: values[5],
            }))
        }
        Some(1) if body.len() == FAILURE_RESPONSE_BODY_LEN => {
            let failure = match body[2] {
                0 => WorkerFailure::Unreachable,
                1 => WorkerFailure::Rejected,
                2 => WorkerFailure::Malformed,
                _ => return Err(CodecError::InvalidFrame),
            };
            Ok(WorkerResponse::Failure(failure))
        }
        Some(_) => Err(CodecError::InvalidFrame),
        None => Err(CodecError::Truncated),
    }
}

fn frame(body: Vec<u8>) -> Vec<u8> {
    let mut framed = Vec::with_capacity(4 + body.len());
    framed.extend_from_slice(&(body.len() as u32).to_be_bytes());
    framed.extend_from_slice(&body);
    framed
}

fn decode_frame_body(frame: &[u8], expected: usize) -> Result<&[u8], CodecError> {
    let body = decode_variable_frame_body(frame)?;
    if body.len() != expected {
        return Err(if body.len() < expected {
            CodecError::Truncated
        } else {
            CodecError::InvalidFrame
        });
    }
    Ok(body)
}

fn decode_variable_frame_body(frame: &[u8]) -> Result<&[u8], CodecError> {
    let prefix = frame.get(..4).ok_or(CodecError::Truncated)?;
    let declared =
        u32::from_be_bytes(prefix.try_into().map_err(|_| CodecError::Truncated)?) as usize;
    if declared > MAX_WORKER_FRAME_BODY {
        return Err(CodecError::FrameTooLarge);
    }
    let total = 4_usize
        .checked_add(declared)
        .ok_or(CodecError::FrameTooLarge)?;
    if frame.len() < total {
        return Err(CodecError::Truncated);
    }
    if frame.len() > total {
        return Err(CodecError::TrailingData);
    }
    Ok(&frame[4..total])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy)]
    enum TestOrder {
        Big,
        Little,
    }

    fn put_i32(buffer: &mut [u8], offset: usize, value: i32, order: TestOrder) {
        let bytes = match order {
            TestOrder::Big => value.to_be_bytes(),
            TestOrder::Little => value.to_le_bytes(),
        };
        buffer[offset..offset + 4].copy_from_slice(&bytes);
    }

    fn put_i64(buffer: &mut [u8], offset: usize, value: i64, order: TestOrder) {
        let bytes = match order {
            TestOrder::Big => value.to_be_bytes(),
            TestOrder::Little => value.to_le_bytes(),
        };
        buffer[offset..offset + 8].copy_from_slice(&bytes);
    }

    fn fixture(order: TestOrder) -> Vec<u8> {
        let metrics = [
            (THREAD_STARTED, 4, 2, 100),
            (THREAD_LIVE, 1, 3, 8),
            (THREAD_PEAK, 1, 3, 12),
            (THREAD_DAEMON, 1, 3, 3),
            (CLASS_LOADED, 4, 2, 80),
            (CLASS_SHARED_LOADED, 4, 2, 20),
            (CLASS_UNLOADED, 4, 2, 7),
            (CLASS_SHARED_UNLOADED, 4, 2, 3),
        ];
        let mut buffer = vec![0_u8; PROLOGUE_LEN];
        buffer[..4].copy_from_slice(&MAGIC);
        buffer[4] = match order {
            TestOrder::Big => 0,
            TestOrder::Little => 1,
        };
        buffer[5..8].copy_from_slice(&[2, 0, 1]);
        for (name, units, variability, value) in metrics {
            let name_len = name.len() + 1;
            let data_offset = (ENTRY_HEADER_LEN + name_len + 7) & !7;
            let entry_len = data_offset + 8;
            let start = buffer.len();
            buffer.resize(start + entry_len, 0);
            put_i32(&mut buffer, start, entry_len as i32, order);
            put_i32(&mut buffer, start + 4, ENTRY_HEADER_LEN as i32, order);
            put_i32(&mut buffer, start + 8, 0, order);
            buffer[start + 12..start + 16].copy_from_slice(&[b'J', 1, units, variability]);
            put_i32(&mut buffer, start + 16, data_offset as i32, order);
            buffer[start + ENTRY_HEADER_LEN..start + ENTRY_HEADER_LEN + name.len()]
                .copy_from_slice(name.as_bytes());
            put_i64(&mut buffer, start + data_offset, value, order);
        }
        let used = buffer.len() as i32;
        put_i32(&mut buffer, 8, used, order);
        put_i32(&mut buffer, 12, 0, order);
        put_i64(&mut buffer, 16, 42, order);
        put_i32(&mut buffer, 24, PROLOGUE_LEN as i32, order);
        put_i32(&mut buffer, 28, metrics.len() as i32, order);
        buffer
    }

    #[test]
    fn parses_required_metrics_in_both_byte_orders() {
        for order in [TestOrder::Big, TestOrder::Little] {
            assert_eq!(
                parse(&fixture(order)),
                Ok(JvmPerfDataMetrics {
                    threads_started_total: 100,
                    threads_live: 8,
                    threads_peak: 12,
                    threads_daemon: 3,
                    classes_loaded: 90,
                    classes_unloaded_total: 10,
                })
            );
        }
    }

    #[test]
    fn rejects_invalid_prologue_fields_and_limits() {
        let mut data = fixture(TestOrder::Little);
        data[0] = 0;
        assert_eq!(parse(&data), Err(ParseError::InvalidMagic));
        let mut data = fixture(TestOrder::Little);
        data[4] = 2;
        assert_eq!(parse(&data), Err(ParseError::UnsupportedFormat));
        let mut data = fixture(TestOrder::Little);
        data[6] = 1;
        assert_eq!(parse(&data), Err(ParseError::UnsupportedFormat));
        let mut data = fixture(TestOrder::Little);
        data[7] = 0;
        assert_eq!(parse(&data), Err(ParseError::Inaccessible));
        let mut data = fixture(TestOrder::Little);
        put_i32(&mut data, 12, 1, TestOrder::Little);
        assert_eq!(parse(&data), Err(ParseError::Overflow));
        assert_eq!(
            parse(&vec![0; MAX_PERFDATA_BYTES + 1]),
            Err(ParseError::InputTooLarge)
        );
    }

    #[test]
    fn rejects_entry_bounds_alignment_and_nonprogress() {
        let mut data = fixture(TestOrder::Little);
        put_i32(&mut data, PROLOGUE_LEN, 0, TestOrder::Little);
        assert_eq!(parse(&data), Err(ParseError::Malformed));
        let mut data = fixture(TestOrder::Little);
        put_i32(&mut data, PROLOGUE_LEN, 25, TestOrder::Little);
        assert_eq!(parse(&data), Err(ParseError::Malformed));
        let mut data = fixture(TestOrder::Little);
        put_i32(&mut data, PROLOGUE_LEN + 16, 21, TestOrder::Little);
        assert_eq!(parse(&data), Err(ParseError::Malformed));
        let mut data = fixture(TestOrder::Little);
        put_i32(&mut data, 28, 4097, TestOrder::Little);
        assert_eq!(parse(&data), Err(ParseError::LimitExceeded));
    }

    #[test]
    fn rejects_missing_duplicate_negative_and_bad_metadata() {
        let mut data = fixture(TestOrder::Little);
        rename_metric(&mut data, CLASS_SHARED_UNLOADED);
        assert_eq!(parse(&data), Err(ParseError::MissingMetric));

        let mut data = fixture(TestOrder::Little);
        let first = entry_start(&data, 0);
        let first_len = i32::from_le_bytes(data[first..first + 4].try_into().unwrap()) as usize;
        let duplicate = data[first..first + first_len].to_vec();
        data.extend_from_slice(&duplicate);
        let used = data.len() as i32;
        put_i32(&mut data, 8, used, TestOrder::Little);
        put_i32(&mut data, 28, 9, TestOrder::Little);
        assert_eq!(parse(&data), Err(ParseError::DuplicateMetric));

        let mut data = fixture(TestOrder::Little);
        let data_offset = i32::from_le_bytes(
            data[PROLOGUE_LEN + 16..PROLOGUE_LEN + 20]
                .try_into()
                .unwrap(),
        ) as usize;
        put_i64(&mut data, PROLOGUE_LEN + data_offset, -1, TestOrder::Little);
        assert_eq!(parse(&data), Err(ParseError::InvalidMetric));

        let mut data = fixture(TestOrder::Little);
        data[PROLOGUE_LEN + 13] = 0;
        assert_eq!(parse(&data), Err(ParseError::InvalidMetric));
    }

    #[test]
    fn rejects_metric_invariants_and_class_underflow() {
        let mut data = fixture(TestOrder::Little);
        set_metric(&mut data, THREAD_DAEMON, 9);
        assert_eq!(parse(&data), Err(ParseError::InvariantViolation));
        let mut data = fixture(TestOrder::Little);
        set_metric(&mut data, CLASS_LOADED, 1);
        set_metric(&mut data, CLASS_SHARED_LOADED, 1);
        assert_eq!(parse(&data), Err(ParseError::InvalidMetric));
    }

    fn set_metric(data: &mut [u8], target: &str, value: i64) {
        let mut cursor = PROLOGUE_LEN;
        loop {
            let len = i32::from_le_bytes(data[cursor..cursor + 4].try_into().unwrap()) as usize;
            let name_offset =
                i32::from_le_bytes(data[cursor + 4..cursor + 8].try_into().unwrap()) as usize;
            let name = &data[cursor + name_offset..cursor + len];
            let nul = name.iter().position(|byte| *byte == 0).unwrap();
            if &name[..nul] == target.as_bytes() {
                let data_offset =
                    i32::from_le_bytes(data[cursor + 16..cursor + 20].try_into().unwrap()) as usize;
                put_i64(data, cursor + data_offset, value, TestOrder::Little);
                return;
            }
            cursor += len;
        }
    }

    fn rename_metric(data: &mut [u8], target: &str) {
        let mut cursor = PROLOGUE_LEN;
        loop {
            let len = i32::from_le_bytes(data[cursor..cursor + 4].try_into().unwrap()) as usize;
            let name_offset =
                i32::from_le_bytes(data[cursor + 4..cursor + 8].try_into().unwrap()) as usize;
            let name = &data[cursor + name_offset..cursor + len];
            let nul = name.iter().position(|byte| *byte == 0).unwrap();
            if &name[..nul] == target.as_bytes() {
                data[cursor + name_offset] = b'x';
                return;
            }
            cursor += len;
        }
    }

    fn entry_start(data: &[u8], index: usize) -> usize {
        let mut cursor = PROLOGUE_LEN;
        for _ in 0..index {
            let len = i32::from_le_bytes(data[cursor..cursor + 4].try_into().unwrap()) as usize;
            cursor += len;
        }
        cursor
    }

    #[test]
    fn validates_unknown_entries_before_ignoring_them() {
        let mut data = fixture(TestOrder::Little);
        data[PROLOGUE_LEN + 12] = b'Q';
        assert_eq!(parse(&data), Err(ParseError::Malformed));
        let mut data = fixture(TestOrder::Little);
        data[PROLOGUE_LEN + 12] = b'Q';
        put_i32(&mut data, PROLOGUE_LEN + 16, 0, TestOrder::Little);
        assert_eq!(parse(&data), Err(ParseError::Malformed));
    }

    fn request() -> WorkerRequest {
        WorkerRequest {
            pid: 42,
            start_ticks: 99,
            selector_digest_version: 3,
            selector_digest: [7; 32],
            opaque_workload_id: [9; 16],
        }
    }

    #[test]
    fn request_codec_round_trips_deterministically() {
        let encoded = encode_request(&request());
        assert_eq!(encoded.len(), 4 + REQUEST_BODY_LEN);
        assert_eq!(encode_request(&request()), encoded);
        assert_eq!(decode_request(&encoded), Ok(request()));
    }

    #[test]
    fn response_codec_round_trips_metrics_and_failures() {
        let metrics = parse(&fixture(TestOrder::Little)).unwrap();
        let response = WorkerResponse::Metrics(metrics);
        assert_eq!(decode_response(&encode_response(&response)), Ok(response));
        for failure in [
            WorkerFailure::Unreachable,
            WorkerFailure::Rejected,
            WorkerFailure::Malformed,
        ] {
            let response = WorkerResponse::Failure(failure);
            assert_eq!(decode_response(&encode_response(&response)), Ok(response));
        }
    }

    #[test]
    fn codec_rejects_cap_truncation_trailing_and_version() {
        let mut oversized = Vec::new();
        oversized.extend_from_slice(&((MAX_WORKER_FRAME_BODY + 1) as u32).to_be_bytes());
        assert_eq!(decode_request(&oversized), Err(CodecError::FrameTooLarge));

        let encoded = encode_request(&request());
        assert_eq!(
            decode_request(&encoded[..encoded.len() - 1]),
            Err(CodecError::Truncated)
        );
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(decode_request(&trailing), Err(CodecError::TrailingData));
        let mut wrong_version = encoded;
        wrong_version[4] = PROTOCOL_VERSION + 1;
        assert_eq!(
            decode_request(&wrong_version),
            Err(CodecError::UnsupportedVersion)
        );
    }
}
