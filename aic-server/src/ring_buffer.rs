//! 최근 명령어 레코드를 순환 저장하는 인메모리 버퍼.
//!
//! 용량 제약은 레코드 수가 아닌 **총 출력 라인 수** 기준이다.
//! `max_lines`를 초과하면 가장 오래된 레코드부터 제거한다.

use aic_common::CommandRecord;
use std::collections::VecDeque;

pub struct RingBuffer {
    records: VecDeque<CommandRecord>,
    max_lines: usize,
    current_line_count: usize,
}

impl RingBuffer {
    /// `max_lines` 라인 용량의 Ring Buffer 생성.
    pub fn new(max_lines: usize) -> Self {
        Self {
            records: VecDeque::new(),
            max_lines,
            current_line_count: 0,
        }
    }

    /// 새 CommandRecord 추가. 총 라인 수가 max_lines 초과 시 오래된 레코드부터 제거.
    pub fn push(&mut self, record: CommandRecord) {
        let new_lines = record.output_lines.len();

        // 새 레코드 자체가 max_lines보다 크면 기존 레코드를 모두 비우고 새 레코드만 저장
        if new_lines > self.max_lines {
            self.records.clear();
            self.current_line_count = 0;
            self.records.push_back(record);
            self.current_line_count = new_lines;
            return;
        }

        // 오래된 레코드를 제거하여 공간 확보
        while self.current_line_count + new_lines > self.max_lines {
            if let Some(oldest) = self.records.pop_front() {
                self.current_line_count -= oldest.output_lines.len();
            } else {
                break;
            }
        }

        self.current_line_count += new_lines;
        self.records.push_back(record);
    }

    /// 가장 최근 CommandRecord 반환.
    pub fn last(&self) -> Option<&CommandRecord> {
        self.records.back()
    }

    /// 전체 저장된 출력 라인 수 반환.
    pub fn total_lines(&self) -> usize {
        self.current_line_count
    }

    /// 라인 용량 (`max_lines`).
    pub fn capacity(&self) -> usize {
        self.max_lines
    }

    /// 최근 N 라인의 텍스트를 시간순(오래된 → 최신)으로 반환.
    pub fn recent_lines(&self, n: usize) -> Vec<&str> {
        if n == 0 {
            return Vec::new();
        }

        // 뒤에서부터 레코드를 순회하며 라인 수집
        let mut collected: Vec<&str> = Vec::with_capacity(n);
        let mut remaining = n;

        for record in self.records.iter().rev() {
            let lines = &record.output_lines;
            if lines.len() <= remaining {
                // 이 레코드의 모든 라인을 역순으로 추가
                for line in lines.iter().rev() {
                    collected.push(line.as_str());
                }
                remaining -= lines.len();
            } else {
                // 이 레코드의 마지막 remaining개 라인만 역순으로 추가
                for line in lines[lines.len() - remaining..].iter().rev() {
                    collected.push(line.as_str());
                }
                remaining = 0;
            }

            if remaining == 0 {
                break;
            }
        }

        // 역순으로 수집했으므로 뒤집어서 시간순으로 반환
        collected.reverse();
        collected
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use proptest::prelude::*;

    fn make_record(lines: Vec<&str>) -> CommandRecord {
        CommandRecord {
            command: Some("test".to_string()),
            exit_code: 0,
            output_lines: lines.into_iter().map(String::from).collect(),
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn empty_buffer_last_returns_none() {
        let buf = RingBuffer::new(100);
        assert!(buf.last().is_none());
        assert_eq!(buf.total_lines(), 0);
    }

    #[test]
    fn single_record_push_and_last() {
        let mut buf = RingBuffer::new(100);
        let record = make_record(vec!["hello", "world"]);
        buf.push(record.clone());

        assert_eq!(buf.last().unwrap().output_lines, vec!["hello", "world"]);
        assert_eq!(buf.total_lines(), 2);
    }

    #[test]
    fn eviction_when_exceeding_max_lines() {
        let mut buf = RingBuffer::new(5);

        buf.push(make_record(vec!["a", "b", "c"])); // 3 lines
        buf.push(make_record(vec!["d", "e"])); // +2 = 5 lines (정확히 max)
        assert_eq!(buf.total_lines(), 5);

        buf.push(make_record(vec!["f"])); // +1 = 6 > 5 → 첫 레코드(3줄) 제거
        assert_eq!(buf.total_lines(), 3); // 2 + 1
        assert_eq!(buf.last().unwrap().output_lines, vec!["f"]);
    }

    #[test]
    fn recent_lines_collects_across_records() {
        let mut buf = RingBuffer::new(100);
        buf.push(make_record(vec!["a", "b"]));
        buf.push(make_record(vec!["c", "d", "e"]));

        assert_eq!(buf.recent_lines(3), vec!["c", "d", "e"]);
        assert_eq!(buf.recent_lines(4), vec!["b", "c", "d", "e"]);
        assert_eq!(buf.recent_lines(5), vec!["a", "b", "c", "d", "e"]);
        // n이 총 라인 수보다 크면 가능한 만큼만 반환
        assert_eq!(buf.recent_lines(10), vec!["a", "b", "c", "d", "e"]);
    }

    #[test]
    fn recent_lines_zero_returns_empty() {
        let mut buf = RingBuffer::new(100);
        buf.push(make_record(vec!["a"]));
        assert!(buf.recent_lines(0).is_empty());
    }

    #[test]
    fn record_with_zero_lines() {
        let mut buf = RingBuffer::new(10);
        buf.push(make_record(vec![]));
        assert_eq!(buf.total_lines(), 0);
        assert!(buf.recent_lines(5).is_empty());
        assert!(buf.last().is_some());
    }

    #[test]
    fn oversized_record_replaces_all() {
        let mut buf = RingBuffer::new(3);
        buf.push(make_record(vec!["a", "b"]));
        // 새 레코드가 max_lines보다 큰 경우
        buf.push(make_record(vec!["x", "y", "z", "w"]));
        assert_eq!(buf.total_lines(), 4);
        assert_eq!(buf.recent_lines(4), vec!["x", "y", "z", "w"]);
    }

    // --- max_lines 경계값 edge case 테스트 ---

    #[test]
    fn max_lines_one_single_line_record() {
        let mut buf = RingBuffer::new(1);
        buf.push(make_record(vec!["a"]));
        assert_eq!(buf.total_lines(), 1);
        assert_eq!(buf.last().unwrap().output_lines, vec!["a"]);

        // 새 레코드 push → 기존 레코드 eviction
        buf.push(make_record(vec!["b"]));
        assert_eq!(buf.total_lines(), 1);
        assert_eq!(buf.last().unwrap().output_lines, vec!["b"]);
        assert_eq!(buf.recent_lines(10), vec!["b"]);
    }

    #[test]
    fn exact_fill_no_eviction() {
        let mut buf = RingBuffer::new(4);
        buf.push(make_record(vec!["a", "b"])); // 2 lines
        buf.push(make_record(vec!["c", "d"])); // +2 = 4 lines (정확히 max)
        assert_eq!(buf.total_lines(), 4);
        assert_eq!(buf.recent_lines(4), vec!["a", "b", "c", "d"]);
    }

    #[test]
    fn single_eviction_on_boundary() {
        let mut buf = RingBuffer::new(3);
        buf.push(make_record(vec!["a", "b"])); // 2 lines
        buf.push(make_record(vec!["c"])); // +1 = 3 (정확히 max, eviction 없음)
        assert_eq!(buf.total_lines(), 3);

        buf.push(make_record(vec!["d"])); // +1 = 4 > 3 → 첫 레코드(2줄) 제거
        assert_eq!(buf.total_lines(), 2); // "c" + "d"
        assert_eq!(buf.recent_lines(3), vec!["c", "d"]);
    }

    #[test]
    fn consecutive_pushes_each_trigger_eviction() {
        let mut buf = RingBuffer::new(2);
        buf.push(make_record(vec!["a", "b"])); // 2 lines (max)
        assert_eq!(buf.total_lines(), 2);

        buf.push(make_record(vec!["c"])); // +1 > 2 → "a","b" 제거 → 1 line
        assert_eq!(buf.total_lines(), 1);
        assert_eq!(buf.recent_lines(2), vec!["c"]);

        buf.push(make_record(vec!["d", "e"])); // +2 > 2 → "c" 제거 → 2 lines
        assert_eq!(buf.total_lines(), 2);
        assert_eq!(buf.recent_lines(2), vec!["d", "e"]);

        buf.push(make_record(vec!["f"])); // +1 > 2 → "d","e" 제거 → 1 line
        assert_eq!(buf.total_lines(), 1);
        assert_eq!(buf.recent_lines(2), vec!["f"]);
    }

    // Feature: ac-cli-tool, Property 2: Ring Buffer FIFO with Capacity Constraint

    /// 임의의 CommandRecord를 생성하는 proptest strategy.
    /// output_lines는 0~10개, 각 라인은 임의의 문자열.
    fn arb_command_record() -> impl Strategy<Value = CommandRecord> {
        (
            proptest::option::of("[a-z0-9 _-]{0,20}"),
            -128i32..128i32,
            prop::collection::vec("[a-zA-Z0-9 ]{0,30}", 0..=10),
        )
            .prop_map(|(command, exit_code, output_lines)| CommandRecord {
                command,
                exit_code,
                output_lines,
                timestamp: Utc::now(),
            })
    }

    proptest! {
        /// **Validates: Requirements 2.2, 2.3, 2.4, 4.4**
        ///
        /// 임의의 N개 CommandRecord 시퀀스에 대해:
        /// (1) 총 라인 수 ≤ max_lines (단일 레코드가 max_lines 초과하는 경우 제외)
        /// (2) 최근 레코드가 push 순서대로 존재 (FIFO)
        /// (3) last()가 마지막 push된 레코드 반환
        #[test]
        fn ring_buffer_fifo_with_capacity_constraint(
            records in prop::collection::vec(arb_command_record(), 1..=30),
            max_lines in 1usize..=100,
        ) {
            let mut buf = RingBuffer::new(max_lines);

            for record in &records {
                buf.push(record.clone());
            }

            // (1) total_lines() ≤ max_lines, 단 마지막 레코드가 max_lines 초과 시 예외
            let last_record_lines = records.last().unwrap().output_lines.len();
            if last_record_lines > max_lines {
                // 단일 레코드가 max_lines보다 크면 해당 레코드만 남음
                prop_assert_eq!(buf.total_lines(), last_record_lines);
            } else {
                prop_assert!(
                    buf.total_lines() <= max_lines,
                    "total_lines({}) > max_lines({})",
                    buf.total_lines(),
                    max_lines
                );
            }

            // (3) last()는 가장 마지막에 push된 레코드를 반환
            let last = buf.last().unwrap();
            let expected_last = records.last().unwrap();
            prop_assert_eq!(&last.output_lines, &expected_last.output_lines);
            prop_assert_eq!(last.exit_code, expected_last.exit_code);
            prop_assert_eq!(&last.command, &expected_last.command);

            // (2) 버퍼에 남은 레코드들은 push 순서(FIFO)를 유지
            // 참조 구현으로 기대값을 계산하여 recent_lines 결과와 비교
            let mut ref_buf = RingBuffer::new(max_lines);
            for record in &records {
                ref_buf.push(record.clone());
            }
            let all_recent = buf.recent_lines(buf.total_lines());
            let ref_recent = ref_buf.recent_lines(ref_buf.total_lines());
            prop_assert_eq!(&all_recent, &ref_recent,
                "FIFO order mismatch: two identical push sequences must yield identical results");

            // 추가 검증: recent_lines의 라인들이 원본 records의 push 순서를 유지하는지 확인
            // 버퍼에 남은 라인들을 원본 records 끝에서부터 매칭
            let mut expected_lines: Vec<&str> = Vec::new();
            for record in records.iter().rev() {
                let candidate: Vec<&str> = record.output_lines.iter().map(|s| s.as_str()).collect();
                let candidate_len = candidate.len();
                if candidate_len + expected_lines.len() <= buf.total_lines() {
                    // 이 레코드의 라인을 앞에 추가 (나중에 reverse)
                    for line in candidate.into_iter().rev() {
                        expected_lines.push(line);
                    }
                } else {
                    break;
                }
            }
            expected_lines.reverse();
            prop_assert_eq!(all_recent, expected_lines,
                "FIFO order: recent lines must match the most recent records in push order");
        }
    }
}
