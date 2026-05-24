//! RFC-004 단계 1 — tui-textarea 0.7의 CJK(한글) 처리 검증 PoC.
//! go/no-go: 통과 시 tui-textarea 채택, 실패 시 직접 입력 위젯(split_at_width 재사용).

use ratatui::{backend::TestBackend, Terminal};
use tui_textarea::{CursorMove, TextArea};

/// 한글이 char(grapheme) 단위로 편집되는가 — cursor index, 중간 삽입.
#[test]
fn cjk_char_level_editing() {
    let mut ta = TextArea::default();
    ta.insert_str("가나다");
    assert_eq!(ta.lines(), ["가나다"]);
    // cursor는 char index (display col 아님) — 끝이면 3.
    assert_eq!(ta.cursor(), (0, 3));

    // 두 칸 왼쪽 = '나' 앞(char index 1).
    ta.move_cursor(CursorMove::Back);
    ta.move_cursor(CursorMove::Back);
    assert_eq!(ta.cursor(), (0, 1));

    // 한글 사이에 삽입.
    ta.insert_char('X');
    assert_eq!(ta.lines(), ["가X나다"]);
    assert_eq!(ta.cursor(), (0, 2));
}

/// 렌더 시 한글이 2-cell wide로 그려지는가 — display width 정확성.
#[test]
fn cjk_render_display_width() {
    let mut ta = TextArea::default();
    ta.insert_str("가나");
    let mut term = Terminal::new(TestBackend::new(12, 1)).unwrap();
    term.draw(|f| f.render_widget(&ta, f.area())).unwrap();
    let buf = term.backend().buffer();
    // 한글은 2 cell 폭: "가"=cell0(다음 cell은 wide 연속), "나"=cell2.
    assert_eq!(buf[(0, 0)].symbol(), "가", "cell0 should be 가");
    assert_eq!(buf[(2, 0)].symbol(), "나", "cell2 should be 나 (가 takes 2 cells)");
}

/// 영문/한글 혼용 + 삭제(backspace) — grapheme 경계.
#[test]
fn mixed_ascii_cjk_delete() {
    let mut ta = TextArea::default();
    ta.insert_str("a가b나");
    assert_eq!(ta.cursor(), (0, 4));
    // backspace 1회 → '나' 삭제.
    ta.delete_char();
    assert_eq!(ta.lines(), ["a가b"]);
    assert_eq!(ta.cursor(), (0, 3));
}
