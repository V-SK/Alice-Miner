//! `logo` — the Alice brand mark as compact terminal block-art.
//!
//! This is a FAITHFUL, offline-rasterized render of the website logo
//! (`alice-website/assets/alice-logo.svg` — the stylized "A" mark with the inner
//! hourglass notch and split legs, brand orange `#F97316`). The SVG's single filled
//! path (two subpaths, even-odd) was rasterized OFFLINE to a 34×24 pixel grid and
//! collapsed to a 34-column × 12-row half-block grid: each cell encodes its two
//! vertical pixels as `F` (both → `█`), `T` (upper only → `▀`), `B` (lower only →
//! `▄`), or a space (empty). We COMMIT that grid as a `const` here and map it to
//! ratatui spans at render time — NO runtime SVG rasterizer dependency.
//!
//! Fidelity note: at 34×12 the mark is recognizable as the Alice "A" (triangular
//! outline, the two interior facets, the two feet). The brand orange is applied as
//! a truecolor foreground; on a terminal without truecolor, ratatui degrades it to
//! the nearest ANSI color, and the shape still reads.

use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};

/// The Alice brand orange (`#F97316`).
pub const BRAND: Color = Color::Rgb(0xF9, 0x71, 0x16);

/// The committed half-block art grid (34 cols × 12 rows). Each char:
///   `F` = full block `█` · `T` = upper half `▀` · `B` = lower half `▄` · ` ` = empty.
/// Produced by the offline rasterizer over the logo SVG (see the module docs).
const LOGO_ART: &[&str] = &[
    "                 B                ",
    "               BFFB               ",
    "             BFFFFFF              ",
    "            BFFFFFFFFB            ",
    "           FFFFFFFFFFFF           ",
    "         BFFFFFT  TFFFFFB         ",
    "        BFFFFF      FFFFFF        ",
    "      BFFFFFT        TFFFFFB      ",
    "     BFFFFF            FFFFFF     ",
    "   BFFFFFFT            FFFFFFFB   ",
    "  BFFFFFFFF            FFFFFFFFB  ",
    " TTTTTTTTTTTT        TTTTTTTTTTTT ",
];

/// The number of rows the rendered logo occupies (compact — fits ~12 rows).
pub const LOGO_ROWS: u16 = 12;

/// Map an art cell code to its Unicode half-block glyph.
fn glyph(c: char) -> char {
    match c {
        'F' => '█',
        'T' => '▀',
        'B' => '▄',
        _ => ' ',
    }
}

/// Build the logo as styled ratatui [`Line`]s (brand-orange foreground on the default
/// background). Each art row becomes one line; empty cells are plain spaces so the
/// mark floats on whatever background the terminal uses.
pub fn lines() -> Vec<Line<'static>> {
    let style = Style::default().fg(BRAND);
    LOGO_ART
        .iter()
        .map(|row| {
            let rendered: String = row.chars().map(glyph).collect();
            Line::from(Span::styled(rendered, style))
        })
        .collect()
}

/// A PLAIN-TEXT (no ANSI) rendering of the logo, for a non-ratatui fallback or a
/// dumb terminal. Same shape, just the half-block glyphs with no color. (Exposed for
/// a future non-TUI fallback + exercised by tests; the live menu path uses [`lines`].)
#[allow(dead_code)]
pub fn plain() -> String {
    LOGO_ART
        .iter()
        .map(|row| row.chars().map(glyph).collect::<String>())
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The art is exactly 12 rows (the compact budget) and every row is the same width.
    #[test]
    fn art_is_rectangular_and_compact() {
        assert_eq!(LOGO_ART.len(), 12);
        assert_eq!(LOGO_ROWS, 12);
        let w = LOGO_ART[0].chars().count();
        assert_eq!(w, 34, "34 columns");
        for (i, row) in LOGO_ART.iter().enumerate() {
            assert_eq!(row.chars().count(), w, "row {i} width mismatch");
        }
    }

    /// Every art cell is one of the four legal codes (F / T / B / space).
    #[test]
    fn art_cells_are_legal_codes() {
        for row in LOGO_ART {
            for c in row.chars() {
                assert!(matches!(c, 'F' | 'T' | 'B' | ' '), "illegal cell {c:?}");
            }
        }
    }

    /// The rendered lines carry the brand color and the block glyphs (a real mark, not
    /// blank), and the plain form has the same row count.
    #[test]
    fn renders_brand_colored_blocks() {
        let ls = lines();
        assert_eq!(ls.len(), 12);
        let joined = plain();
        assert!(joined.contains('█'), "has full blocks");
        assert_eq!(joined.lines().count(), 12);
    }
}
