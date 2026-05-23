package tui

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/seolcu/hostveil/internal/domain"
)

// ─── Debug layout mode ──────────────────────────────────────────────────────
var debugLayout = os.Getenv("HOSTVEIL_TUI_DEBUG_LAYOUT") == "1"

// assertDisplayWidthLTE checks that no line in s exceeds maxW.
// In debug mode it prints violations to stderr. Always recomputes widths
// for accuracy; compile-time noop only if dead-code-eliminated.
func assertDisplayWidthLTE(s string, maxW int) {
	if !debugLayout {
		return
	}
	for _, line := range strings.Split(s, "\n") {
		w := lipgloss.Width(line)
		if w > maxW {
			fmt.Fprintf(os.Stderr, "[layout] overflow %d > %d: %s\n", w, maxW, truncateStr(stripANSI(line), 60))
		}
	}
}

// Rect defines a rectangular region in terminal cell coordinates.
// W and H include borders (outer width/height).
type Rect struct {
	X, Y, W, H int
}

// Right returns the rightmost column index (inclusive).
func (r Rect) Right() int { return r.X + r.W - 1 }

// Bottom returns the bottommost row index (inclusive).
func (r Rect) Bottom() int { return r.Y + r.H - 1 }

// InnerW returns the inner (usable) width excluding left/right borders.
func (r Rect) InnerW() int { return max(0, r.W-2) }

// InnerH returns the inner (usable) height excluding top/bottom borders.
func (r Rect) InnerH() int { return max(0, r.H-2) }

// Inner returns the inner Rect with borders removed.
func (r Rect) Inner() Rect { return Rect{r.X + 1, r.Y + 1, max(0, r.W-2), max(0, r.H-2)} }

// Fit reports whether r fits within the given terminal dimensions (no overflow).
func (r Rect) Fit(termW, termH int) bool {
	return r.X >= 0 && r.Y >= 0 && r.Right() < termW && r.Bottom() < termH
}

// Spacing defines consistent gap/padding values for a given layout mode.
type Spacing struct {
	OuterX    int // left/right outer margin
	OuterY    int // top/bottom outer margin
	RowGap    int // number of blank lines between rows
	ColGap    int // number of spaces between columns
	CardPadX  int // left/right padding inside cards (beyond border)
	CardPadY  int // top/bottom padding inside cards (beyond border)
	FooterGap int // blank lines between last content row and footer
}

// spacingFor returns the appropriate Spacing for a given LayoutMode.
func spacingFor(mode LayoutMode) Spacing {
	switch {
	case mode >= LayoutWide:
		return Spacing{OuterX: 0, OuterY: 0, RowGap: 0, ColGap: 0, CardPadX: 2, CardPadY: 0, FooterGap: 0}
	case mode >= LayoutMedium:
		return Spacing{OuterX: 0, OuterY: 0, RowGap: 0, ColGap: 0, CardPadX: 1, CardPadY: 0, FooterGap: 0}
	default:
		return Spacing{OuterX: 0, OuterY: 0, RowGap: 0, ColGap: 0, CardPadX: 0, CardPadY: 0, FooterGap: 0}
	}
}

// contentArea returns the safe root content area given terminal dimensions.
// Column overflow is prevented by splitColumns (gap subtracted first) and
// joinColumns (truncates over-wide columns), so no safe-right-margin needed.
func contentArea(termW, termH int) Rect {
	return Rect{
		X: 0,
		Y: 1, // below header
		W: termW,
		H: max(0, termH-1-1), // minus header(1) and footer(1)
	}
}

// splitColumns divides totalW into numCols columns with colGap between them.
// Gap is subtracted from totalW before distribution, so the sum of returned
// widths plus gaps equals totalW (or less, due to integer division).
func splitColumns(totalW int, numCols int, colGap int) []int {
	if numCols <= 0 {
		return nil
	}
	if numCols == 1 {
		return []int{totalW}
	}
	available := totalW - colGap*(numCols-1)
	if available < numCols {
		available = numCols
	}
	base := available / numCols
	remainder := available % numCols
	widths := make([]int, numCols)
	for i := range widths {
		widths[i] = base
		if i < remainder {
			widths[i]++
		}
	}
	return widths
}

type LayoutMode int

const (
	LayoutMini LayoutMode = iota
	LayoutCompact
	LayoutMedium
	LayoutWide
	LayoutUltraWide
)

func layoutMode(w, h int) LayoutMode {
	switch {
	case w >= 180 && h >= 45:
		return LayoutUltraWide
	case w >= 120 && h >= 35:
		return LayoutWide
	case w >= 80 && h >= 24:
		return LayoutMedium
	case w >= 50 && h >= 16:
		return LayoutCompact
	default:
		return LayoutMini
	}
}

// renderCard renders a bordered card. width is passed through to
// lipgloss.Width() — the outer rendered width will be width+2 (border).
// Use renderCardBounded when you need exact outer-width control.
func renderCard(title, body string, theme Theme, width, height int) string {
	return renderCardBounded(title, body, theme, Rect{W: width + 2, H: height})
}

// renderCardBounded renders a bordered card whose outer dimensions match
// bounds exactly (W × H). borders are included in bounds.W and bounds.H.
// Content lines are clipped or padded inside the card so the rendered card
// always occupies exactly bounds.H visual rows.
func renderCardBounded(title, body string, theme Theme, bounds Rect) string {
	innerW := bounds.InnerW()
	if innerW < 4 {
		innerW = 4
	}
	contentW := innerW - 2 // subtract padding(2)
	if contentW < 2 {
		contentW = 2
	}

	// Truncate body lines to fit content width
	if body != "" {
		var truncated []string
		for _, line := range strings.Split(body, "\n") {
			if lipgloss.Width(stripANSI(line)) > contentW {
				truncated = append(truncated, truncateWidth(line, contentW))
			} else {
				truncated = append(truncated, line)
			}
		}
		body = strings.Join(truncated, "\n")
	}

	// Build content lines (title + body bodyLines)
	var contentLines []string
	if title != "" {
		titleStyle := lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color(theme.Text)).
			Width(contentW)
		if lipgloss.Width(title) > contentW {
			title = truncateWidth(title, contentW)
		}
		contentLines = append(contentLines, titleStyle.Render(title))
	}
	if body != "" {
		for _, line := range strings.Split(body, "\n") {
			contentLines = append(contentLines, line)
		}
	}

	// Fixed-height contract: pad/truncate content to fill the slot INSIDE the
	// card border. The border consumes 2 rows (top + bottom), so content height
	// = bounds.H - 2. Short content is padded, long content is clipped.
	if bounds.H > 0 {
		targetContentH := bounds.H - 2
		if targetContentH < 0 {
			targetContentH = 0
		}
		if len(contentLines) > targetContentH {
			contentLines = contentLines[:targetContentH]
		}
		for len(contentLines) < targetContentH {
			contentLines = append(contentLines, "")
		}
	}

	style := lipgloss.NewStyle().
		Width(innerW).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(theme.Border)).
		Padding(0, 1)

	content := strings.Join(contentLines, "\n")
	rendered := style.Render(content)
	if debugLayout {
		lw := lipgloss.Width(rendered)
		if lw > bounds.W {
			fmt.Fprintf(os.Stderr, "[layout] renderCardBounded: outer %d > bounds.W %d (innerW=%d, contentW=%d)\n",
				lw, bounds.W, innerW, contentW)
		}
	}
	return rendered
}

// lineCount returns the number of visible lines in s (including ANSI sequences).
func lineCount(s string) int {
	if s == "" {
		return 0
	}
	return strings.Count(s, "\n") + 1
}

// fitBlockHeight pads or truncates s to exactly targetH lines.
func fitBlockHeight(s string, targetH int) string {
	if targetH <= 0 {
		return ""
	}
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) == 1 && lines[0] == "" {
		lines = []string{}
	}
	if len(lines) > targetH {
		lines = lines[:targetH]
	}
	for len(lines) < targetH {
		lines = append(lines, "")
	}
	return strings.Join(lines, "\n")
}

func truncateWidth(s string, maxWidth int) string {
	// Fast path: if visible width already fits, return as-is
	if lipgloss.Width(s) <= maxWidth {
		return s
	}

	var visible int
	var result strings.Builder
	inEscape := false
	hasAnsi := false
	for _, r := range s {
		if r == '\x1b' {
			inEscape = true
			hasAnsi = true
			result.WriteRune(r)
			continue
		}
		if inEscape {
			result.WriteRune(r)
			if r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' {
				inEscape = false
			}
			continue
		}
		rw := lipgloss.Width(string(r))
		if visible+rw > maxWidth-1 {
			result.WriteString("…")
			break
		}
		result.WriteRune(r)
		visible += rw
	}
	if hasAnsi {
		result.WriteString("\x1b[0m")
	}
	return result.String()
}

func truncatePathForWidth(path string, maxWidth int) string {
	if maxWidth < 8 {
		return "…"
	}
	if lipgloss.Width(stripANSI(path)) <= maxWidth {
		return path
	}

	// Try filename only
	parts := strings.Split(path, "/")
	filename := parts[len(parts)-1]
	if lipgloss.Width(filename)+4 <= maxWidth {
		return ".../" + filename
	}

	// Try parent/filename
	if len(parts) >= 2 {
		parent := parts[len(parts)-2]
		parentFile := parent + "/" + filename
		if lipgloss.Width(parentFile)+4 <= maxWidth {
			return ".../" + parentFile
		}
	}

	// Try grandparent/parent/filename
	if len(parts) >= 3 {
		gp := parts[len(parts)-3] + "/" + parts[len(parts)-2] + "/" + filename
		if lipgloss.Width(gp)+4 <= maxWidth {
			return ".../" + gp
		}
	}

	// Fallback: ellipsis the filename itself
	maxFn := maxWidth - 4
	if maxFn < 4 {
		maxFn = 4
	}
	fn := truncateWidth(filename, maxFn)
	return ".../" + fn
}

func wrapLines(s string, w int) []string {
	if w <= 0 || s == "" {
		return []string{}
	}
	var result []string
	runes := []rune(s)
	for len(runes) > 0 {
		if len(runes) <= w {
			result = append(result, string(runes))
			break
		}
		result = append(result, string(runes[:w]))
		runes = runes[w:]
	}
	return result
}

func joinColumns(columns []string, widths []int, gap int) string {
	if len(columns) == 0 {
		return ""
	}
	if len(columns) == 1 {
		return columns[0]
	}

	colLines := make([][]string, len(columns))
	maxLines := 0
	for i, col := range columns {
		lines := strings.Split(col, "\n")
		colLines[i] = lines
		if len(lines) > maxLines {
			maxLines = len(lines)
		}
	}

	// Pad all columns to same height
	for i := range colLines {
		for len(colLines[i]) < maxLines {
			colLines[i] = append(colLines[i], strings.Repeat(" ", widths[i]))
		}
	}

	gapStr := strings.Repeat(" ", gap)
	var result []string
	for lineIdx := 0; lineIdx < maxLines; lineIdx++ {
		var rowParts []string
		for colIdx := range columns {
			line := colLines[colIdx][lineIdx]
			lw := visibleWidth(line)
			if lw > widths[colIdx] {
				line = truncateWidth(line, widths[colIdx])
				if debugLayout {
					fmt.Fprintf(os.Stderr, "[layout] joinColumns: col %d overflow %d > %d, truncated\n", colIdx, lw, widths[colIdx])
				}
			} else if lw < widths[colIdx] {
				line += strings.Repeat(" ", widths[colIdx]-lw)
			}
			rowParts = append(rowParts, line)
		}
		result = append(result, strings.Join(rowParts, gapStr))
	}

	// In debug mode, verify final line widths
	if debugLayout {
		for _, line := range result {
			totalW := lipgloss.Width(line)
			expectedW := 0
			for _, w := range widths {
				expectedW += w
			}
			expectedW += gap * (len(widths) - 1)
			if totalW > expectedW {
				fmt.Fprintf(os.Stderr, "[layout] joinColumns row overflow %d > %d\n", totalW, expectedW)
			}
		}
	}

	return strings.Join(result, "\n")
}

func joinRows(rows ...string) string {
	var nonEmpty []string
	for _, r := range rows {
		if r != "" {
			nonEmpty = append(nonEmpty, r)
		}
	}
	return strings.Join(nonEmpty, "\n")
}

// joinRowsWithGap joins non-empty content blocks with a fixed number of
// blank lines between them. gap=0 produces no blank lines (direct \n join).
func joinRowsWithGap(gap int, rows ...string) string {
	var parts []string
	for _, r := range rows {
		trimmed := strings.TrimRight(r, "\n")
		if trimmed != "" {
			parts = append(parts, trimmed)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	if gap <= 0 {
		return strings.Join(parts, "\n")
	}
	sep := "\n" + strings.Repeat("\n", gap)
	return strings.Join(parts, sep)
}

func stripANSI(s string) string {
	var b strings.Builder
	i := 0
	runes := []rune(s)
	for i < len(runes) {
		if runes[i] == '\x1b' && i+1 < len(runes) && runes[i+1] == '[' {
			i += 2
			for i < len(runes) && !(runes[i] >= 'A' && runes[i] <= 'Z') && !(runes[i] >= 'a' && runes[i] <= 'z') {
				i++
			}
			if i < len(runes) {
				i++
			}
			continue
		}
		b.WriteRune(runes[i])
		i++
	}
	return b.String()
}

func visibleWidth(s string) int {
	return lipgloss.Width(s)
}


func renderBar(score uint8, width int, color string) string {
	if width < 2 {
		return ""
	}
	filled := int(score) * (width - 2) / 100
	if filled > width-2 {
		filled = width - 2
	}
	bar := "["
	for i := 0; i < width-2; i++ {
		if i < filled {
			bar += "█"
		} else {
			bar += "░"
		}
	}
	bar += "]"
	return lipgloss.NewStyle().Foreground(lipgloss.Color(color)).Render(bar)
}

func clamp(v, min, max int) int {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

func areaBarWidth(cardWidth int, mode LayoutMode) int {
	switch mode {
	case LayoutUltraWide:
		return clamp(cardWidth/4, 10, 18)
	case LayoutWide:
		return clamp(cardWidth/4, 8, 14)
	case LayoutMedium:
		return clamp(cardWidth/5, 6, 10)
	default:
		return 0
	}
}

func renderAreaHealthBars(r *domain.ScanResult, width int, mode LayoutMode, theme Theme) []string {
	var lines []string
	nameW := 24
	barW := areaBarWidth(width, mode)

	for _, axis := range domain.AllAxes() {
		score := r.ScoreReport.AxisScores[axis]
		scoreColor := theme.Success
		gradeStr := "Good"
		if score < 80 {
			scoreColor = theme.Medium
			gradeStr = "Risk"
		}
		if score < 50 {
			scoreColor = theme.Critical
			gradeStr = "Critical"
		}

		label := axis.Label()
		if lipgloss.Width(label) > nameW {
			label = truncateWidth(label, nameW)
		}

		bar := renderBar(score, barW, scoreColor)
		scoreTag := lipgloss.NewStyle().
			Foreground(lipgloss.Color(scoreColor)).
			Width(4).
			Align(lipgloss.Right).
			Render(fmt.Sprintf("%d", score))
		gradeTag := lipgloss.NewStyle().
			Foreground(lipgloss.Color(scoreColor)).
			Render(gradeStr)

		lines = append(lines, fmt.Sprintf("  %-*s %s %s %s", nameW, label, bar, scoreTag, gradeTag))
	}
	return lines
}

// ─── Layout contract types ─────────────────────────────────────────────────

// OverflowPolicy defines how content that exceeds its slot is handled.
type OverflowPolicy int

const (
	OverflowClip OverflowPolicy = iota
	OverflowEllipsis
	OverflowScroll
)

// DashboardState distinguishes clean vs risk dashboard skeletons.
type DashboardState int

const (
	DashboardClean DashboardState = iota
	DashboardRisk
)

// FindingsLayout defines fixed slot positions for the Findings screen.
type FindingsLayout struct {
	FilterBar Rect
	List      Rect
	Detail    Rect
	MidLeft   Rect
	MidRight  Rect
	Guidance  Rect
}

// DashboardLayout defines fixed slot positions for the Dashboard screen.
type DashboardLayout struct {
	Hero     Rect
	Row1     []Rect
	Row2     []Rect
	Row3     []Rect
	Brand    Rect
	Timeline Rect
}

// ReportLayout defines fixed slot positions for the Report screen.
type ReportLayout struct {
	Row1     []Rect
	Row2     []Rect
	Row3     []Rect
	Guidance Rect
}

// FindingsSlots computes fixed slot positions for the Findings screen.
// hasBottom indicates whether mid-row cards (filter/context) and guidance are shown.
func FindingsSlots(w, h int, mode LayoutMode, hasBottom bool) FindingsLayout {
	filterH := 1
	midH := 6
	guidH := 3
	gapH := 1

	if h < 20 || !hasBottom {
		return FindingsLayout{
			FilterBar: Rect{X: 0, Y: 0, W: w, H: filterH},
			List:      Rect{X: 0, Y: filterH, W: w, H: max(0, h-filterH)},
			Detail:    Rect{},
		}
	}

	topH := h - filterH - midH - guidH - gapH*3
	if topH < 6 {
		topH = 6
	}

	cols := splitColumns(w, 2, 1)

	y := filterH
	listRect := Rect{X: 0, Y: y, W: cols[0], H: topH}
	detailRect := Rect{X: cols[0] + 1, Y: y, W: cols[1], H: topH}

	y += topH + gapH
	midLeft := Rect{X: 0, Y: y, W: cols[0], H: midH}
	midRight := Rect{X: cols[0] + 1, Y: y, W: cols[1], H: midH}

	y += midH + gapH
	guidRect := Rect{X: 0, Y: y, W: w, H: guidH}

	return FindingsLayout{
		FilterBar: Rect{X: 0, Y: 0, W: w, H: filterH},
		List:      listRect,
		Detail:    detailRect,
		MidLeft:   midLeft,
		MidRight:  midRight,
		Guidance:  guidRect,
	}
}

// DashboardSlots computes fixed slot positions for the Dashboard screen.
// Slots are computed from viewport and state only — NOT from content.
func DashboardSlots(w, h int, state DashboardState, mode LayoutMode) DashboardLayout {
	rowGap := 0

	var heroH, mainH, secH, tertH, timelineH int
	var row1, row2, row3 []Rect

	brandH := 0
	if state == DashboardClean {
		switch mode {
		case LayoutUltraWide:
			brandH = 8
		case LayoutWide:
			brandH = 6
		}
	}

	switch mode {
	case LayoutUltraWide:
		heroH = 7
		mainH = 7
		secH = 6
		tertH = 6
		timelineH = 4

		used := heroH + mainH + secH
		if brandH > 0 {
			used += brandH
		} else {
			used += tertH
		}
		used += timelineH
		extra := max(0, h-used)
		if extra > 0 {
			heroAdd := min(extra, 2)
			heroH += heroAdd
			remaining := extra - heroAdd
			if remaining > 0 {
				if brandH > 0 {
					base := mainH + secH + timelineH
					timelineH += remaining * timelineH / base
					mainH += remaining * mainH / base
					secH += remaining - (remaining*timelineH/base + remaining*mainH/base)
				} else {
					base := mainH + secH + tertH + timelineH
					timelineH += remaining * timelineH / base
					mainH += remaining * mainH / base
					secH += remaining * secH / base
					tertH += remaining - (remaining*timelineH/base + remaining*mainH/base + remaining*secH/base)
				}
			}
		}

		y := 0
		heroRect := Rect{X: 0, Y: y, W: w, H: heroH}

		y += heroH + rowGap
		col4 := splitColumns(w, 4, 0)
		row1 = rectsFromWidths(col4, 0, y, mainH)

		y += mainH + rowGap
		col2 := splitColumns(w, 2, 0)
		row2 = rectsFromWidths(col2, 0, y, secH)

		y += secH + rowGap

		var brandRect Rect
		if brandH > 0 {
			brandRect = Rect{X: 0, Y: y, W: w, H: brandH}
			y += brandH + rowGap
		} else {
			row3 = rectsFromWidths(col2, 0, y, tertH)
			y += tertH + rowGap
		}

		timelineRect := Rect{X: 0, Y: y, W: w, H: timelineH}

		return DashboardLayout{
			Hero:     heroRect,
			Row1:     row1,
			Row2:     row2,
			Row3:     row3,
			Brand:    brandRect,
			Timeline: timelineRect,
		}

	case LayoutWide:
		heroH = 6
		mainH = 7
		secH = 5
		timelineH = 3

		used := heroH + mainH + secH
		if brandH > 0 {
			used += brandH
		}
		used += timelineH
		extra := max(0, h-used)
		if extra > 0 {
			heroAdd := min(extra, 2)
			heroH += heroAdd
			remaining := extra - heroAdd
			if remaining > 0 {
				base := mainH + secH + timelineH
				timelineH += remaining * timelineH / base
				mainH += remaining * mainH / base
				secH += remaining - (remaining*timelineH/base + remaining*mainH/base)
			}
		}

		y := 0
		heroRect := Rect{X: 0, Y: y, W: w, H: heroH}

		y += heroH + rowGap
		col3 := splitColumns(w, 3, 0)
		row1 = rectsFromWidths(col3, 0, y, mainH)

		y += mainH + rowGap
		col2 := splitColumns(w, 2, 0)
		row2 = rectsFromWidths(col2, 0, y, secH)

		y += secH + rowGap

		var brandRect Rect
		if brandH > 0 {
			brandRect = Rect{X: 0, Y: y, W: w, H: brandH}
			y += brandH + rowGap
		}

		timelineRect := Rect{X: 0, Y: y, W: w, H: timelineH}

		return DashboardLayout{
			Hero:     heroRect,
			Row1:     row1,
			Row2:     row2,
			Brand:    brandRect,
			Timeline: timelineRect,
		}

	case LayoutMedium:
		heroH = 6
		mainH = 7
		timelineH = 3

		used := heroH + mainH + timelineH
		extra := max(0, h-used)
		if extra > 0 {
			heroAdd := min(extra, 2)
			heroH += heroAdd
			remaining := extra - heroAdd
			if remaining > 0 {
				base := mainH + timelineH
				timelineH += remaining * timelineH / base
				mainH += remaining - remaining*timelineH/base
			}
		}

		y := 0
		heroRect := Rect{X: 0, Y: y, W: w, H: heroH}
		y += heroH + rowGap

		row1 = []Rect{{X: 0, Y: y, W: w, H: mainH}}
		y += mainH + rowGap
		timelineRect := Rect{X: 0, Y: y, W: w, H: timelineH}

		return DashboardLayout{
			Hero:     heroRect,
			Row1:     row1,
			Timeline: timelineRect,
		}

	default:
		return DashboardLayout{}
	}
}

func renderInfoStrip(label, text string, theme Theme, outerW, outerH int) string {
	contentW := max(1, outerW-8)
	line := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(theme.Text)).Render(label) + "  " + text
	return renderCardBounded("", "  "+truncateWidth(line, contentW), theme, Rect{W: outerW, H: outerH})
}

func rectsFromWidths(widths []int, x, y, h int) []Rect {
	rects := make([]Rect, len(widths))
	cx := x
	for i, w := range widths {
		rects[i] = Rect{X: cx, Y: y, W: w, H: h}
		cx += w + 1 // +1 for col gap
	}
	return rects
}

// ReportSlots computes fixed slot positions for the Report screen.
// Row heights are derived from the height budget with row gaps subtracted,
// so the rendered output never exceeds the content area height.
func ReportSlots(w, h int, mode LayoutMode) ReportLayout {
	sp := spacingFor(mode)
	rootW := max(1, w-sp.OuterX*2)
	cols := splitColumns(rootW, 2, sp.ColGap)
	guidH := 3

	gapH := max(0, sp.RowGap)
	usableH := h - guidH - gapH*3
	if usableH < 9 {
		usableH = max(0, h-guidH)
		gapH = 0
	}

	row1H := usableH / 3
	row2H := usableH / 3
	row3H := usableH - row1H - row2H

	y := 0
	row1 := []Rect{
		{X: 0, Y: y, W: cols[0], H: row1H},
		{X: cols[0] + sp.ColGap, Y: y, W: cols[1], H: row1H},
	}
	y += row1H + gapH

	row2 := []Rect{
		{X: 0, Y: y, W: cols[0], H: row2H},
		{X: cols[0] + sp.ColGap, Y: y, W: cols[1], H: row2H},
	}
	y += row2H + gapH

	row3 := []Rect{
		{X: 0, Y: y, W: cols[0], H: row3H},
		{X: cols[0] + sp.ColGap, Y: y, W: cols[1], H: row3H},
	}
	y += row3H + gapH

	return ReportLayout{
		Row1:     row1,
		Row2:     row2,
		Row3:     row3,
		Guidance: Rect{X: 0, Y: y, W: rootW, H: guidH},
	}
}

// RenderPanel renders content into a fixed-size rect, handling overflow.
// The output is always exactly rect.H lines tall.
func RenderPanel(rect Rect, title, content string, theme Theme, overflow OverflowPolicy) string {
	if rect.H <= 0 || rect.W <= 0 {
		return ""
	}
	innerH := rect.InnerH()
	if innerH <= 0 {
		return ""
	}

	// Split content into lines
	lines := strings.Split(content, "\n")

	// Handle overflow
	if len(lines) > innerH {
		switch overflow {
		case OverflowClip:
			lines = lines[:innerH]
		case OverflowEllipsis:
			if innerH > 0 {
				lines = lines[:innerH]
				last := len(lines) - 1
				if last >= 0 {
					lines[last] = truncateWidth(lines[last], rect.InnerW()-4)
				}
			}
		case OverflowScroll:
			// Keep all lines; renderCardBounded will handle height
		}
	}

	content = strings.Join(lines, "\n")
	card := renderCardBounded(title, content, theme, rect)
	return card
}

// KV represents a key-value row for renderKV.
type KV struct {
	Key   string
	Value string
}

// renderKV renders a string of key-value rows with the given label width.
// Each row is formatted as "  key: value" with labels right-padded to labelWidth.
func renderKV(pairs []KV, labelWidth int) string {
	var rows []string
	for _, p := range pairs {
		rows = append(rows, fmt.Sprintf("  %-*s %s", labelWidth, p.Key+":", p.Value))
	}
	return strings.Join(rows, "\n")
}
