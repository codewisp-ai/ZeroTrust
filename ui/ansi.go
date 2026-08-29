package ui

import (
	"fmt"
	"strings"
)

// ANSI Color Constants replacing fatih/color and lipgloss
const (
	Reset     = "\033[0m"
	Bold      = "\033[1m"
	Dim       = "\033[2m"
	Red       = "\033[31m"
	Green     = "\033[32m"
	Yellow    = "\033[33m"
	Blue      = "\033[34m"
	Magenta   = "\033[35m"
	Cyan      = "\033[36m"
	White     = "\033[37m"
	BoldRed   = "\033[1;31m"
	BoldGreen = "\033[1;32m"
	BoldYel   = "\033[1;33m"
	BoldBlue  = "\033[1;34m"
	BoldCyan  = "\033[1;36m"
)

// Colorize wraps text with ANSI color code if enabled.
func Colorize(text, colorCode string, enabled bool) string {
	if !enabled {
		return text
	}
	return colorCode + text + Reset
}

// Badge returns a formatted status badge.
func Badge(text, color string, enabled bool) string {
	if !enabled {
		return "[" + text + "]"
	}
	return color + Bold + "[" + text + "]" + Reset
}

// FormatTable renders aligned ASCII tables.
func FormatTable(headers []string, rows [][]string) string {
	if len(rows) == 0 {
		return ""
	}

	colWidths := make([]int, len(headers))
	for i, h := range headers {
		colWidths[i] = len(stripANSI(h))
	}

	for _, row := range rows {
		for i, val := range row {
			if i < len(colWidths) {
				cleanVal := len(stripANSI(val))
				if cleanVal > colWidths[i] {
					colWidths[i] = cleanVal
				}
			}
		}
	}

	var sb strings.Builder

	// Header row
	for i, h := range headers {
		sb.WriteString(fmt.Sprintf("%-*s  ", colWidths[i], h))
	}
	sb.WriteString("\n")

	// Separator row
	for _, w := range colWidths {
		sb.WriteString(strings.Repeat("-", w) + "  ")
	}
	sb.WriteString("\n")

	// Data rows
	for _, row := range rows {
		for i, val := range row {
			if i < len(colWidths) {
				visibleLen := len(stripANSI(val))
				pad := colWidths[i] - visibleLen
				sb.WriteString(val + strings.Repeat(" ", pad) + "  ")
			}
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

func stripANSI(s string) string {
	var sb strings.Builder
	inEsc := false
	for _, r := range s {
		if r == '\033' {
			inEsc = true
			continue
		}
		if inEsc {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				inEsc = false
			}
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
