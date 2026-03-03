// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/term"
)

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// Progress writes status updates to stderr during long operations.
// It auto-disables in non-TTY contexts (piped output).
type Progress struct {
	w       io.Writer
	r       *lipgloss.Renderer
	enabled bool

	mu        sync.Mutex
	name      string
	current   int
	total     int
	frame     int
	started   bool
	stopped   bool
	stop      chan struct{}
	done      sync.Once
	completed []string
	prevLines int
}

// NewProgress creates a progress writer. Disabled when w is not a terminal.
func NewProgress(w io.Writer) *Progress {
	enabled := false
	if f, ok := w.(*os.File); ok {
		enabled = term.IsTerminal(f.Fd())
	}
	return &Progress{
		w:       w,
		r:       lipgloss.NewRenderer(w),
		enabled: enabled,
		stop:    make(chan struct{}),
	}
}

// Update sets the current progress state. The spinner animates independently.
func (p *Progress) Update(name string, current, total int) {
	if !p.enabled {
		return
	}

	p.mu.Lock()
	first := !p.started
	if p.started && p.name != "" && p.name != name {
		p.completed = append(p.completed, p.name)
	}
	p.name = name
	p.current = current
	p.total = total
	p.started = true
	p.mu.Unlock()

	if first {
		go p.animate()
	}
}

func (p *Progress) animate() {
	ticker := time.NewTicker(80 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-p.stop:
			return
		case <-ticker.C:
			p.mu.Lock()
			stopped := p.stopped
			if !stopped {
				p.render()
			}
			p.mu.Unlock()
		}
	}
}

// render draws the current state. Must be called with p.mu held.
func (p *Progress) render() {
	// Move cursor up to overwrite previous output
	if p.prevLines > 0 {
		fmt.Fprintf(p.w, "\033[%dA", p.prevLines)
	}

	lines := 0

	// Completed items
	check := p.r.NewStyle().Foreground(lipgloss.Color("10")).Render("✓")
	dimStyle := p.r.NewStyle().Faint(true)
	for _, name := range p.completed {
		fmt.Fprintf(p.w, "\033[K  %s %s\n", check, dimStyle.Render(name))
		lines++
	}

	// Current item with spinner
	spin := spinnerFrames[p.frame%len(spinnerFrames)]
	p.frame++

	spinner := p.r.NewStyle().Bold(true).Foreground(lipgloss.Color("6")).Render(spin)
	label := p.r.NewStyle().Bold(true).Render("Auditing ")
	server := p.r.NewStyle().Foreground(lipgloss.Color("6")).Render(p.name)
	fmt.Fprintf(p.w, "\033[K  %s %s%s\n", spinner, label, server)
	lines++

	// Progress bar
	barWidth := 30
	filled := 0
	if p.total > 0 {
		filled = barWidth * p.current / p.total
	}
	empty := barWidth - filled
	bar := p.r.NewStyle().Foreground(lipgloss.Color("6")).Render(strings.Repeat("█", filled)) +
		p.r.NewStyle().Foreground(lipgloss.Color("238")).Render(strings.Repeat("░", empty))
	counter := p.r.NewStyle().Faint(true).Render(fmt.Sprintf(" %d/%d", p.current, p.total))
	fmt.Fprintf(p.w, "\033[K    %s%s\n", bar, counter)
	lines++

	p.prevLines = lines
}

// Done stops the spinner and replaces the dynamic lines (spinner + bar)
// with the final completed checkmark, preserving all checkmarks on screen.
func (p *Progress) Done() {
	if !p.enabled {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.started {
		return
	}

	p.stopped = true
	p.done.Do(func() {
		close(p.stop)
	})

	if p.prevLines == 0 {
		return
	}

	// Move to the top of the rendered block and redraw completed items,
	// including the final server that was still in-progress.
	fmt.Fprintf(p.w, "\033[%dA", p.prevLines)

	check := p.r.NewStyle().Foreground(lipgloss.Color("10")).Render("✓")
	dimStyle := p.r.NewStyle().Faint(true)
	if p.name != "" {
		p.completed = append(p.completed, p.name)
	}
	for _, name := range p.completed {
		fmt.Fprintf(p.w, "\033[K  %s %s\n", check, dimStyle.Render(name))
	}

	// Clear leftover dynamic lines (spinner + bar) that are no longer needed.
	leftover := p.prevLines - len(p.completed)
	for i := 0; i < leftover; i++ {
		fmt.Fprintf(p.w, "\033[K\n")
	}
	// Move cursor back up past the cleared lines so subsequent output
	// starts right after the checkmarks.
	if leftover > 0 {
		fmt.Fprintf(p.w, "\033[%dA", leftover)
	}
}
