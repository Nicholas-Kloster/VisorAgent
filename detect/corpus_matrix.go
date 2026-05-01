package detect

import (
	"fmt"
	"strings"

	"github.com/Nicholas-Kloster/VisorAgent/vectors"
)

func PrintCorpusMatrix(results []*vectors.CorpusCaseResult) {
	unsafe, safe, errCount := 0, 0, 0
	for _, r := range results {
		switch r.Status {
		case "UNSAFE":
			unsafe++
		case "SAFE":
			safe++
		default:
			errCount++
		}
	}

	fmt.Println()
	fmt.Println("  ══════════════════════════════════════════════════════════════════════════")
	fmt.Println("  VisorAgent Corpus Run — Results")
	fmt.Println("  ══════════════════════════════════════════════════════════════════════════")
	fmt.Printf("  %-12s  %-10s  %-8s  %-30s  %s\n", "ID", "Vector", "Severity", "Category", "Status")
	fmt.Println("  ──────────────────────────────────────────────────────────────────────────")

	for _, r := range results {
		status := r.Status
		if status == "UNSAFE" {
			status = "UNSAFE ←"
		}
		fmt.Printf("  %-12s  %-10s  %-8s  %-30s  %s\n",
			r.Case.ID,
			string(r.Case.Delivery()),
			r.Case.Severity,
			truncate(r.Case.Category, 30),
			status,
		)
		for _, s := range r.Signals {
			if s.Hit {
				fmt.Printf("              ↳ %s\n", s.Label)
			}
		}
	}

	fmt.Println("  ──────────────────────────────────────────────────────────────────────────")
	fmt.Printf("  Total: %d cases — UNSAFE: %d  SAFE: %d  ERROR: %d\n",
		len(results), unsafe, safe, errCount)

	if unsafe == 0 {
		fmt.Println("  [RESULT]  Agent resisted all corpus injections.")
	} else {
		pct := float64(unsafe) / float64(len(results)) * 100
		fmt.Printf("  [RESULT]  %.0f%% injection success rate (%d/%d cases broke through).\n",
			pct, unsafe, len(results))
	}
	fmt.Println("  ══════════════════════════════════════════════════════════════════════════")

	// Category breakdown
	if unsafe > 0 {
		fmt.Println()
		fmt.Println("  Breakdowns by category (UNSAFE only):")
		cats := map[string]int{}
		for _, r := range results {
			if r.Status == "UNSAFE" {
				cats[r.Case.Category]++
			}
		}
		for cat, n := range cats {
			fmt.Printf("    %-35s  %d\n", cat, n)
		}
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + strings.Repeat(".", 1)
}
