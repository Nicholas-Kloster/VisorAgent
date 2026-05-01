package detect

import (
	"fmt"
	"strings"

	"github.com/Nicholas-Kloster/VisorAgent/vectors"
)

func PrintExternalMatrix(results []*vectors.ExternalCaseResult) {
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
	fmt.Println("  ══════════════════════════════════════════════════════════════════════════════")
	fmt.Println("  VisorAgent External Target Run — Results")
	fmt.Println("  ══════════════════════════════════════════════════════════════════════════════")
	fmt.Printf("  %-25s  %-12s  %-8s  %-25s  %s\n", "Target", "ID", "Severity", "Category", "Status")
	fmt.Println("  ────────────────────────────────────────────────────────────────────────────────")

	for _, r := range results {
		status := r.Status
		if status == "UNSAFE" {
			status = "UNSAFE ←"
		}
		host := r.Endpoint.Host
		if len(host) > 25 {
			host = host[:24] + "."
		}
		fmt.Printf("  %-25s  %-12s  %-8s  %-25s  %s\n",
			host,
			truncate(r.Case.ID, 12),
			r.Case.Severity,
			truncate(r.Case.Category, 25),
			status,
		)
		for _, s := range r.Signals {
			if s.Hit {
				fmt.Printf("    ↳ %s\n", s.Label)
			}
		}
		if r.Status == "ERROR" {
			fmt.Printf("    ↳ error: %s\n", r.Reason)
		}
	}

	fmt.Println("  ────────────────────────────────────────────────────────────────────────────────")
	fmt.Printf("  Total: %d probes — UNSAFE: %d  SAFE: %d  ERROR: %d\n",
		len(results), unsafe, safe, errCount)

	if unsafe == 0 {
		fmt.Println("  [RESULT]  No injection vulnerabilities detected on external targets.")
	} else {
		pct := float64(unsafe) / float64(len(results)) * 100
		fmt.Printf("  [RESULT]  %.0f%% injection success rate — %d probe(s) broke through.\n",
			pct, unsafe)
	}
	fmt.Println("  ══════════════════════════════════════════════════════════════════════════════")

	if unsafe > 0 {
		fmt.Println()
		fmt.Println("  Vulnerable targets:")
		seen := map[string]bool{}
		for _, r := range results {
			if r.Status == "UNSAFE" && !seen[r.Endpoint.Host] {
				seen[r.Endpoint.Host] = true
				fmt.Printf("    %s  (%s)\n", r.Endpoint.Host, strings.ToUpper(r.Endpoint.Kind))
			}
		}
	}
}
