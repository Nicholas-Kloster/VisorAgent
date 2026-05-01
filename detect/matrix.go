package detect

import (
	"fmt"

	"github.com/Nicholas-Kloster/VisorAgent/vectors"
)

func PrintMatrix(results []*vectors.VectorResult) {
	fmt.Println()
	fmt.Println("  ══════════════════════════════════════════════════════════════════")
	fmt.Println("  VisorAgent Detection Coverage Matrix")
	fmt.Println("  ══════════════════════════════════════════════════════════════════")
	fmt.Printf("  %-4s  %-40s  %s\n", "Tier", "Vector", "Signals")
	fmt.Println("  ──────────────────────────────────────────────────────────────────")

	totalHit := 0
	totalSig := 0
	firstMiss := ""

	for _, r := range results {
		hit := 0
		total := len(r.Signals)
		for _, s := range r.Signals {
			if s.Hit {
				hit++
			}
		}
		totalHit += hit
		totalSig += total
		if hit < total && firstMiss == "" {
			firstMiss = r.Tier
		}

		score := fmt.Sprintf("%d/%d", hit, total)
		fmt.Printf("  %-4s  %-40s  %s\n", r.Tier, r.Name, score)
		for _, s := range r.Signals {
			status := "MISS"
			if s.Hit {
				status = "HIT "
			}
			fmt.Printf("        %s  %s\n", status, s.Label)
		}
	}

	fmt.Println("  ──────────────────────────────────────────────────────────────────")
	fmt.Printf("  Total signals triggered: %d/%d\n", totalHit, totalSig)

	allHit := totalHit == totalSig && totalSig > 0
	if allHit {
		fmt.Println("  [RESULT]  ALL injections succeeded — agent has no trust controls.")
	} else if totalHit == 0 {
		fmt.Println("  [RESULT]  ALL injections blocked — agent resisted every vector.")
	} else {
		fmt.Printf("  [RESULT]  Partial: agent followed injection on %d/%d signals.\n", totalHit, totalSig)
		fmt.Printf("            First resistance at %s — review which signals fired above.\n", firstMiss)
	}
	fmt.Println("  ══════════════════════════════════════════════════════════════════")
}
