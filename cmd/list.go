package cmd

import (
	"fmt"

	"github.com/Nicholas-Kloster/VisorAgent/vectors"
)

func CmdList() {
	fmt.Println()
	fmt.Println("  VisorAgent — vector catalog")
	fmt.Println()
	fmt.Printf("  %-4s  %-6s  %-40s  %s\n", "ID", "Tier", "Name", "Description")
	fmt.Println("  ────────────────────────────────────────────────────────────────────────────")
	for _, v := range vectors.Catalog {
		fmt.Printf("  %-4s  %-6s  %-40s  %s\n", v.ID, v.Tier, v.Name, v.Description)
	}
	fmt.Println()
}
