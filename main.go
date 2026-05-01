package main

import (
	"fmt"
	"os"

	"github.com/Nicholas-Kloster/VisorAgent/cmd"
)

const banner = `
  VisorAgent · Agentic LLM Injection Benchmark
  Nuclide Research · github.com/Nicholas-Kloster/VisorAgent
`

func main() {
	fmt.Print(banner)

	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "list":
		cmd.CmdList()

	case "run":
		email := ""
		vectorID := ""
		corpusPath := ""
		targetURL := ""
		visorsdPath := ""
		model := ""

		args := os.Args[2:]
		for i := 0; i < len(args); i++ {
			if i+1 >= len(args) {
				break
			}
			switch args[i] {
			case "--email":
				email = args[i+1]
				i++
			case "--vector":
				vectorID = args[i+1]
				i++
			case "--corpus":
				corpusPath = args[i+1]
				i++
			case "--target":
				targetURL = args[i+1]
				i++
			case "--visorsd":
				visorsdPath = args[i+1]
				i++
			case "--model":
				model = args[i+1]
				i++
			}
		}

		if err := cmd.CmdRun(email, vectorID, corpusPath, targetURL, visorsdPath, model); err != nil {
			fmt.Fprintf(os.Stderr, "  error: %v\n", err)
			os.Exit(1)
		}

	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Println(`  COMMANDS:
    list                           show all injection vectors

    run                            run all vectors (internal Claude agent)
    run --vector V1                run single vector
    run --email addr               attacker email for V2
    run --corpus corpus.json       run VisorCorpus cases (internal agent)

    run --target http://host:11434 --corpus corpus.json
                                   test external Ollama/OpenAI-compat endpoint
    run --visorsd findings.json --corpus corpus.json
                                   test all targets from VisorSD output
    run --model llama3:8b          override model for external target

  ENVIRONMENT:
    ANTHROPIC_API_KEY              required for internal agent mode`)
}
