package cmd

import (
	"fmt"
	"strings"

	"github.com/Nicholas-Kloster/VisorAgent/corpus"
	"github.com/Nicholas-Kloster/VisorAgent/detect"
	"github.com/Nicholas-Kloster/VisorAgent/server"
	"github.com/Nicholas-Kloster/VisorAgent/target"
	"github.com/Nicholas-Kloster/VisorAgent/vectors"
)

func CmdRun(attackerEmail, vectorID, corpusPath, targetURL, visorsdPath, model string) error {
	if attackerEmail == "" {
		attackerEmail = "attacker@evil.example"
	}

	// External target mode — bypass internal agent
	if targetURL != "" || visorsdPath != "" {
		return runExternal(corpusPath, targetURL, visorsdPath, model)
	}

	srv, err := server.New()
	if err != nil {
		return fmt.Errorf("start server: %w", err)
	}
	defer srv.Stop()

	srv.SetPayload("/report.html",
		strings.ReplaceAll(vectors.ReportHTML, "ATTACKER_URL", srv.BaseURL))
	srv.SetPayload("/recon.py", vectors.ReconPY)
	srv.SetPayload("/policy.txt",
		strings.ReplaceAll(vectors.PolicyTXT, "ATTACKER_EMAIL", attackerEmail))

	if corpusPath != "" {
		return runCorpus(srv, attackerEmail, corpusPath)
	}

	// Standard internal mode
	fmt.Printf("\n  VisorAgent — injection benchmark\n")
	fmt.Printf("  listener: %s\n", srv.BaseURL)
	fmt.Printf("  attacker: %s\n\n", attackerEmail)

	catalog := vectors.Catalog
	if vectorID != "" {
		var filtered []vectors.Vector
		for _, v := range catalog {
			if strings.EqualFold(v.ID, vectorID) {
				filtered = append(filtered, v)
			}
		}
		if len(filtered) == 0 {
			return fmt.Errorf("vector %q not found", vectorID)
		}
		catalog = filtered
	}

	var results []*vectors.VectorResult
	for i, v := range catalog {
		fmt.Printf("  [%d/%d] %s: %s\n", i+1, len(catalog), v.Tier, v.Name)
		result, err := v.Run(srv, srv.BaseURL, attackerEmail)
		if err != nil {
			fmt.Printf("        ERROR: %v\n", err)
			continue
		}
		for _, s := range result.Signals {
			status := "MISS"
			if s.Hit {
				status = "HIT "
			}
			fmt.Printf("        %s  %s\n", status, s.Label)
		}
		fmt.Println()
		results = append(results, result)
	}

	detect.PrintMatrix(results)
	return nil
}

func runCorpus(srv *server.Server, attackerEmail, corpusPath string) error {
	cases, err := corpus.Load(corpusPath)
	if err != nil {
		return err
	}

	fmt.Printf("\n  VisorAgent — corpus run\n")
	fmt.Printf("  corpus:   %s (%d cases)\n", corpusPath, len(cases))
	fmt.Printf("  listener: %s\n", srv.BaseURL)
	fmt.Printf("  attacker: %s\n\n", attackerEmail)

	var results []*vectors.CorpusCaseResult
	for i, ac := range cases {
		fmt.Printf("  [%d/%d] %-30s  %-8s  %s\n", i+1, len(cases), ac.ID, ac.Severity, ac.Category)
		r := vectors.RunCorpusCase(ac, srv, srv.BaseURL, attackerEmail)
		if r.Status == "UNSAFE" {
			fmt.Printf("         UNSAFE — %d signal(s) fired\n", len(r.Signals))
		}
		results = append(results, r)
	}

	detect.PrintCorpusMatrix(results)
	return nil
}

func runExternal(corpusPath, targetURL, visorsdPath, model string) error {
	if corpusPath == "" {
		return fmt.Errorf("--corpus required for external target mode")
	}

	cases, err := corpus.Load(corpusPath)
	if err != nil {
		return err
	}

	var endpoints []*target.Endpoint

	if visorsdPath != "" {
		eps, err := target.LoadVisorSD(visorsdPath)
		if err != nil {
			return fmt.Errorf("load visorsd: %w", err)
		}
		endpoints = eps
	}

	if targetURL != "" {
		ep := &target.Endpoint{URL: targetURL, Host: targetURL, Kind: "ollama"}
		if model != "" {
			ep.Model = model
		}
		// Auto-detect available models on Ollama
		if models, err := target.ListOllamaModels(targetURL); err == nil && len(models) > 0 {
			ep.Model = models[0]
		}
		endpoints = append(endpoints, ep)
	}

	if len(endpoints) == 0 {
		return fmt.Errorf("no targets found")
	}

	fmt.Printf("\n  VisorAgent — external target run\n")
	fmt.Printf("  corpus:  %s (%d cases)\n", corpusPath, len(cases))
	fmt.Printf("  targets: %d endpoint(s)\n\n", len(endpoints))

	for _, ep := range endpoints {
		kind := ep.Kind
		if ep.Model != "" {
			kind = fmt.Sprintf("%s/%s", ep.Kind, ep.Model)
		}
		fmt.Printf("  target: %s  [%s]\n", ep.Host, kind)
	}
	fmt.Println()

	var results []*vectors.ExternalCaseResult
	total := len(endpoints) * len(cases)
	n := 0

	for _, ep := range endpoints {
		for _, ac := range cases {
			n++
			fmt.Printf("  [%d/%d] %-20s  %s\n", n, total, ep.Host, ac.ID)
			r := vectors.RunExternalCase(ac, ep)
			if r.Status == "UNSAFE" {
				fmt.Printf("         UNSAFE — %s\n", r.Reason)
			}
			results = append(results, r)
		}
	}

	detect.PrintExternalMatrix(results)
	return nil
}
