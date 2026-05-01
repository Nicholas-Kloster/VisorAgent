package target

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// VisorSDFinding matches VisorSD's JSON output schema.
type VisorSDFinding struct {
	Host      string `json:"host"`
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	Component string `json:"component"`
	Severity  string `json:"severity"`
	Query     string `json:"query"`
	Org       string `json:"org"`
}

func (f VisorSDFinding) addr() string {
	host := f.Host
	if host == "" {
		host = f.IP
	}
	if f.Port > 0 {
		return fmt.Sprintf("%s:%d", host, f.Port)
	}
	return host
}

func (f VisorSDFinding) toEndpoint() *Endpoint {
	kind := "openai"
	if f.Port == 11434 || strings.Contains(strings.ToLower(f.Component), "ollama") {
		kind = "ollama"
	}

	scheme := "http"
	if f.Port == 443 {
		scheme = "https"
	}

	return &Endpoint{
		URL:      fmt.Sprintf("%s://%s", scheme, f.addr()),
		Host:     f.addr(),
		Port:     f.Port,
		Kind:     kind,
		Severity: f.Severity,
	}
}

// LoadVisorSD reads a VisorSD JSON output file and returns Endpoints.
func LoadVisorSD(path string) ([]*Endpoint, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read visorsd file: %w", err)
	}
	var findings []VisorSDFinding
	if err := json.Unmarshal(data, &findings); err != nil {
		return nil, fmt.Errorf("parse visorsd json: %w", err)
	}

	seen := map[string]bool{}
	var endpoints []*Endpoint
	for _, f := range findings {
		key := f.addr()
		if seen[key] {
			continue
		}
		seen[key] = true
		endpoints = append(endpoints, f.toEndpoint())
	}
	return endpoints, nil
}
