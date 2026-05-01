package target

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Endpoint represents an external LLM target.
type Endpoint struct {
	URL      string
	Host     string
	Port     int
	Kind     string // "ollama" | "openai" | "openwebui"
	Severity string // from VisorSD
	Model    string // model to use (ollama only)
}

// Probe sends a single prompt to the endpoint and returns the model's response.
func (e *Endpoint) Probe(prompt string) (string, error) {
	switch e.kind() {
	case "ollama":
		return e.probeOllama(prompt)
	default:
		return e.probeOpenAI(prompt)
	}
}

func (e *Endpoint) kind() string {
	if e.Kind != "" {
		return strings.ToLower(e.Kind)
	}
	if strings.Contains(e.URL, "11434") {
		return "ollama"
	}
	return "openai"
}

func (e *Endpoint) model() string {
	if e.Model != "" {
		return e.Model
	}
	if e.kind() == "ollama" {
		return "llama3"
	}
	return "gpt-3.5-turbo"
}

func (e *Endpoint) probeOllama(prompt string) (string, error) {
	base := strings.TrimRight(e.URL, "/")
	url := base + "/api/chat"

	payload := map[string]interface{}{
		"model":  e.model(),
		"stream": false,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	}
	return e.post(url, payload, func(body []byte) (string, error) {
		var resp struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			Error string `json:"error"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return "", fmt.Errorf("decode ollama response: %w", err)
		}
		if resp.Error != "" {
			return "", fmt.Errorf("ollama error: %s", resp.Error)
		}
		return resp.Message.Content, nil
	})
}

func (e *Endpoint) probeOpenAI(prompt string) (string, error) {
	base := strings.TrimRight(e.URL, "/")
	// Accept both base URL and full endpoint URL
	url := base
	if !strings.HasSuffix(base, "/chat/completions") {
		url = base + "/v1/chat/completions"
	}

	payload := map[string]interface{}{
		"model": e.model(),
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	}
	return e.post(url, payload, func(body []byte) (string, error) {
		var resp struct {
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
			Error *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return "", fmt.Errorf("decode openai response: %w", err)
		}
		if resp.Error != nil {
			return "", fmt.Errorf("api error: %s", resp.Error.Message)
		}
		if len(resp.Choices) == 0 {
			return "", fmt.Errorf("no choices in response")
		}
		return resp.Choices[0].Message.Content, nil
	})
}

func (e *Endpoint) post(url string, payload interface{}, parse func([]byte) (string, error)) (string, error) {
	body, _ := json.Marshal(payload)
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d from %s: %s", resp.StatusCode, url, string(respBody))
	}
	return parse(respBody)
}

// ListOllamaModels queries /api/tags to get available models on an Ollama instance.
func ListOllamaModels(baseURL string) ([]string, error) {
	url := strings.TrimRight(baseURL, "/") + "/api/tags"
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var result struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(result.Models))
	for _, m := range result.Models {
		out = append(out, m.Name)
	}
	return out, nil
}
