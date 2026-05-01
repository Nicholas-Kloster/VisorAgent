package corpus

import (
	"encoding/json"
	"fmt"
	"os"
)

type Expect struct {
	ExpectRefusal       bool     `json:"ExpectRefusal"`
	ForbiddenSubstrings []string `json:"ForbiddenSubstrings"`
	NoIgnorePrevious    bool     `json:"NoIgnorePrevious"`
	NoInternalURLs      bool     `json:"NoInternalURLs"`
	NoLargeVerbatim     bool     `json:"NoLargeVerbatim"`
}

type AttackCase struct {
	ID           string            `json:"id"`
	Category     string            `json:"category"`
	Profile      string            `json:"profile"`
	Severity     string            `json:"severity"`
	Description  string            `json:"description"`
	Prompt       string            `json:"prompt"`
	AttackVector string            `json:"attack_vector"`
	Domain       string            `json:"domain"`
	LengthHint   string            `json:"length_hint"`
	Expect       Expect            `json:"expect"`
	Tags         map[string]string `json:"tags"`
}

type DeliveryVector string

const (
	DeliveryWebFetch  DeliveryVector = "V1"
	DeliveryDocPoison DeliveryVector = "V2"
	DeliveryCodeExec  DeliveryVector = "V3"
)

func (ac AttackCase) Delivery() DeliveryVector {
	// Route by explicit attack_vector first
	switch ac.AttackVector {
	case "doc_poison", "kb_instruction_poisoning":
		return DeliveryDocPoison
	case "code_exec", "sandbox_escape":
		return DeliveryCodeExec
	}
	// Fall back to category
	switch ac.Category {
	case "doc_poison", "kb_exfiltration", "kb_instruction_poisoning":
		return DeliveryDocPoison
	case "code_exec":
		return DeliveryCodeExec
	}
	return DeliveryWebFetch
}

func Load(path string) ([]AttackCase, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read corpus: %w", err)
	}
	var cases []AttackCase
	if err := json.Unmarshal(data, &cases); err != nil {
		return nil, fmt.Errorf("parse corpus: %w", err)
	}
	return cases, nil
}
