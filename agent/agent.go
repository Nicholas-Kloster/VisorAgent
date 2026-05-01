package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

const apiURL = "https://api.anthropic.com/v1/messages"
const Model = "claude-sonnet-4-6"

// ToolHandler is called for each tool invocation during the agent loop.
// Returns the tool result string to feed back to the model.
type ToolHandler func(name string, input map[string]interface{}) string

type RunResult struct {
	ToolCalls []ToolCall
	Final     string
}

type ToolCall struct {
	Name  string
	Input map[string]interface{}
}

var toolDefs = []map[string]interface{}{
	{
		"name":        "web_fetch",
		"description": "Fetch the content of a URL and return it as text.",
		"input_schema": map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{"url": map[string]interface{}{"type": "string"}},
			"required":   []string{"url"},
		},
	},
	{
		"name":        "doc_retrieve",
		"description": "Search the internal document store and return matching document chunks.",
		"input_schema": map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{"query": map[string]interface{}{"type": "string"}},
			"required":   []string{"query"},
		},
	},
	{
		"name":        "code_exec",
		"description": "Execute Python code in a sandboxed container and return stdout.",
		"input_schema": map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{"code": map[string]interface{}{"type": "string"}},
			"required":   []string{"code"},
		},
	},
	{
		"name":        "email_send",
		"description": "Send an email via the internal mail service.",
		"input_schema": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"to":      map[string]interface{}{"type": "string"},
				"subject": map[string]interface{}{"type": "string"},
				"body":    map[string]interface{}{"type": "string"},
			},
			"required": []string{"to", "subject", "body"},
		},
	},
}

type message struct {
	Role    string        `json:"role"`
	Content []interface{} `json:"content"`
}

type textBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type toolUseBlock struct {
	Type  string                 `json:"type"`
	ID    string                 `json:"id"`
	Name  string                 `json:"name"`
	Input map[string]interface{} `json:"input"`
}

type toolResultBlock struct {
	Type      string `json:"type"`
	ToolUseID string `json:"tool_use_id"`
	Content   string `json:"content"`
}

type apiRequest struct {
	Model     string                   `json:"model"`
	MaxTokens int                      `json:"max_tokens"`
	System    string                   `json:"system"`
	Tools     []map[string]interface{} `json:"tools"`
	Messages  []message                `json:"messages"`
}

type apiResponse struct {
	Content    []json.RawMessage `json:"content"`
	StopReason string            `json:"stop_reason"`
	Error      *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// Run executes a single agentic task with tool use.
// handler is called for every tool invocation; its return value is fed back as the tool result.
func Run(task string, handler ToolHandler) (*RunResult, error) {
	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("ANTHROPIC_API_KEY not set")
	}

	result := &RunResult{}
	messages := []message{
		{Role: "user", Content: []interface{}{textBlock{Type: "text", Text: task}}},
	}
	system := "You are a helpful AI assistant with access to tools. Use them to complete the user's task efficiently."

	for turn := 0; turn < 10; turn++ {
		req := apiRequest{
			Model:     Model,
			MaxTokens: 4096,
			System:    system,
			Tools:     toolDefs,
			Messages:  messages,
		}

		body, _ := json.Marshal(req)
		httpReq, _ := http.NewRequest("POST", apiURL, bytes.NewReader(body))
		httpReq.Header.Set("x-api-key", apiKey)
		httpReq.Header.Set("anthropic-version", "2023-06-01")
		httpReq.Header.Set("content-type", "application/json")

		resp, err := http.DefaultClient.Do(httpReq)
		if err != nil {
			return nil, fmt.Errorf("API call: %w", err)
		}
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("API %d: %s", resp.StatusCode, string(respBody))
		}

		var apiResp apiResponse
		if err := json.Unmarshal(respBody, &apiResp); err != nil {
			return nil, fmt.Errorf("decode response: %w", err)
		}
		if apiResp.Error != nil {
			return nil, fmt.Errorf("API error %s: %s", apiResp.Error.Type, apiResp.Error.Message)
		}

		var assistantContent []interface{}
		var toolUses []toolUseBlock
		var finalText string

		for _, raw := range apiResp.Content {
			var base struct {
				Type string `json:"type"`
			}
			json.Unmarshal(raw, &base)
			switch base.Type {
			case "text":
				var tb textBlock
				json.Unmarshal(raw, &tb)
				finalText = tb.Text
				assistantContent = append(assistantContent, tb)
			case "tool_use":
				var tu toolUseBlock
				json.Unmarshal(raw, &tu)
				toolUses = append(toolUses, tu)
				assistantContent = append(assistantContent, tu)
				result.ToolCalls = append(result.ToolCalls, ToolCall{Name: tu.Name, Input: tu.Input})
			}
		}

		messages = append(messages, message{Role: "assistant", Content: assistantContent})

		if apiResp.StopReason == "end_turn" || len(toolUses) == 0 {
			result.Final = finalText
			break
		}

		var toolResults []interface{}
		for _, tu := range toolUses {
			output := handler(tu.Name, tu.Input)
			toolResults = append(toolResults, toolResultBlock{
				Type:      "tool_result",
				ToolUseID: tu.ID,
				Content:   output,
			})
		}
		messages = append(messages, message{Role: "user", Content: toolResults})
	}

	return result, nil
}
