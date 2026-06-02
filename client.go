package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/joho/godotenv"
	"resty.dev/v3"
)

// Client is the IMSLP API client (library).
type Client struct {
	*resty.Client

	LoginToken string
	UserID     int
	Username   string
}

// NewClient creates a new IMSLP client, loading .env and any existing token.
func NewClient() *Client {
	_ = godotenv.Load()

	c := &Client{
		Client: resty.New().
			SetBaseURL("https://app0.imslp.org/").
			SetHeader("Content-Type", "text/plain;charset=UTF-8").
			SetHeader("Origin", "https://imslp.org").
			SetHeader("Referer", "https://imslp.org/"),
		LoginToken: os.Getenv("IMSLP_LOGIN_TOKEN"),
	}
	return c
}

// EnsureAuth ensures we have a LoginToken. If none but IMSLP_USERNAME/IMSLP_PASSWORD
// are present in env, performs an automatic login (and persists the token).
// This makes using username/password in .env transparent for other commands.
func (c *Client) EnsureAuth() error {
	if c.LoginToken != "" {
		return nil
	}
	u := os.Getenv("IMSLP_USERNAME")
	p := os.Getenv("IMSLP_PASSWORD")
	if u == "" || p == "" {
		return fmt.Errorf("no IMSLP_LOGIN_TOKEN and no IMSLP_USERNAME/IMSLP_PASSWORD in .env")
	}
	if err := c.Login(u, p); err != nil {
		return fmt.Errorf("auto-login failed: %w", err)
	}
	// Persist token so future runs don't need password (and user can remove pass from .env)
	_ = SaveTokenToEnv(c.LoginToken)
	return nil
}

// Login performs the login flow using username/password and obtains a loginToken.
// It stores the token on the client and optionally persists it.
func (c *Client) Login(username, password string) error {
	if username == "" || password == "" {
		return fmt.Errorf("username and password are required")
	}

	payload := map[string]any{
		"command":    "user.login",
		"username":   username,
		"password":   password,
		"apiVersion": 3,
	}

	bodyBytes, _ := json.Marshal(payload)

	resp, err := c.R().
		SetBody(string(bodyBytes)).
		Post("/")
	if err != nil {
		return fmt.Errorf("login request failed: %w", err)
	}

	bodyStr := resp.String()
	// Parse response. Success returns user object with loginToken at top level.
	// Error returns {"message": "...", "code": ...} even on 200 or 4xx.
	var errResp struct {
		Message string `json:"message"`
		Code    int    `json:"code"`
	}
	_ = json.Unmarshal([]byte(bodyStr), &errResp)
	if errResp.Message != "" {
		return fmt.Errorf("login failed: %s", errResp.Message)
	}

	var okResp struct {
		LoginToken   string `json:"loginToken"`
		UserID       int    `json:"userId"`
		Username     string `json:"username"`
		SoftDeletedAt any    `json:"softDeletedAt"`
	}
	if err := json.Unmarshal([]byte(bodyStr), &okResp); err != nil {
		return fmt.Errorf("failed to parse login response: %w (body: %s)", err, bodyStr)
	}
	if okResp.LoginToken == "" {
		return fmt.Errorf("login did not return a loginToken (response: %s)", bodyStr)
	}

	c.LoginToken = okResp.LoginToken
	c.UserID = okResp.UserID
	c.Username = okResp.Username

	return nil
}

// call is a helper for sync.* and other authenticated commands.
func (c *Client) call(command string, extra map[string]any, out any) error {
	payload := map[string]any{
		"command":    command,
		"apiVersion": 3,
	}
	if c.LoginToken != "" {
		payload["loginToken"] = c.LoginToken
	}
	for k, v := range extra {
		payload[k] = v
	}

	bodyBytes, _ := json.Marshal(payload)
	req := c.R().SetBody(string(bodyBytes))
	if out != nil {
		req = req.SetResult(out)
	}

	resp, err := req.Post("/")
	if err != nil {
		return err
	}
	bodyStr := resp.String()
	if resp.IsError() {
		// Try to surface server message if present
		var e struct{ Message string `json:"message"` }
		_ = json.Unmarshal([]byte(bodyStr), &e)
		if e.Message != "" {
			return fmt.Errorf("api error: %s (status %s)", e.Message, resp.Status())
		}
		return fmt.Errorf("api error %s: %s", resp.Status(), bodyStr)
	}

	if bodyStr != "" && out != nil {
		// Force unmarshal (SetResult may depend on response content-type sniffing)
		_ = json.Unmarshal([]byte(bodyStr), out)
	}

	// Some responses may be error encoded in body even on 200 (e.g. old sync protocol).
	// Callers can inspect the returned map.
	return nil
}

// SyncGet performs a sync.get to fetch updates since given revisions.
// Pass revisionPosition, revisionRequested, revisionMajor from previous state (or 0).
func (c *Client) SyncGet(revisionPosition, revisionRequested, revisionMajor int) (map[string]any, error) {
	var out map[string]any
	err := c.call("sync.get", map[string]any{
		"revisionPosition":  revisionPosition,
		"revisionRequested": revisionRequested,
		"revisionMajor":     revisionMajor,
	}, &out)
	return out, err
}

// SyncPut sends items (scores, setlists, annotations, etc) to be created/updated/deleted.
func (c *Client) SyncPut(items []any) (map[string]any, error) {
	var out map[string]any
	err := c.call("sync.put", map[string]any{
		"items": items,
	}, &out)
	return out, err
}

// SaveTokenToEnv writes (or updates) the IMSLP_LOGIN_TOKEN in .env .
// Sensitive material (token) is persisted here as requested.
func SaveTokenToEnv(token string) error {
	if token == "" {
		return fmt.Errorf("cannot save empty token")
	}
	envPath := ".env"

	existing := ""
	if b, err := os.ReadFile(envPath); err == nil {
		existing = string(b)
	}

	lines := strings.Split(existing, "\n")
	updated := false
	for i, line := range lines {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "IMSLP_LOGIN_TOKEN=") || strings.HasPrefix(trim, "#IMSLP_LOGIN_TOKEN=") {
			lines[i] = "IMSLP_LOGIN_TOKEN=" + token
			updated = true
			break
		}
	}
	if !updated {
		// ensure trailing newline behavior
		if len(lines) == 0 || (len(lines) == 1 && lines[0] == "") {
			lines = []string{"IMSLP_LOGIN_TOKEN=" + token}
		} else {
			if lines[len(lines)-1] != "" {
				lines = append(lines, "")
			}
			lines = append(lines, "IMSLP_LOGIN_TOKEN="+token)
		}
	}

	newContent := strings.Join(lines, "\n")
	if !strings.HasSuffix(newContent, "\n") {
		newContent += "\n"
	}

	return os.WriteFile(envPath, []byte(newContent), 0600)
}
