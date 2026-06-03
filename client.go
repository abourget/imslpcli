package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"resty.dev/v3"
)

func init() {
	// Load .env as early as possible so that os.Getenv calls anywhere (including
	// in command handlers before NewClient is called) see the values.
	_ = godotenv.Load()
}

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

// NewClientWithToken returns a client authenticated with the provided IMSLP login token
// (used by the MCP server to serve per-user sessions from OAuth JWTs).
func NewClientWithToken(token string) *Client {
	c := NewClient()
	c.LoginToken = token
	return c
}

// IMSLPLoginTokenFromTokenInfo extracts the embedded IMSLP login token from
// the MCP RequestExtra.TokenInfo (our custom claim from the issued JWT).
func IMSLPLoginTokenFromTokenInfo(ti *auth.TokenInfo) string {
	if ti == nil || ti.Extra == nil {
		return ""
	}
	if v, ok := ti.Extra["imslp_login_token"].(string); ok && v != "" {
		return v
	}
	return ""
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

// FetchCurrentState performs a full sync starting from revision 0, paging through
// all history by repeatedly calling sync.get and following the returned revision
// cursors. It stops only when a response contains no items (len(items)==0).
// This ensures it pulls the absolute latest changes (including live deltas pushed
// by other clients/apps after previous syncs), not just up to the point where
// "remaining" first hits 0.
func (c *Client) FetchCurrentState() (currentItems []any, finalPos, finalMaj, finalReq int, err error) {
	itemMap := map[string]map[string]any{}
	pos, req, maj := 0, 0, 0
	for {
		data, err := c.SyncGet(pos, req, maj)
		if err != nil {
			return nil, 0, 0, 0, err
		}
		nitems := 0
		if itemsIface, ok := data["items"].([]any); ok {
			nitems = len(itemsIface)
			for _, itIface := range itemsIface {
				if it, ok := itIface.(map[string]any); ok {
					if id, ok := it["itemId"].(string); ok && id != "" {
						// later revisions (higher in the log) win
						itemMap[id] = it
					}
				}
			}
		}
		if v, ok := data["revisionPosition"].(float64); ok {
			pos = int(v)
		}
		if v, ok := data["revisionMajor"].(float64); ok {
			maj = int(v)
		}
		if v, ok := data["revisionRequested"].(float64); ok {
			req = int(v)
		}
		if nitems == 0 {
			break
		}
	}
	// materialize current non-deleted items
	for _, it := range itemMap {
		isDeleted := false
		if v, ok := it["isDeleted"]; ok {
			switch vv := v.(type) {
			case float64:
				isDeleted = vv != 0
			case bool:
				isDeleted = vv
			}
		}
		if !isDeleted {
			currentItems = append(currentItems, it)
		}
	}
	return currentItems, pos, maj, req, nil
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

// --- Setlist mutation helpers (reverse engineered from HAR session) ---

// generateSetlistItemID produces itemIds in the exact format the app uses:
// <unix_millis>-<16 uppercase hex chars>
func generateSetlistItemID() string {
	ts := time.Now().UnixMilli()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// very unlikely; fallback to deterministic for the call
		copy(b, []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef})
	}
	return fmt.Sprintf("%d-%s", ts, strings.ToUpper(hex.EncodeToString(b)))
}

func getMap(m map[string]any, key string) map[string]any {
	if v, ok := m[key]; ok {
		if mm, ok := v.(map[string]any); ok {
			return mm
		}
	}
	return map[string]any{}
}

func getString(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getAnySlice(m map[string]any, key string) []any {
	if v, ok := m[key]; ok {
		if s, ok := v.([]any); ok {
			return s
		}
	}
	return nil
}

// CreateSetlist creates a completely new setlist (corresponds to the initial
// userId:false puts with no oldData in the HAR).
// Returns the new itemId.
func (c *Client) CreateSetlist(name string, scoreItemIDs []string) (string, error) {
	itemID := generateSetlistItemID()
	now := time.Now().UnixMilli()

	item := map[string]any{
		"itemId":     itemID,
		"userId":     false,
		"type":       1,
		"fileItemId": nil,
		"data": map[string]any{
			"name":  name,
			"items": scoreItemIDs,
		},
		"revision":  0, // the server accepts and will assign real rev on next sync
		"createdAt": now,
		"updatedAt": now,
		"shareId":   0,
		"isDeleted": false,
	}
	if _, err := c.SyncPut([]any{item}); err != nil {
		return "", err
	}
	return itemID, nil
}

// CloneSetlist creates a new setlist by copying the members of an existing one
// (this is what the session did for "clone"). It follows the HAR pattern of
// supplying oldData even on the create put.
func (c *Client) CloneSetlist(source map[string]any, newName string) (string, error) {
	if source == nil {
		return "", fmt.Errorf("source setlist item required")
	}
	srcData := getMap(source, "data")
	itemID := generateSetlistItemID()
	now := time.Now().UnixMilli()

	data := map[string]any{
		"name":  newName,
		"items": getAnySlice(srcData, "items"),
	}
	oldData := map[string]any{
		"name":  getString(srcData, "name"),
		"items": getAnySlice(srcData, "items"),
	}

	item := map[string]any{
		"itemId":     itemID,
		"userId":     false,
		"type":       1,
		"fileItemId": nil,
		"data":       data,
		"revision":   source["revision"],
		"createdAt":  now,
		"updatedAt":  now,
		"shareId":    0,
		"oldData":    oldData,
		"isDeleted":  false,
	}
	if _, err := c.SyncPut([]any{item}); err != nil {
		return "", err
	}
	return itemID, nil
}

// UpdateSetlist performs a rename, reorder, add or remove on an existing setlist.
// You must pass the *current* full item (as returned by FetchCurrentState or
// loaded from your setlists.json) so we can build the correct oldData that the
// backend expects for modifications.
func (c *Client) UpdateSetlist(current map[string]any, newName string, newScoreItemIDs []any) error {
	if current == nil {
		return fmt.Errorf("current setlist item (from sync) is required")
	}
	itemID := getString(current, "itemId")
	if itemID == "" {
		return fmt.Errorf("current item has no itemId")
	}

	curData := getMap(current, "data")
	oldData := map[string]any{
		"name":  getString(curData, "name"),
		"items": getAnySlice(curData, "items"),
	}

	now := time.Now().UnixMilli()
	newData := map[string]any{
		"name":  newName,
		"items": newScoreItemIDs,
	}

	putItem := map[string]any{
		"itemId":     itemID,
		"userId":     current["userId"],
		"type":       1,
		"fileItemId": current["fileItemId"],
		"data":       newData,
		"revision":   current["revision"],
		"createdAt":  current["createdAt"],
		"updatedAt":  now,
		"shareId":    current["shareId"],
		"oldData":    oldData,
		"isDeleted":  false,
	}
	_, err := c.SyncPut([]any{putItem})
	return err
}

// DeleteSetlist marks a setlist as deleted (the isDeleted:1 + oldData pattern).
func (c *Client) DeleteSetlist(current map[string]any) error {
	if current == nil {
		return fmt.Errorf("current setlist item required")
	}
	itemID := getString(current, "itemId")
	curData := getMap(current, "data")
	oldData := map[string]any{
		"name":  getString(curData, "name"),
		"items": getAnySlice(curData, "items"),
	}

	now := time.Now().UnixMilli()

	putItem := map[string]any{
		"itemId":     itemID,
		"userId":     current["userId"],
		"type":       1,
		"fileItemId": current["fileItemId"],
		"data":       curData, // keep current name/items in data
		"revision":   current["revision"],
		"createdAt":  current["createdAt"],
		"updatedAt":  now,
		"shareId":    current["shareId"],
		"oldData":    oldData,
		"isDeleted":  1, // important: 1 (number) as seen in HAR
	}
	_, err := c.SyncPut([]any{putItem})
	return err
}

// AppendToSetlist appends scoreID to the end of the current setlist's items list
// (does nothing if already present). Uses UpdateSetlist internally so oldData is provided.
func (c *Client) AppendToSetlist(current map[string]any, scoreID string) error {
	if current == nil {
		return fmt.Errorf("current setlist item required")
	}
	data := getMap(current, "data")
	items := getAnySlice(data, "items")
	for _, id := range items {
		if fmt.Sprintf("%v", id) == scoreID {
			return nil
		}
	}
	newItems := append(append([]any(nil), items...), scoreID)
	name := getString(data, "name")
	return c.UpdateSetlist(current, name, newItems)
}

// PrependToSetlist inserts scoreID at the beginning (if not already present).
func (c *Client) PrependToSetlist(current map[string]any, scoreID string) error {
	if current == nil {
		return fmt.Errorf("current setlist item required")
	}
	data := getMap(current, "data")
	items := getAnySlice(data, "items")
	for _, id := range items {
		if fmt.Sprintf("%v", id) == scoreID {
			return nil
		}
	}
	newItems := append([]any{scoreID}, items...)
	name := getString(data, "name")
	return c.UpdateSetlist(current, name, newItems)
}

// InsertAfterInSetlist inserts insertedID immediately after prevID.
// If prevID is not found, appends at the end (unless inserted already present).
func (c *Client) InsertAfterInSetlist(current map[string]any, prevID, insertedID string) error {
	if current == nil {
		return fmt.Errorf("current setlist item required")
	}
	data := getMap(current, "data")
	items := getAnySlice(data, "items")

	// dedup check
	for _, id := range items {
		if fmt.Sprintf("%v", id) == insertedID {
			return nil
		}
	}

	newItems := make([]any, 0, len(items)+1)
	inserted := false
	for _, id := range items {
		newItems = append(newItems, id)
		if fmt.Sprintf("%v", id) == prevID {
			newItems = append(newItems, insertedID)
			inserted = true
		}
	}
	if !inserted {
		newItems = append(newItems, insertedID)
	}

	name := getString(data, "name")
	return c.UpdateSetlist(current, name, newItems)
}

// ScoreSearchResult for search.
type ScoreSearchResult struct {
	ID        string
	Title     string
	Composer  string
	WorkTitle string
}

// SearchScores does a full sync then returns scores whose info contains the query
// (case-insensitive). Returns ID, Work Title, Composer and Title.
func (c *Client) SearchScores(query string) ([]ScoreSearchResult, error) {
	items, _, _, _, err := c.FetchCurrentState()
	if err != nil {
		return nil, err
	}
	q := strings.ToLower(query)
	var res []ScoreSearchResult
	for _, itIface := range items {
		it, ok := itIface.(map[string]any)
		if !ok {
			continue
		}
		if t, _ := it["type"].(float64); int(t) != 0 {
			continue
		}
		data := getMap(it, "data")
		title := ""
		composer := ""
		workTitle := ""
		matches := false
		for _, infIface := range getAnySlice(data, "info") {
			inf, ok := infIface.([]any)
			if !ok || len(inf) < 2 {
				continue
			}
			key := strings.ToLower(fmt.Sprintf("%v", inf[0]))
			val := fmt.Sprintf("%v", inf[1])
			if key == "title" {
				title = val
			} else if key == "composer" {
				composer = val
			} else if key == "work title" {
				workTitle = val
			}
			if strings.Contains(strings.ToLower(val), q) || strings.Contains(key, q) {
				matches = true
			}
		}
		if matches {
			id := getString(it, "itemId")
			res = append(res, ScoreSearchResult{ID: id, Title: title, Composer: composer, WorkTitle: workTitle})
		}
	}
	return res, nil
}

// SetlistSearchResult ...
type SetlistSearchResult struct {
	ID   string
	Name string
}

// SearchSetlists returns setlists whose name contains query (case-insens).
// Always returns ID too, since names can collide.
func (c *Client) SearchSetlists(query string) ([]SetlistSearchResult, error) {
	items, _, _, _, err := c.FetchCurrentState()
	if err != nil {
		return nil, err
	}
	q := strings.ToLower(query)
	var res []SetlistSearchResult
	for _, itIface := range items {
		it, ok := itIface.(map[string]any)
		if !ok {
			continue
		}
		if t, _ := it["type"].(float64); int(t) != 1 {
			continue
		}
		data := getMap(it, "data")
		name := getString(data, "name")
		if strings.Contains(strings.ToLower(name), q) {
			id := getString(it, "itemId")
			res = append(res, SetlistSearchResult{ID: id, Name: name})
		}
	}
	return res, nil
}

// DownloadFile fetches a file from a direct URL (public IMSLP files or
// stor.imslp.org blobs for mylib-only scores) and saves it to target.
// It is intentionally minimal and direct: no auth, no special headers,
// no cookies, no HTML scraping or web login. The caller is responsible
// for providing the final asset URL, which for mylib scores we obtain
// directly from the fileHash already present in our local sync data.
func DownloadFile(u, target string) error {
	resp, err := http.Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("http status %d for %s: %s", resp.StatusCode, u, string(b))
	}
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		return err
	}
	f, err := os.Create(target)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

