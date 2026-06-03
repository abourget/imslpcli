package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/joho/godotenv"
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
	ID    string
	Title string
}

// SearchScores does a full sync then returns scores whose info (esp. Work Title)
// contains the query (case-insensitive). Returns ID (itemId) and Title.
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
		matches := false
		for _, infIface := range getAnySlice(data, "info") {
			inf, ok := infIface.([]any)
			if !ok || len(inf) < 2 {
				continue
			}
			key := strings.ToLower(fmt.Sprintf("%v", inf[0]))
			val := fmt.Sprintf("%v", inf[1])
			if key == "work title" {
				title = val
			}
			if strings.Contains(strings.ToLower(val), q) || strings.Contains(key, q) {
				matches = true
			}
		}
		if matches {
			id := getString(it, "itemId")
			res = append(res, ScoreSearchResult{ID: id, Title: title})
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

func (c *Client) initWebClient() {
	if c.webClient != nil {
		return
	}
	jar, _ := cookiejar.New(nil)
	c.webClient = &http.Client{
		Jar:     jar,
		Timeout: 120 * time.Second,
	}
}

// fetchURLWithBrowserHeaders performs a GET mimicking the browser curl the user
// provided for stor.imslp.org assets (with Referer/Origin/UA/Sec-* headers).
// It also carries cookies from the jar (loginToken when present).
func (c *Client) fetchURLWithBrowserHeaders(u string) (*http.Response, error) {
	c.initWebClient()
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}
	// Headers from the exact curl example provided for the stor PDF fetch:
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9,fr;q=0.8")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Referer", "https://imslp.org/")
	req.Header.Set("Origin", "https://imslp.org")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36")
	req.Header.Set("sec-ch-ua", `"Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99"`)
	req.Header.Set("sec-ch-ua-mobile", "?0")
	req.Header.Set("sec-ch-ua-platform", `"macOS"`)
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Set("Connection", "keep-alive")

	// Also attach loginToken (as cookie) when we have it, per "curl ... with the login token".
	if c.LoginToken != "" {
		if parsed, perr := url.Parse(u); perr == nil && strings.HasSuffix(parsed.Host, "imslp.org") {
			root, _ := url.Parse("https://imslp.org/")
			c.webClient.Jar.SetCookies(root, []*http.Cookie{
				{Name: "loginToken", Value: c.LoginToken, Path: "/", Domain: ".imslp.org"},
			})
		}
	}

	return c.webClient.Do(req)
}

// extractPDFURL scans a (HTML/JS) page body for a direct PDF asset URL.
// Prefers stor.imslp.org links; falls back to other .pdf mentions (skips obvious non-assets).
func extractPDFURL(pageBody, base string) string {
	// direct stor links (what browser curl actually hits)
	reStor := regexp.MustCompile(`https?://stor\.imslp\.org/[^\s"'<>]+\.pdf`)
	if m := reStor.FindString(pageBody); m != "" {
		return m
	}
	// any full URL containing stor + .pdf
	re := regexp.MustCompile(`(https?://[^"'\s<>()]*stor[^"'\s<>()]*\.pdf[^"'\s<>()]*)`)
	if m := re.FindStringSubmatch(pageBody); len(m) > 1 {
		return m[1]
	}
	// relative paths
	reRel := regexp.MustCompile(`["'](/[^"'\s<>()]*\.pdf[^"'\s<>()]*)["']`)
	if m := reRel.FindStringSubmatch(pageBody); len(m) > 1 {
		if bu, err := url.Parse(base); err == nil {
			if ru, err := url.Parse(m[1]); err == nil {
				return bu.ResolveReference(ru).String()
			}
		}
		return m[1]
	}
	// broad quoted .pdf , avoid login-related
	rePDF := regexp.MustCompile(`["']([^"']+\.pdf[^"'\s<>'"]*)["']`)
	for _, m := range rePDF.FindAllStringSubmatch(pageBody, -1) {
		u := m[1]
		lu := strings.ToLower(u)
		if strings.Contains(lu, ".pdf") && !strings.Contains(lu, "login") && !strings.Contains(lu, "icon") && !strings.Contains(lu, "logo") && !strings.Contains(lu, "spinner") {
			if strings.HasPrefix(u, "http") {
				return u
			}
			if bu, err := url.Parse(base); err == nil {
				if ru, err := url.Parse(u); err == nil {
					return bu.ResolveReference(ru).String()
				}
			}
			return u
		}
	}
	return ""
}

// downloadToFile fetches u using browser-like headers + web cookies (loginToken),
// saves bytes to target. If the response is not a PDF (e.g. HTML viewer page),
// it extracts an asset URL from the body and fetches that instead (the actual stor PDF).
// This lets us "just do something like a curl on that [mylib or stor] URL".
func (c *Client) downloadToFile(u, target string) error {
	resp, err := c.fetchURLWithBrowserHeaders(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("http status %d for %s: %s", resp.StatusCode, u, string(b))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	ct := resp.Header.Get("Content-Type")
	isPDF := strings.Contains(ct, "pdf") || bytes.HasPrefix(body, []byte("%PDF"))
	if !isPDF {
		// got HTML or other (viewer page); extract the real PDF asset (stor URL typically)
		asset := extractPDFURL(string(body), u)
		if asset == "" {
			return fmt.Errorf("fetched %s (type=%s, %d bytes) but it was not a PDF and no stor/asset .pdf link found in response; body snippet: %.200s", u, ct, len(body), string(body))
		}
		if !strings.HasPrefix(asset, "http") {
			if bu, perr := url.Parse(u); perr == nil {
				if ru, perr := url.Parse(asset); perr == nil {
					asset = bu.ResolveReference(ru).String()
				}
			}
		}
		// recurse to fetch the real one (with same headers + cookies)
		return c.downloadToFile(asset, target)
	}

	// write PDF
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(target, body, 0644); err != nil {
		return err
	}
	return nil
}

