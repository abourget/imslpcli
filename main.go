package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/joho/godotenv"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "imslpcli",
	Short: "IMSLP command-line client (library + CLI)",
	Long: `A cobra-based CLI tool for IMSLP using the private sync API.
Uses resty for HTTP and godotenv for .env secrets (username/password or login token).`,
}

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Log in to IMSLP and obtain/save a login token",
	RunE: func(cmd *cobra.Command, args []string) error {
		_ = godotenv.Load() // ensure .env is loaded before we read IMSLP_* vars below

		username, _ := cmd.Flags().GetString("username")
		password, _ := cmd.Flags().GetString("password")

		if username == "" {
			username = os.Getenv("IMSLP_USERNAME")
		}
		if password == "" {
			password = os.Getenv("IMSLP_PASSWORD")
		}

		if username == "" || password == "" {
			return fmt.Errorf("username and password required (use --username/--password or set IMSLP_USERNAME/IMSLP_PASSWORD in .env)")
		}

		client := NewClient()
		if err := client.Login(username, password); err != nil {
			return err
		}

		if err := SaveTokenToEnv(client.LoginToken); err != nil {
			return fmt.Errorf("logged in but failed to save token to .env: %w", err)
		}

		fmt.Printf("Login successful for user %q (id=%d). Token saved to .env\n", client.Username, client.UserID)
		fmt.Println("You can now remove IMSLP_PASSWORD from .env (token is sufficient and preferred).")
		// Do not print the token itself.
		return nil
	},
}

var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Show current logged-in identity (from token in env)",
	RunE: func(cmd *cobra.Command, args []string) error {
		client := NewClient()
		if err := client.EnsureAuth(); err != nil {
			return err
		}
		data, err := client.SyncGet(0, 0, 0)
		if err != nil {
			return fmt.Errorf("failed to query identity: %w", err)
		}

		// Try to find user info in items
		if items, ok := data["items"].([]any); ok {
			for _, it := range items {
				if m, ok := it.(map[string]any); ok {
					if itemID, _ := m["itemId"].(string); itemID != "" && len(itemID) > 9 && itemID[:9] == "SHAREUSER" {
						if data, ok := m["data"].(map[string]any); ok {
							fmt.Printf("Logged in as: %v (userId=%v)\n", data["username"], m["userId"])
							return nil
						}
					}
				}
			}
		}
		// Fallback: print some info
		fmt.Printf("Token present (userId may be in previous sync state). Raw keys from sync.get: %v\n", keys(data))
		return nil
	},
}

func keys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sync local state (full history to get current scores + setlists)",
	RunE: func(cmd *cobra.Command, args []string) error {
		client := NewClient()
		if err := client.EnsureAuth(); err != nil {
			return err
		}

		fmt.Println("Performing full sync (paging history until caught up)...")
		currentItems, finalPos, finalMaj, finalReq, err := client.FetchCurrentState()
		if err != nil {
			return err
		}
		fmt.Printf("Full sync complete. %d current (non-deleted) items. final rev pos=%d maj=%d req=%d\n",
			len(currentItems), finalPos, finalMaj, finalReq)

		// Separate scores (type 0) and setlists (type 1)
		var scores, setlists []any
		for _, it := range currentItems {
			if m, ok := it.(map[string]any); ok {
				if t, ok := m["type"].(float64); ok {
					switch int(t) {
					case 0:
						scores = append(scores, it)
					case 1:
						setlists = append(setlists, it)
					}
				}
			}
		}
		fmt.Printf("Current scores: %d , setlists: %d\n", len(scores), len(setlists))

		// Write the materialized current views (these should have "data" for active items)
		if b, _ := json.MarshalIndent(scores, "", "  "); len(b) > 2 {
			_ = os.WriteFile("scores.json", b, 0644)
			fmt.Printf("Wrote scores.json (%d current items)\n", len(scores))
		}
		if b, _ := json.MarshalIndent(setlists, "", "  "); len(b) > 2 {
			_ = os.WriteFile("setlists.json", b, 0644)
			fmt.Printf("Wrote setlists.json (%d current items)\n", len(setlists))
		}

		// Also write a small snapshot of the final cursors for future incremental sync (not implemented yet)
		meta := map[string]any{
			"revisionPosition":  finalPos,
			"revisionMajor":     finalMaj,
			"revisionRequested": finalReq,
			"numScores":         len(scores),
			"numSetlists":       len(setlists),
		}
		if b, _ := json.MarshalIndent(meta, "", "  "); len(b) > 2 {
			_ = os.WriteFile("sync_meta.json", b, 0644)
		}

		return nil
	},
}

// --- setlist subcommands (create / modify using the patterns from the HAR) ---

var setlistCmd = &cobra.Command{
	Use:   "setlist",
	Short: "Manage setlists (playlists) - create, rename, clone, reorder, delete",
}

var setlistListCmd = &cobra.Command{
	Use:   "list",
	Short: "List current setlists (from a fresh full sync)",
	RunE: func(cmd *cobra.Command, args []string) error {
		client := NewClient()
		if err := client.EnsureAuth(); err != nil {
			return err
		}
		items, _, _, _, err := client.FetchCurrentState()
		if err != nil {
			return err
		}
		var lists []any
		for _, it := range items {
			if m, ok := it.(map[string]any); ok {
				if t, _ := m["type"].(float64); int(t) == 1 {
					lists = append(lists, it)
				}
			}
		}
		// write for convenience
		b, _ := json.MarshalIndent(lists, "", "  ")
		_ = os.WriteFile("setlists.json", b, 0644)
		fmt.Printf("%d setlists:\n", len(lists))
		var lines []string
		lines = append(lines, "ID|NAME|ITEMS")
		for _, l := range lists {
			if m, ok := l.(map[string]any); ok {
				data := getMap(m, "data")
				id := getString(m, "itemId")
				name := getString(data, "name")
				n := len(getAnySlice(data, "items"))
				lines = append(lines, fmt.Sprintf("%s|%s|%d", id, name, n))
			}
		}
		fmt.Println(columnize.SimpleFormat(lines))
		return nil
	},
}

var setlistCreateCmd = &cobra.Command{
	Use:   "create <name> [scoreItemId1 scoreItemId2 ...]",
	Short: "Create a brand new setlist (like the initial create in the HAR)",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client := NewClient()
		if err := client.EnsureAuth(); err != nil {
			return err
		}
		name := args[0]
		ids := args[1:]
		newID, err := client.CreateSetlist(name, ids)
		if err != nil {
			return err
		}
		fmt.Printf("Created setlist %q -> itemId=%s\n", name, newID)
		// refresh local files
		return refreshSetlistsAndScores(client)
	},
}

var setlistCloneCmd = &cobra.Command{
	Use:   "clone <sourceItemIdOrName> <newName>",
	Short: "Clone an existing setlist (the pattern used in the session)",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		client := NewClient()
		if err := client.EnsureAuth(); err != nil {
			return err
		}
		srcID := args[0]
		newName := args[1]

		current, err := findSetlist(client, srcID)
		if err != nil {
			return err
		}
		newID, err := client.CloneSetlist(current, newName)
		if err != nil {
			return err
		}
		fmt.Printf("Cloned to new setlist %q -> itemId=%s\n", newName, newID)
		return refreshSetlistsAndScores(client)
	},
}

var setlistRenameCmd = &cobra.Command{
	Use:   "rename <itemIdOrName> <newName>",
	Short: "Rename a setlist (update data.name, with oldData)",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		client := NewClient()
		if err := client.EnsureAuth(); err != nil {
			return err
		}
		idOrName := args[0]
		newName := args[1]

		cur, err := findSetlist(client, idOrName)
		if err != nil {
			return err
		}
		data := getMap(cur, "data")
		oldItems := getAnySlice(data, "items")
		if err := client.UpdateSetlist(cur, newName, oldItems); err != nil {
			return err
		}
		fmt.Printf("Renamed setlist to %q\n", newName)
		return refreshSetlistsAndScores(client)
	},
}

var setlistReorderCmd = &cobra.Command{
	Use:   "reorder <itemIdOrName> <id1> <id2> ...",
	Short: "Change the order (or membership) of a setlist (provides oldData)",
	Args:  cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		client := NewClient()
		if err := client.EnsureAuth(); err != nil {
			return err
		}
		idOrName := args[0]
		newOrder := args[1:]

		cur, err := findSetlist(client, idOrName)
		if err != nil {
			return err
		}
		data := getMap(cur, "data")
		oldName := getString(data, "name")
		// convert []string from CLI args to []any
		ids := make([]any, len(newOrder))
		for i, s := range newOrder {
			ids[i] = s
		}
		if err := client.UpdateSetlist(cur, oldName, ids); err != nil {
			return err
		}
		fmt.Printf("Reordered setlist %q\n", oldName)
		return refreshSetlistsAndScores(client)
	},
}

var setlistDeleteCmd = &cobra.Command{
	Use:   "delete <itemIdOrName>",
	Short: "Delete a setlist (the isDeleted:1 + oldData pattern from the HAR)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client := NewClient()
		if err := client.EnsureAuth(); err != nil {
			return err
		}
		cur, err := findSetlist(client, args[0])
		if err != nil {
			return err
		}
		name := getString(getMap(cur, "data"), "name")
		if err := client.DeleteSetlist(cur); err != nil {
			return err
		}
		fmt.Printf("Deleted setlist %q\n", name)
		return refreshSetlistsAndScores(client)
	},
}

var setlistAppendCmd = &cobra.Command{
	Use:   "append <setlist-id-or-name> <score-id>",
	Short: "Append a score (by its ID) to the end of a setlist",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		client := NewClient()
		if err := client.EnsureAuth(); err != nil {
			return err
		}
		setlistRef, scoreID := args[0], args[1]
		cur, err := findSetlist(client, setlistRef)
		if err != nil {
			return err
		}
		if err := client.AppendToSetlist(cur, scoreID); err != nil {
			return err
		}
		fmt.Printf("Appended %s to setlist\n", scoreID)
		return refreshSetlistsAndScores(client)
	},
}

var setlistPrependCmd = &cobra.Command{
	Use:   "prepend <setlist-id-or-name> <score-id>",
	Short: "Prepend a score (by its ID) to the beginning of a setlist",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		client := NewClient()
		if err := client.EnsureAuth(); err != nil {
			return err
		}
		setlistRef, scoreID := args[0], args[1]
		cur, err := findSetlist(client, setlistRef)
		if err != nil {
			return err
		}
		if err := client.PrependToSetlist(cur, scoreID); err != nil {
			return err
		}
		fmt.Printf("Prepended %s to setlist\n", scoreID)
		return refreshSetlistsAndScores(client)
	},
}

var setlistInsertCmd = &cobra.Command{
	Use:   "insert <setlist-id-or-name> <prev-score-id> <new-score-id>",
	Short: "Insert new-score-id right after prev-score-id in the setlist",
	Args:  cobra.ExactArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		client := NewClient()
		if err := client.EnsureAuth(); err != nil {
			return err
		}
		setlistRef, prevID, newID := args[0], args[1], args[2]
		cur, err := findSetlist(client, setlistRef)
		if err != nil {
			return err
		}
		if err := client.InsertAfterInSetlist(cur, prevID, newID); err != nil {
			return err
		}
		fmt.Printf("Inserted %s after %s in setlist\n", newID, prevID)
		return refreshSetlistsAndScores(client)
	},
}

var setlistSearchCmd = &cobra.Command{
	Use:   "search <query>",
	Short: "Search setlists by name (case-insens), shows ID and Name (use ID to refer unambiguously)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client := NewClient()
		if err := client.EnsureAuth(); err != nil {
			return err
		}
		results, err := client.SearchSetlists(args[0])
		if err != nil {
			return err
		}
		for _, r := range results {
			fmt.Printf("%s\t%s\n", r.ID, r.Name)
		}
		if len(results) == 0 {
			fmt.Println("no matches")
		}
		return nil
	},
}

var setlistShowCmd = &cobra.Command{
	Use:   "show <setlist-id-or-name>",
	Short: "Show all scores in a setlist (by ID or name), using Work Title from scores",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client := NewClient()
		if err := client.EnsureAuth(); err != nil {
			return err
		}
		ref := args[0]
		allItems, _, _, _, err := client.FetchCurrentState()
		if err != nil {
			return err
		}
		// find setlist (dupe of findSetlist logic to avoid extra fetch)
		var setlist map[string]any
		trimmed := strings.TrimSpace(ref)
		for _, it := range allItems {
			if m, ok := it.(map[string]any); ok {
				if t, _ := m["type"].(float64); int(t) == 1 {
					data := getMap(m, "data")
					if getString(m, "itemId") == ref || strings.TrimSpace(getString(data, "name")) == trimmed {
						setlist = m
						break
					}
				}
			}
		}
		if setlist == nil {
			return fmt.Errorf("no setlist found with id or name %q (run `imslpcli setlist list`)", ref)
		}
		data := getMap(setlist, "data")
		name := getString(data, "name")
		id := getString(setlist, "itemId")
		scoreIDs := getAnySlice(data, "items")
		// build score id -> title map
		scoreTitles := map[string]string{}
		for _, it := range allItems {
			if m, ok := it.(map[string]any); ok {
				if t, _ := m["type"].(float64); int(t) == 0 {
					sid := getString(m, "itemId")
					sdata := getMap(m, "data")
					title := ""
					for _, infIface := range getAnySlice(sdata, "info") {
						inf, ok := infIface.([]any)
						if !ok || len(inf) < 2 {
							continue
						}
						key := strings.ToLower(fmt.Sprintf("%v", inf[0]))
						val := fmt.Sprintf("%v", inf[1])
						if key == "work title" {
							title = val
							break
						}
					}
					scoreTitles[sid] = title
				}
			}
		}
		fmt.Printf("Setlist %s (%s) has %d scores:\n", name, id, len(scoreIDs))
		var lines []string
		lines = append(lines, "ID|TITLE")
		for _, sidIface := range scoreIDs {
			sid := fmt.Sprintf("%v", sidIface)
			title := scoreTitles[sid]
			if title == "" {
				title = "(not found / deleted?)"
			}
			lines = append(lines, fmt.Sprintf("%s|%s", sid, title))
		}
		fmt.Println(columnize.SimpleFormat(lines))
		return nil
	},
}

var scoresCmd = &cobra.Command{
	Use:   "scores",
	Short: "Commands for searching scores in your library",
}

var scoresSearchCmd = &cobra.Command{
	Use:   "search <query>",
	Short: "Search scores (by Work Title or other info), prints ID, Work Title, Composer and Title",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client := NewClient()
		if err := client.EnsureAuth(); err != nil {
			return err
		}
		results, err := client.SearchScores(args[0])
		if err != nil {
			return err
		}
		if len(results) == 0 {
			fmt.Println("no matches")
			return nil
		}
		var lines []string
		lines = append(lines, "ID|WORK TITLE|COMPOSER|TITLE")
		for _, r := range results {
			lines = append(lines, fmt.Sprintf("%s|%s|%s|%s", r.ID, r.WorkTitle, r.Composer, r.Title))
		}
		fmt.Println(columnize.SimpleFormat(lines))
		return nil
	},
}

var scoresDownloadCmd = &cobra.Command{
	Use:   "download <idOrName>",
	Short: "Download a score by ID or name (Work Title). If name ambiguous, lists matches with IDs and exits.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client := NewClient()
		if err := client.EnsureAuth(); err != nil {
			return err
		}
		ref := args[0]
		score, err := findScore(client, ref)
		if err != nil {
			return err
		}
		data := getMap(score, "data")
		custom := getMap(data, "custom")
		downloadURL := getString(custom, "downloadURL")
		title := ""
		for _, infIface := range getAnySlice(data, "info") {
			inf, ok := infIface.([]any)
			if !ok || len(inf) < 2 {
				continue
			}
			key := strings.ToLower(fmt.Sprintf("%v", inf[0]))
			val := fmt.Sprintf("%v", inf[1])
			if key == "work title" {
				title = val
				break
			}
		}
		if title == "" {
			title = getString(score, "itemId")
		}
		// determine target
		dir, _ := cmd.Flags().GetString("directory")
		out, _ := cmd.Flags().GetString("output")
		var target string
		if out != "" {
			target = out
		} else {
			base := sanitizeFileName(title) + ".pdf"
			if dir != "" {
				target = filepath.Join(dir, base)
			} else {
				target = base
			}
		}
		if downloadURL == "" {
			// mylib-only/user-uploaded scores (the ones that only appear under /mylib/)
			// have no downloadURL in the sync data, but they *do* have fileHash.
			// We construct the stor.imslp.org URL directly from it and fetch plain.
			// (These stor links work completely unauthenticated; no token/cookies/headers/HTML needed.)
			fileHash := getString(custom, "fileHash")
			if fileHash == "" || len(fileHash) < 3 {
				return fmt.Errorf("no downloadURL for this score and no fileHash to synthesize stor PDF URL")
			}
			downloadURL = fmt.Sprintf("https://stor.imslp.org/uploads/shared/%s/%s/%s/%s.pdf",
				fileHash[0:1], fileHash[1:2], fileHash[2:3], fileHash)
		}
		fmt.Printf("Downloading %s to %s ...\n", downloadURL, target)
		if err := DownloadFile(downloadURL, target); err != nil {
			return fmt.Errorf("download failed: %w", err)
		}
		fmt.Printf("Downloaded to %s\n", target)
		return nil
	},
}

var scoresShowCmd = &cobra.Command{
	Use:   "show <idOrName>",
	Short: "Show detailed info for a score by ID or Work Title (ambiguous names list matches with IDs)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client := NewClient()
		if err := client.EnsureAuth(); err != nil {
			return err
		}
		ref := args[0]
		score, err := findScore(client, ref)
		if err != nil {
			return err
		}
		data := getMap(score, "data")
		custom := getMap(data, "custom")
		itemID := getString(score, "itemId")

		var entries []struct{ key, val string }
		entries = append(entries, struct{key, val string}{"ID", itemID})

		// core top-level record fields (format integers without scientific notation for readability)
		for _, k := range []string{"createdAt", "updatedAt", "revision", "userId", "type", "isDeleted", "fileItemId"} {
			raw := score[k]
			v := fmt.Sprintf("%v", raw)
			if f, ok := raw.(float64); ok {
				if f == float64(int64(f)) {
					v = fmt.Sprintf("%d", int64(f))
				} else {
					// force full digits, no e+ notation for large timestamps etc.
					v = fmt.Sprintf("%.0f", f)
				}
			}
			if v == "<nil>" {
				v = "(null)"
			}
			entries = append(entries, struct{key, val string}{k, v})
		}

		// the song metadata from the info array (preserves original order)
		for _, infIface := range getAnySlice(data, "info") {
			inf, ok := infIface.([]any)
			if !ok || len(inf) < 2 {
				continue
			}
			k := fmt.Sprintf("%v", inf[0])
			v := fmt.Sprintf("%v", inf[1])
			entries = append(entries, struct{key, val string}{k, v})
		}

		// custom storage fields (fileHash always present for asset location)
		for _, ck := range []string{"fileHash", "downloadURL", "filePath"} {
			cv := getString(custom, ck)
			entries = append(entries, struct{key, val string}{ck, cv})
		}

		// always derive + show the direct Download URL (the stor one, works unauthenticated)
		fileHash := getString(custom, "fileHash")
		stor := "(unavailable - no fileHash)"
		if len(fileHash) >= 3 {
			stor = fmt.Sprintf("https://stor.imslp.org/uploads/shared/%s/%s/%s/%s.pdf",
				fileHash[0:1], fileHash[1:2], fileHash[2:3], fileHash)
		}
		entries = append(entries, struct{key, val string}{"Download URL", stor})

		// print everything aligned; special handling for multiline values (Lyrics, Publisher, Copyright, etc.)
		maxW := 0
		for _, e := range entries {
			if l := runeLen(e.key); l > maxW {
				maxW = l
			}
		}
		for _, e := range entries {
			printKeyValue(e.key, e.val, maxW)
		}
		return nil
	},
}

// mcpCmd starts the combined Authorization Server + Resource Server for exposing
// all imslpcli functionality over MCP (streamable HTTP) with a built-in OAuth2
// login flow (username/pass HTML form -> real IMSLP login -> short code -> JWT
// containing the loginToken). Designed for hosted multi-tenant use with Claude,
// Grok, etc. Discovery + DCR + PKCE means clients need no pre-configuration.
// The public identity (for metadata, JWT iss/aud, links) comes from --base-url,
// APP_BASE_URL env, or defaults to http://localhost:PORT.
var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Start MCP server (HTTP streaming) with OAuth2 AS+RS (login form + JWTs for per-user IMSLP access)",
	Long: `Runs a single HTTP server that is simultaneously:
- OAuth 2.0 Authorization Server (/.well-known/oauth-authorization-server, /authorize with IMSLP login/pass HTML form, /token for PKCE exchange returning JWT, /register for DCR)
- MCP Resource Server (/mcp) using streamable HTTP; all tool calls authenticated via the Bearer JWT (which embeds the user's IMSLP loginToken for backend calls).

Clients (Claude Desktop, etc.) perform standard discovery from the MCP URL's 401 WWW-Authenticate, auto DCR if needed, redirect user to /authorize for the login form, obtain JWT, and use it. No client secrets or pre-registration required from the human operator. Registered clients, MCP sessions (Mcp-Session-Id bindings), and JWT signing secret are persisted to disk (mcp-clients.json, mcp-sessions.json, mcp-jwt-secret.key by default) so flows and sessions survive restarts.

Use --base-url (or APP_BASE_URL env) when hosting publicly (e.g. https://imslp-mcp.exe.xyz). Provide a stable JWT secret via --jwt-secret, IMSLP_MCP_JWT_SECRET env, or let it be persisted to --jwt-secret-file (default: mcp-jwt-secret.key) so tokens survive restarts.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		port, _ := cmd.Flags().GetInt("port")
		host, _ := cmd.Flags().GetString("host")
		baseURL, _ := cmd.Flags().GetString("base-url")
		jwtSec, _ := cmd.Flags().GetString("jwt-secret")
		jwtSecretFile, _ := cmd.Flags().GetString("jwt-secret-file")
		if baseURL == "" {
			baseURL = os.Getenv("APP_BASE_URL")
		}
		if baseURL == "" {
			baseURL = fmt.Sprintf("http://localhost:%d", port)
		}
		secret, err := loadOrGenerateJWTSecret(jwtSec, os.Getenv("IMSLP_MCP_JWT_SECRET"), jwtSecretFile)
		if err != nil {
			return fmt.Errorf("failed to obtain JWT secret: %w", err)
		}
		addr := fmt.Sprintf("%s:%d", host, port)
		clientsFile, _ := cmd.Flags().GetString("clients-file")
		sessionsFile, _ := cmd.Flags().GetString("sessions-file")
		s := newIMSLPMCPServer(baseURL, secret, clientsFile, sessionsFile)
		mux := http.NewServeMux()
		handler := s.registerHandlers(mux)
		log.Printf("IMSLP MCP (AS+RS) listening on http://%s", addr)
		log.Printf("  Public base (for metadata): %s", baseURL)
		log.Printf("  Connect MCP clients to: %s/mcp", baseURL)
		log.Printf("  OAuth AS metadata: %s/.well-known/oauth-authorization-server", baseURL)
		log.Printf("  Persisted clients file: %s", clientsFile)
		log.Printf("  Persisted sessions file: %s", sessionsFile)
		log.Printf("  JWT secret file: %s (used for persistent signing key)", jwtSecretFile)
		return http.ListenAndServe(addr, handler)
	},
}

func sanitizeFileName(s string) string {
	// replace common invalid filename chars
	repl := strings.NewReplacer(
		"/", "_", "\\", "_", ":", "_", "*", "_",
		"?", "_", "\"", "_", "<", "_", ">", "_", "|", "_",
		"\n", " ", "\r", " ", "\t", " ",
	)
	return strings.TrimSpace(repl.Replace(s))
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// runeLen counts unicode codepoints for proper alignment/padding (handles UTF-8
// accents etc. that tabwriter had trouble with).
func runeLen(s string) int {
	l := 0
	for range s {
		l++
	}
	return l
}

// printKeyValue prints "KEY: value" with keys left-aligned to maxW.
// For values containing \n (e.g. Lyrics, Copyright, Publisher with multi-line notes),
// continuation lines are indented to align under the start of the value.
func printKeyValue(key, val string, maxW int) {
	pad := maxW - runeLen(key)
	if pad < 0 {
		pad = 0
	}
	prefix := key + strings.Repeat(" ", pad) + ": "
	if val == "" {
		val = "(empty)"
	}
	// normalize the various line endings that appear in the synced info data
	val = strings.ReplaceAll(val, "\r\n", "\n")
	val = strings.ReplaceAll(val, "\r", "\n")
	lines := strings.Split(val, "\n")
	for i, line := range lines {
		if i == 0 {
			fmt.Println(prefix + line)
		} else {
			fmt.Println(strings.Repeat(" ", len(prefix)) + line)
		}
	}
}

// findScore resolves an idOrName (exact itemId or exact Work Title) to a single
// score record. Mirrors the logic previously inline in download (now shared).
// On name ambiguity it prints the candidates (with IDs) exactly like download did.
func findScore(client *Client, idOrName string) (map[string]any, error) {
	allItems, _, _, _, err := client.FetchCurrentState()
	if err != nil {
		return nil, err
	}
	var matches []map[string]any
	// heuristic: looks like ID if contains '-' with left ~13 digits, right 16 alphanum
	parts := strings.Split(idOrName, "-")
	looksLikeID := len(parts) == 2 && len(parts[0]) >= 10 && len(parts[1]) == 16 && isHex(parts[1])
	for _, itIface := range allItems {
		it, ok := itIface.(map[string]any)
		if !ok {
			continue
		}
		if t, _ := it["type"].(float64); int(t) != 0 {
			continue
		}
		sid := getString(it, "itemId")
		if looksLikeID && sid == idOrName {
			matches = append(matches, it)
			break
		}
		if !looksLikeID {
			data := getMap(it, "data")
			title := ""
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
			}
			if title != "" && title == idOrName {
				matches = append(matches, it)
			}
		}
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("no score found for %q (use `scores search %q` to find IDs)", idOrName, idOrName)
	}
	if len(matches) > 1 {
		var lines []string
		lines = append(lines, fmt.Sprintf("Ambiguous name %q, multiple matches (use ID instead):", idOrName))
		for _, m := range matches {
			data := getMap(m, "data")
			title := ""
			for _, infIface := range getAnySlice(data, "info") {
				inf, ok := infIface.([]any)
				if !ok || len(inf) < 2 {
					continue
				}
				key := strings.ToLower(fmt.Sprintf("%v", inf[0]))
				val := fmt.Sprintf("%v", inf[1])
				if key == "work title" {
					title = val
					break
				}
			}
			id := getString(m, "itemId")
			lines = append(lines, fmt.Sprintf("  %s  %s", id, title))
		}
		// For CLI this also prints (kept for compatibility), for MCP the error carries details.
		for _, l := range lines {
			fmt.Println(l)
		}
		return nil, fmt.Errorf("%s", strings.Join(lines, "\n"))
	}
	return matches[0], nil
}

func findSetlist(client *Client, idOrName string) (map[string]any, error) {
	items, _, _, _, err := client.FetchCurrentState()
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(idOrName)
	for _, it := range items {
		if m, ok := it.(map[string]any); ok {
			if t, _ := m["type"].(float64); int(t) == 1 {
				data := getMap(m, "data")
				if getString(m, "itemId") == idOrName || strings.TrimSpace(getString(data, "name")) == trimmed {
					return m, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("no setlist found with id or name %q (run `imslpcli setlist list`)", idOrName)
}

func refreshSetlistsAndScores(client *Client) error {
	items, _, _, _, err := client.FetchCurrentState()
	if err != nil {
		return err
	}
	var scores, lists []any
	for _, it := range items {
		if m, ok := it.(map[string]any); ok {
			if t, _ := m["type"].(float64); ok {
				switch int(t) {
				case 0:
					scores = append(scores, it)
				case 1:
					lists = append(lists, it)
				}
			}
		}
	}
	if b, _ := json.MarshalIndent(scores, "", "  "); len(b) > 2 {
		_ = os.WriteFile("scores.json", b, 0644)
	}
	if b, _ := json.MarshalIndent(lists, "", "  "); len(b) > 2 {
		_ = os.WriteFile("setlists.json", b, 0644)
	}
	fmt.Printf("Refreshed: %d scores, %d setlists\n", len(scores), len(lists))
	return nil
}

func init() {
	loginCmd.Flags().StringP("username", "u", "", "IMSLP username or email (falls back to IMSLP_USERNAME env)")
	loginCmd.Flags().StringP("password", "p", "", "IMSLP password (falls back to IMSLP_PASSWORD env)")

	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(whoamiCmd)
	rootCmd.AddCommand(syncCmd)

	setlistCmd.AddCommand(setlistListCmd)
	setlistCmd.AddCommand(setlistCreateCmd)
	setlistCmd.AddCommand(setlistCloneCmd)
	setlistCmd.AddCommand(setlistRenameCmd)
	setlistCmd.AddCommand(setlistReorderCmd)
	setlistCmd.AddCommand(setlistDeleteCmd)
	setlistCmd.AddCommand(setlistAppendCmd)
	setlistCmd.AddCommand(setlistPrependCmd)
	setlistCmd.AddCommand(setlistInsertCmd)
	setlistCmd.AddCommand(setlistSearchCmd)
	setlistCmd.AddCommand(setlistShowCmd)
	rootCmd.AddCommand(setlistCmd)

	scoresCmd.AddCommand(scoresSearchCmd)
	scoresCmd.AddCommand(scoresShowCmd)
	scoresCmd.AddCommand(scoresDownloadCmd)
	scoresDownloadCmd.Flags().StringP("directory", "d", "", "directory to drop the file (default: current directory)")
	scoresDownloadCmd.Flags().StringP("output", "o", "", "exact output path (including filename, default: <song name>.pdf)")
	rootCmd.AddCommand(scoresCmd)

	// mcp server command (AS + RS)
	mcpCmd.Flags().Int("port", 8080, "TCP port to listen on")
	mcpCmd.Flags().String("host", "0.0.0.0", "host address to bind (use 127.0.0.1 to restrict to local)")
	mcpCmd.Flags().String("base-url", "", "canonical public base URL used in OAuth metadata, authorize redirects, JWT iss/aud, and resource identifiers (e.g. https://imslp-mcp.example.com). If not set, falls back to APP_BASE_URL env var, then http://localhost:PORT.")
	mcpCmd.Flags().String("jwt-secret", "", "HMAC secret for signing/verifying the issued JWTs (long random string). Falls back to IMSLP_MCP_JWT_SECRET env var, then the file specified by --jwt-secret-file.")
	mcpCmd.Flags().String("jwt-secret-file", "mcp-jwt-secret.key", "path to file for the persistent JWT signing secret (HMAC). If --jwt-secret and IMSLP_MCP_JWT_SECRET are unset, the secret is loaded from this file (or a new 32-byte secret is generated and saved here on first boot). This ensures tokens survive server restarts.")
	mcpCmd.Flags().String("clients-file", "mcp-clients.json", "path to JSON file used as persistent store for dynamically registered OAuth clients (via DCR at /register). Clients survive server restarts so in-progress flows don't need to re-register.")
	mcpCmd.Flags().String("sessions-file", "mcp-sessions.json", "path to JSON file used as persistent store for MCP sessions (Mcp-Session-Id to user bindings). Sessions survive server restarts.")
	rootCmd.AddCommand(mcpCmd)
}

// loadOrGenerateJWTSecret returns the secret to use for HMAC-SHA256 JWT signing.
// Priority: --jwt-secret flag > IMSLP_MCP_JWT_SECRET env > file at jwtSecretFile
// (load if exists, else generate 32 random bytes, save atomically with 0600 perms, and return it).
func loadOrGenerateJWTSecret(flagSecret, envSecret, jwtSecretFile string) ([]byte, error) {
	if flagSecret != "" {
		return []byte(flagSecret), nil
	}
	if envSecret != "" {
		return []byte(envSecret), nil
	}

	// Try to load from persistent file
	if data, err := os.ReadFile(jwtSecretFile); err == nil && len(data) >= 16 {
		log.Printf("Loaded persistent JWT secret from %s (tokens will survive restarts)", jwtSecretFile)
		return data, nil
	} else if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to read JWT secret file %s: %w", jwtSecretFile, err)
	}

	// Generate new secret
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("failed to generate JWT secret: %w", err)
	}

	// Atomic write
	tmp := jwtSecretFile + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return nil, fmt.Errorf("failed to write temporary JWT secret file: %w", err)
	}
	if err := os.Rename(tmp, jwtSecretFile); err != nil {
		return nil, fmt.Errorf("failed to install JWT secret file %s: %w", jwtSecretFile, err)
	}

	log.Printf("Generated new persistent JWT secret and saved to %s (use --jwt-secret or IMSLP_MCP_JWT_SECRET to override on future runs)", jwtSecretFile)
	return b, nil
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
