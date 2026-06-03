package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/joho/godotenv"
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
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tNAME\tITEMS")
		for _, l := range lists {
			if m, ok := l.(map[string]any); ok {
				data := getMap(m, "data")
				id := getString(m, "itemId")
				name := getString(data, "name")
				n := len(getAnySlice(data, "items"))
				fmt.Fprintf(w, "%s\t%s\t%d\n", id, name, n)
			}
		}
		w.Flush()
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
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tTITLE")
		for _, sidIface := range scoreIDs {
			sid := fmt.Sprintf("%v", sidIface)
			title := scoreTitles[sid]
			if title == "" {
				title = "(not found / deleted?)"
			}
			fmt.Fprintf(w, "%s\t%s\n", sid, title)
		}
		w.Flush()
		return nil
	},
}

var scoresCmd = &cobra.Command{
	Use:   "scores",
	Short: "Commands for searching scores in your library",
}

var scoresSearchCmd = &cobra.Command{
	Use:   "search <query>",
	Short: "Search scores (by Work Title or other info), prints ID and Work Title",
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
		for _, r := range results {
			fmt.Printf("%s\t%s\n", r.ID, r.Title)
		}
		if len(results) == 0 {
			fmt.Println("no matches")
		}
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
		allItems, _, _, _, err := client.FetchCurrentState()
		if err != nil {
			return err
		}
		var matches []map[string]any
		// heuristic: looks like ID if contains '-' with left ~13 digits, right 16 alphanum
		parts := strings.Split(ref, "-")
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
			if looksLikeID && sid == ref {
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
				if title != "" && title == ref {
					matches = append(matches, it)
				}
			}
		}
		if len(matches) == 0 {
			return fmt.Errorf("no score found for %q (use `scores search %q` to find IDs)", ref, ref)
		}
		if len(matches) > 1 {
			fmt.Printf("Ambiguous name %q, multiple matches (use ID instead):\n", ref)
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
				fmt.Printf("  %s  %s\n", id, title)
			}
			return fmt.Errorf("ambiguous name")
		}
		score := matches[0]
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
			// mylib-only / user-uploaded scores lack downloadURL in the sync data (only fileHash).
			// Construct the stor.imslp.org path from the fileHash (content hash) exactly as
			// the mobile/web clients do: https://stor.../uploads/shared/X/Y/Z/<hash>.pdf
			// Then just do a curl-like GET with the browser headers + loginToken cookie.
			fileHash := getString(custom, "fileHash")
			if fileHash == "" || len(fileHash) < 3 {
				return fmt.Errorf("no downloadURL for this score and no fileHash to synthesize stor PDF URL")
			}
			storURL := fmt.Sprintf("https://stor.imslp.org/uploads/shared/%s/%s/%s/%s.pdf",
				fileHash[0:1], fileHash[1:2], fileHash[2:3], fileHash)
			fmt.Printf("Downloading via constructed stor URL (from fileHash) to %s ...\n", target)
			if err := client.downloadToFile(storURL, target); err != nil {
				return fmt.Errorf("download failed: %w", err)
			}
			fmt.Printf("Downloaded to %s\n", target)
			return nil
		}
		fmt.Printf("Downloading %s to %s ...\n", downloadURL, target)
		if err := client.downloadToFile(downloadURL, target); err != nil {
			return fmt.Errorf("download failed: %w", err)
		}
		fmt.Printf("Downloaded to %s\n", target)
		return nil
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
	scoresCmd.AddCommand(scoresDownloadCmd)
	scoresDownloadCmd.Flags().StringP("directory", "d", "", "directory to drop the file (default: current directory)")
	scoresDownloadCmd.Flags().StringP("output", "o", "", "exact output path (including filename, default: <song name>.pdf)")
	rootCmd.AddCommand(scoresCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
