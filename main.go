package main

import (
	"encoding/json"
	"fmt"
	"os"

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

func init() {
	loginCmd.Flags().StringP("username", "u", "", "IMSLP username or email (falls back to IMSLP_USERNAME env)")
	loginCmd.Flags().StringP("password", "p", "", "IMSLP password (falls back to IMSLP_PASSWORD env)")

	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(whoamiCmd)
	rootCmd.AddCommand(syncCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
