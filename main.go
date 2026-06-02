package main

import (
	"encoding/json"
	"fmt"
	"os"

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
	Short: "Sync local state (placeholder - fetches latest items)",
	RunE: func(cmd *cobra.Command, args []string) error {
		client := NewClient()
		if err := client.EnsureAuth(); err != nil {
			return err
		}

		data, err := client.SyncGet(0, 0, 0)
		if err != nil {
			return err
		}
		fmt.Printf("sync.get returned keys: %v\n", keys(data))
		if items, ok := data["items"].([]any); ok {
			fmt.Printf("items count: %d\n", len(items))
		}

		// Persist as per README: simple .json snapshots of the sync data.
		// Later: incremental updates + local mutations + sync.put
		if b, err := json.MarshalIndent(data, "", "  "); err == nil {
			_ = os.WriteFile("sync.json", b, 0644)
			fmt.Println("Wrote sync.json")
		}

		// Separate scores (type 0) and setlists (type 1) for convenience
		var scores, setlists []any
		if items, ok := data["items"].([]any); ok {
			for _, it := range items {
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
		}
		if b, _ := json.MarshalIndent(scores, "", "  "); len(b) > 2 {
			_ = os.WriteFile("scores.json", b, 0644)
			fmt.Printf("Wrote scores.json (%d items)\n", len(scores))
		}
		if b, _ := json.MarshalIndent(setlists, "", "  "); len(b) > 2 {
			_ = os.WriteFile("setlists.json", b, 0644)
			fmt.Printf("Wrote setlists.json (%d items)\n", len(setlists))
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
