package main

import (
	"fmt"
	"os"
	"text/tabwriter"
	"user-space/pkg/engine"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "ai-ida",
	Short: "AI-IDA — High-Performance Kernel Network Defense Subsystem",
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show real-time firewall status, protected adapters, and kernel errors",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("🛡️  AI-IDA Defensive Architecture — Subsystem Status")
		fmt.Println("==================================================")

		interfaces, err := engine.InspectInterfaces()
		if err != nil {
			fmt.Printf("❌ [Error] Failed to inspect network adapters: %v\n", err)
			return
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "INTERFACE\tINDEX\tSTATE\tPROTECTION\tXDP MODE\tPROG ID")
		fmt.Fprintln(w, "---------\t-----\t-----\t----------\t--------\t-------")

		for _, iface := range interfaces {
			shield := "🔴 INACTIVE"
			if iface.IsProtected {
				shield = "🟢 SHIELDED"
			}
			fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%d\n",
				iface.Name, iface.Index, iface.OperState, shield, iface.XdpMode, iface.ProgramID)
		}
		w.Flush()
		fmt.Println()
	},
}

var blockCmd = &cobra.Command{
	Use:   "block [IP or CIDR]",
	Short: "Instantly drop traffic from an IP or CIDR via kernel LPM_TRIE",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cidr := args[0]
		mgr, err := engine.LoadPinnedMaps()
		if err != nil {
			fmt.Printf("❌ [Error] %v\n", err)
			return
		}
		defer mgr.Close()

		if err := mgr.BlockIP(cidr); err != nil {
			fmt.Printf("❌ Failed to block target %s: %v\n", cidr, err)
			return
		}

		fmt.Printf("⛔ [AI-IDA] Successfully blacklisted '%s' in kernel data plane.\n", cidr)
	},
}

var portCmd = &cobra.Command{
	Use:   "port [block|unblock] [port_number]",
	Short: "Block or unblock a Layer-4 port in real-time",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		action := args[0]
		var port uint16
		if _, err := fmt.Sscanf(args[1], "%d", &port); err != nil {
			fmt.Printf("❌ Invalid port number: %v\n", args[1])
			return
		}

		mgr, err := engine.LoadPinnedMaps()
		if err != nil {
			fmt.Printf("❌ [Error] %v\n", err)
			return
		}
		defer mgr.Close()

		if action == "block" {
			if err := mgr.BlockPort(port); err != nil {
				fmt.Printf("❌ Failed to block port %d: %v\n", port, err)
				return
			}
			fmt.Printf("⛔ [AI-IDA] Port %d has been BLOCKED in kernel data plane.\n", port)
		} else if action == "unblock" {
			if err := mgr.UnblockPort(port); err != nil {
				fmt.Printf("❌ Failed to unblock port %d: %v\n", port, err)
				return
			}
			fmt.Printf("✅ [AI-IDA] Port %d has been UNBLOCKED.\n", port)
		}
	},
}

func main() {
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(blockCmd)
	rootCmd.AddCommand(portCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}