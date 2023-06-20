package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/netsys-lab/express-scion-router/topology"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile  string
	topoFile string
	asKey    string
)

var rootCmd = &cobra.Command{
	Use:     "xsr",
	Short:   "eXpress SCION Router",
	Long:    "A fast SCION border router using XDP and P4",
	Example: "xsr --key <AS key> --topo topology.yaml",
	Args:    cobra.NoArgs,
	Run:     runXSR,
}

func main() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "",
		"Configuration file")
	rootCmd.PersistentFlags().StringVarP(&topoFile, "topo", "t", "",
		"AS topology (YAML)")
	rootCmd.PersistentFlags().StringVarP(&asKey, "key", "k", "",
		"base64 encoded AS key")
	viper.BindPFlag("topo", rootCmd.PersistentFlags().Lookup("topo"))
	viper.BindPFlag("key", rootCmd.PersistentFlags().Lookup("key"))
	if err := rootCmd.Execute(); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)

		if err := viper.ReadInConfig(); err != nil {
			fmt.Printf("Error reading config file: %v\n", err)
			os.Exit(1)
		}
	}
}

func runXSR(cmd *cobra.Command, args []string) {
	var wg sync.WaitGroup
	fmt.Println(cmd.Short)

	// Load topology
	if viper.GetString("topo") == "" {
		fmt.Println("Error: No topology file specified")
		os.Exit(1)
	}
	topo, err := topology.LoadTopology(viper.GetString("topo"))
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	// Decode AS key
	if viper.GetString("key") == "" {
		fmt.Println("Error: No AS key specified")
		os.Exit(1)
	}
	key, err := base64.StdEncoding.DecodeString(viper.GetString("key"))
	if err != nil {
		fmt.Println("Error: Invalid AS key")
		os.Exit(1)
	}

	// Stop the router if SIGINT or SIGTERM are received
	ctx, cancel := context.WithCancel(context.Background())
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	wg.Add(1)
	go func() {
		defer signal.Stop(sig)
		defer wg.Done()
		select {
		case <-sig:
			cancel()
		case <-ctx.Done():
		}
	}()

	// Run the router
	r := &DummyRouter{}
	if err = r.Configure(topo, key); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := r.Run(ctx); err != nil {
			fmt.Printf("Error: %v\n", err)
			cancel()
		}
	}()

	wg.Wait()
}
