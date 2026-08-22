package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"barrel-shot/agent"
	"barrel-shot/server"
	"barrel-shot/share"
)

func main() {
	log.SetFlags(0)

	if len(os.Args) < 2 {
		usage()
		os.Exit(0)
	}

	switch os.Args[1] {
	case "server":
		runServer(os.Args[2:])
	case "agent":
		runAgent(os.Args[2:])
	case "keygen":
		runKeygen(os.Args[2:])
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Println(`barrel-shot - RDP/SSH tunneling tool

Usage: barrel-shot <command> [options]

Commands:
  server    Start tunnel server (operator side)
  agent     Connect to server (target side)
  keygen    Generate SSH key pair`)
}

func runServer(args []string) {
	flags := flag.NewFlagSet("server", flag.ExitOnError)
	c := &server.Config{}
	flags.StringVar(&c.Listen, "l", "0.0.0.0:443", "Listen address")
	flags.StringVar(&c.Listen, "listen", "0.0.0.0:443", "Listen address")
	flags.StringVar(&c.KeyFile, "keyfile", "", "SSH private key file")
	flags.StringVar(&c.Auth, "auth", "", "Required agent auth <user:pass>")
	flags.StringVar(&c.TLSCert, "tls-cert", "", "TLS certificate file")
	flags.StringVar(&c.TLSKey, "tls-key", "", "TLS private key file")
	flags.StringVar(&c.Backend, "backend", "", "Reverse proxy non-agent HTTP")
	flags.DurationVar(&c.KeepAlive, "keepalive", 15*time.Second, "Keepalive interval")
	flags.BoolVar(&c.Verbose, "v", false, "Verbose logging")
	flags.Parse(args)

	s, err := server.New(c)
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	if err := s.Run(ctx); err != nil {
		log.Fatal(err)
	}
}

func runAgent(args []string) {
	flags := flag.NewFlagSet("agent", flag.ExitOnError)
	c := &agent.Config{}
	flags.StringVar(&c.Fingerprint, "fingerprint", "", "Server SSH fingerprint")
	flags.StringVar(&c.Auth, "auth", "", "Auth credentials <user:pass>")
	flags.DurationVar(&c.KeepAlive, "keepalive", 15*time.Second, "Keepalive interval")
	flags.IntVar(&c.MaxRetry, "max-retry", 0, "Max reconnect attempts (0=unlimited)")
	flags.DurationVar(&c.RetryInterval, "retry-interval", time.Second, "Base reconnect interval")
	flags.BoolVar(&c.Verbose, "v", false, "Verbose logging")
	flags.BoolVar(&c.TLSSkipVerify, "tls-skip-verify", false, "Skip TLS cert verification")
	flags.Parse(args)

	remaining := flags.Args()
	if len(remaining) >= 2 {
		c.Server = remaining[0]
		c.Remotes = remaining[1:]
	} else if len(remaining) == 1 {
		c.Server = remaining[0]
	} else if !agent.HasEmbeddedConfig() {
		fmt.Println("Usage: barrel-shot agent [flags] <server-url> <remotes...>")
		os.Exit(1)
	}

	a, err := agent.New(c)
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	if err := a.Run(ctx); err != nil {
		log.Fatal(err)
	}
}

func runKeygen(args []string) {
	flags := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := flags.String("o", "", "Output key file")
	flags.Parse(args)

	if *out == "" {
		*out = "-"
	}

	fp, err := share.GenerateKeyFile(*out)
	if err != nil {
		log.Fatal(err)
	}

	if *out != "-" {
		fmt.Printf("Fingerprint: %s\n", fp)
	}
}
