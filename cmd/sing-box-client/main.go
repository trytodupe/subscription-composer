package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/syslog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ttd/subscription-composer/internal/clientupdate"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "sing-box-client:", err)
		if logger, logErr := syslog.New(syslog.LOG_ERR|syslog.LOG_DAEMON, "sing-box-client"); logErr == nil {
			_ = logger.Err(err.Error())
			_ = logger.Close()
		}
		os.Exit(1)
	}
}

func run(args []string, output io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: sing-box-client <fetch|apply|status|rollback> --config PATH [--jitter DURATION]")
	}
	command := args[0]
	switch command {
	case "fetch", "apply", "status", "rollback":
	default:
		return errors.New("unknown command; expected fetch, apply, status, or rollback")
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "/etc/sing-box-client/client.json", "Private client configuration file")
	jitter := flags.Duration("jitter", 0, "Maximum random delay before fetch (for example 5m)")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
		return errors.New("invalid command arguments")
	}
	if *jitter < 0 || (command != "fetch" && *jitter != 0) {
		return errors.New("nonnegative jitter is supported only by fetch")
	}
	cfg, err := clientupdate.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	client, err := clientupdate.New(cfg)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch command {
	case "fetch":
		err = client.Fetch(ctx, time.Duration(*jitter))
	case "apply":
		err = client.Apply(ctx)
	case "rollback":
		err = client.Rollback(ctx)
	}
	if err != nil {
		return err
	}
	state, err := client.Status()
	if err != nil {
		return err
	}
	if json.NewEncoder(output).Encode(state) != nil {
		return errors.New("cannot write status output")
	}
	return nil
}
