package clientupdate

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Exercise actual sing-box merge/schema validation on both migration directions.
// OpenRC remains simulated so this test never changes a host service.
func TestNativeAPIMigrationPairValidation(t *testing.T) {
	binary := os.Getenv("SUBCOMPOSE_SING_BOX")
	if binary == "" {
		t.Skip("set SUBCOMPOSE_SING_BOX to a sing-box 1.14 executable")
	}
	for _, present := range []bool{false, true} {
		for _, failRestart := range []bool{false, true} {
			name := "initial"
			if present {
				name = "existing"
			}
			if failRestart {
				name += "/failed-restart"
			} else {
				name += "/success"
			}
			t.Run(name, func(t *testing.T) {
				c := fixture(t)
				c.cfg.SingBoxBinary = binary
				if err := os.Mkdir(c.cfg.WorkDir, 0700); err != nil {
					t.Fatal(err)
				}
				old := `{"outbounds":[{"type":"direct","tag":"direct"}]}`
				if present {
					writeFile(t, c.cfg.SubscriptionFile, old)
				}
				writeFile(t, c.path("candidate.json"), apiSubscription)
				restarts, nativeChecks := 0, 0
				c.run = func(ctx context.Context, executable string, args ...string) error {
					if executable == binary {
						nativeChecks++
						return exec.CommandContext(ctx, executable, args...).Run()
					}
					if executable == c.cfg.RCServiceBinary && args[1] == "restart" {
						restarts++
						if failRestart && restarts == 1 {
							return errors.New("simulated OpenRC restart failure")
						}
					}
					return nil
				}
				err := c.Apply(context.Background())
				if failRestart {
					if err == nil || !strings.Contains(err.Error(), "previous configuration restored") {
						t.Fatalf("native migration recovery failed: %v", err)
					}
				} else {
					if err != nil {
						t.Fatal(err)
					}
					local, err := readRegular(c.cfg.LocalFile)
					if err != nil {
						t.Fatal(err)
					}
					assertProjectedLocal(t, local)
					if err := c.Rollback(context.Background()); err != nil {
						t.Fatal(err)
					}
				}
				assertFile(t, c.cfg.LocalFile, localConfig)
				if present {
					assertFile(t, c.cfg.SubscriptionFile, old)
				} else if _, err := os.Stat(c.cfg.SubscriptionFile); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("native recovery did not restore subscription absence")
				}
				if nativeChecks < 3 || restarts != 2 || stateOf(t, c).Transaction {
					t.Fatal("native migration/recovery did not complete")
				}
			})
		}
	}
}
