package compose

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ttd/subscription-composer/internal/model"
)

func TestRejectEmptyDirectDNSDetourBeforePublishing(t *testing.T) {
	device, _, nodes := fixture()
	device.Base = json.RawMessage(`{"outbounds":[{"type":"direct","tag":"direct"}],"dns":{"servers":[{"type":"udp","tag":"bootstrap","server":"223.5.5.5","detour":"direct"}]}}`)
	_, err := Build(device, model.Policy{}, nodes)
	if err == nil || !strings.Contains(err.Error(), "empty direct") {
		t.Fatalf("expected actionable startup validation for empty direct DNS detour, got %v", err)
	}
}

func TestAllowDNSDetourWithConfiguredDirectDialer(t *testing.T) {
	device, _, nodes := fixture()
	device.Base = json.RawMessage(`{"outbounds":[{"type":"direct","tag":"bound","bind_interface":"en0"}],"dns":{"servers":[{"type":"udp","tag":"bootstrap","server":"223.5.5.5","detour":"bound"}]}}`)
	if _, err := Build(device, model.Policy{}, nodes); err != nil {
		t.Fatal(err)
	}
}
