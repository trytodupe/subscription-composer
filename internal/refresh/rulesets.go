package refresh

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/ttd/subscription-composer/internal/model"
	"github.com/ttd/subscription-composer/internal/rulesets"
)

// Inline rule sets after composition so device-specific base sets are included.
func inlineRuleSets(ctx context.Context, config []byte, prior map[string]rulesets.Cache, binary string) ([]byte, map[string]rulesets.Cache, []model.SourceStatus, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(config, &root); err != nil {
		return nil, nil, nil, errors.New("invalid compiled config")
	}
	var route map[string]json.RawMessage
	if err := json.Unmarshal(root["route"], &route); err != nil {
		return nil, nil, nil, errors.New("invalid compiled route")
	}
	var entries []json.RawMessage
	if raw, ok := route["rule_set"]; ok {
		if err := json.Unmarshal(raw, &entries); err != nil {
			return nil, nil, nil, errors.New("invalid compiled rule sets")
		}
	}
	resolved, next, statuses, err := rulesets.Resolve(ctx, entries, prior, binary)
	if err != nil {
		return nil, nil, statuses, err
	}
	if len(entries) == 0 {
		return config, next, statuses, nil
	}
	route["rule_set"], err = json.Marshal(resolved)
	if err != nil {
		return nil, nil, statuses, errors.New("cannot encode inline rule sets")
	}
	root["route"], err = json.Marshal(route)
	if err != nil {
		return nil, nil, statuses, errors.New("cannot encode inline route")
	}
	result, err := json.Marshal(root)
	if err != nil {
		return nil, nil, statuses, errors.New("cannot encode inline config")
	}
	return result, next, statuses, nil
}
