package model

import "encoding/json"

// Config keeps service settings separate from native sing-box rules.
type Config struct {
	Listen         string   `json:"listen"`
	SnapshotDir    string   `json:"snapshot_dir"`
	RefreshTimeout string   `json:"refresh_timeout"`
	Debounce       string   `json:"debounce"`
	CheckBinary    string   `json:"check_binary,omitempty"`
	Sources        []Source `json:"sources"`
	Policy         Policy   `json:"policy"`
	Devices        []Device `json:"devices"`
}

type Source struct {
	ID      string            `json:"id"`
	Type    string            `json:"type,omitempty"`
	URL     string            `json:"url,omitempty"`
	File    string            `json:"file,omitempty"`
	Format  string            `json:"format,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

type Policy struct {
	CountryOverrides map[string]string `json:"country_overrides,omitempty"`
	RegionalDomains  []string          `json:"regional_domains,omitempty"`
	DirectDomains    []string          `json:"direct_domains,omitempty"`
	DirectCIDRs      []string          `json:"direct_cidrs,omitempty"`
	Rules            []json.RawMessage `json:"rules,omitempty"`
	RuleSets         []json.RawMessage `json:"rule_sets,omitempty"`
	DirectRuleSets   []string          `json:"direct_rule_sets,omitempty"`
	TestURL          string            `json:"test_url,omitempty"`
	TestInterval     string            `json:"test_interval,omitempty"`
}

type Device struct {
	ID       string          `json:"id"`
	Platform string          `json:"platform"`
	Token    string          `json:"token"`
	Base     json.RawMessage `json:"base"`
}

type Node struct {
	Provider    string
	Name        string
	Tag         string
	Country     string
	Outbound    map[string]any
	DNSResolver *DNSServer
}

// DNSServer describes a source-provided resolver for a node's server hostname.
// Bootstrap and tags are assigned per device during composition.
type DNSServer struct {
	Type       string `json:"type"`
	Server     string `json:"server"`
	ServerPort uint16 `json:"server_port,omitempty"`
	Path       string `json:"path,omitempty"`
}

type SourceStatus struct {
	ID          string `json:"id"`
	CheckedAt   string `json:"checked_at,omitempty"`
	SucceededAt string `json:"succeeded_at,omitempty"`
	ChangedAt   string `json:"changed_at,omitempty"`
	Stale       bool   `json:"stale"`
	Error       string `json:"error,omitempty"`
	NodeCount   int    `json:"node_count"`
}

type Status struct {
	CheckedAt   string         `json:"checked_at,omitempty"`
	PublishedAt string         `json:"published_at,omitempty"`
	Revision    string         `json:"revision,omitempty"`
	LastError   string         `json:"last_error,omitempty"`
	Sources     []SourceStatus `json:"sources"`
}
