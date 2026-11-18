package clientupdate

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Config describes this machine's subscription and OpenRC deployment.
// HealthAddress is a TCP listener probe, not an authenticated API check.
type Config struct {
	SubscriptionURL  string `json:"subscription_url"`
	Username         string `json:"username"`
	TokenFile        string `json:"token_file"`
	StateDir         string `json:"state_dir"`
	ConfigDir        string `json:"config_dir"`
	LocalFile        string `json:"local_file"`
	SubscriptionFile string `json:"subscription_file"`
	WorkDir          string `json:"work_dir"`
	SingBoxBinary    string `json:"sing_box_binary"`
	RCServiceBinary  string `json:"rc_service_binary"`
	ServiceName      string `json:"service_name"`
	HealthAddress    string `json:"health_address"`
}

func LoadConfig(path string) (Config, error) {
	var cfg Config
	data, err := readPrivate(path)
	if err != nil {
		return cfg, errors.New("cannot read private client configuration")
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, errors.New("invalid client configuration")
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return cfg, errors.New("invalid client configuration")
	}
	return cfg, cfg.validate()
}

func (c Config) validate() error {
	for _, path := range []string{c.TokenFile, c.StateDir, c.ConfigDir, c.LocalFile, c.SubscriptionFile, c.WorkDir, c.SingBoxBinary, c.RCServiceBinary} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return errors.New("configuration paths must be absolute and clean")
		}
	}
	if filepath.Dir(c.LocalFile) != c.ConfigDir || filepath.Dir(c.SubscriptionFile) != c.ConfigDir || c.LocalFile == c.SubscriptionFile {
		return errors.New("local_file and subscription_file must be distinct files directly under config_dir")
	}
	if !strings.HasSuffix(c.LocalFile, ".json") || !strings.HasSuffix(c.SubscriptionFile, ".json") {
		return errors.New("local_file and subscription_file must end in .json")
	}
	// Native checks use local then subscription, matching the daemon's sorted -C inputs.
	if c.LocalFile > c.SubscriptionFile {
		return errors.New("local_file must sort before subscription_file in config_dir")
	}
	if c.StateDir == c.ConfigDir || strings.HasPrefix(c.StateDir, c.ConfigDir+string(filepath.Separator)) {
		return errors.New("state_dir must be outside config_dir")
	}
	for _, path := range []string{c.TokenFile, c.SingBoxBinary, c.RCServiceBinary} {
		if path == c.LocalFile || path == c.SubscriptionFile || strings.HasPrefix(path, c.StateDir+string(filepath.Separator)) {
			return errors.New("credential and executable paths must not overlap managed files")
		}
	}
	u, err := url.Parse(c.SubscriptionURL)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return errors.New("invalid subscription URL")
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "https" && !(u.Scheme == "http" && ip != nil && ip.IsLoopback()) {
		return errors.New("subscription URL requires HTTPS (HTTP is allowed only for loopback IPs)")
	}
	if c.Username == "" || strings.ContainsAny(c.Username, ":\r\n") {
		return errors.New("invalid subscription username")
	}
	if c.ServiceName == "" || strings.HasPrefix(c.ServiceName, "-") || strings.ContainsAny(c.ServiceName, "/ \t\r\n") {
		return errors.New("invalid OpenRC service name")
	}
	host, port, err := net.SplitHostPort(c.HealthAddress)
	n, portErr := strconv.Atoi(port)
	if err != nil || host == "" || portErr != nil || n < 1 || n > 65535 {
		return errors.New("health_address must be a host:port TCP address")
	}
	if address, err := netip.ParseAddr(host); err == nil && address.Unmap().IsUnspecified() {
		return errors.New("health_address must not use a wildcard host")
	}
	return nil
}

func readRegular(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("expected a regular file")
	}
	return os.ReadFile(path)
}

func readPrivate(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("expected a private regular file")
	}
	return os.ReadFile(path)
}
