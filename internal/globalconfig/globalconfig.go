// Package globalconfig parses /etc/vws/global.yaml, the bootstrap settings
// of the global layer: the IAM etcd, listener addresses, the paths of the
// KEK and the internal mTLS credentials, and the default project. Regions
// and AWS accounts are not in it; operators register them through the admin
// API. Secrets are named by file path, never written inline.
package globalconfig

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"go.yaml.in/yaml/v3"
)

// Config is a parsed global.yaml.
type Config struct {
	IAM            IAM         `yaml:"iam"`
	Listeners      Listeners   `yaml:"listeners"`
	Credentials    Credentials `yaml:"credentials"`
	DefaultProject string      `yaml:"default_project"`
}

// IAM is where vws-iam and the admin registry keep their records.
type IAM struct {
	EtcdEndpoints []string `yaml:"etcd_endpoints"`
	TLS           TLSFiles `yaml:"tls"`
}

// TLSFiles names PEM files. CertFile and KeyFile are set together or not
// at all.
type TLSFiles struct {
	CAFile   string `yaml:"ca_file"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// Listeners are host:port addresses. An empty one keeps its flag default.
type Listeners struct {
	Console string `yaml:"console"`
	EC2     string `yaml:"ec2"`
	S3      string `yaml:"s3"`
	IAM     string `yaml:"iam"`
	Ops     string `yaml:"ops"`
}

// Credentials names the systemd credential files of the global layer.
type Credentials struct {
	KEKFile string   `yaml:"kek_file"`
	MTLS    TLSFiles `yaml:"mtls"`
}

// The kinds of refusal. Every error Parse returns wraps exactly one.
var (
	ErrRegistration = errors.New("regions and AWS accounts are registered through the admin API, not global.yaml")
	ErrInlineSecret = errors.New("a secret is named by an absolute file path, never written inline")
	ErrInvalid      = errors.New("invalid global.yaml")
)

// MaxBytes bounds the file. A bootstrap file is a few hundred bytes.
const MaxBytes = 64 << 10

// registrationKey reports a top-level key for what the admin API registers.
func registrationKey(key string) bool {
	switch strings.ToLower(key) {
	case "region", "regions", "proxmox", "clusters", "account", "accounts", "aws", "aws_accounts":
		return true
	}
	return false
}

// Parse reads one YAML document holding only the bootstrap keys.
func Parse(data []byte) (Config, error) {
	if len(data) > MaxBytes {
		return Config{}, fmt.Errorf("%w: larger than %d bytes", ErrInvalid, MaxBytes)
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return Config{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if err := refuseKeys(&root); err != nil {
		return Config{}, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return Config{}, fmt.Errorf("%w: empty", ErrInvalid)
		}
		return Config{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if err := dec.Decode(&yaml.Node{}); !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("%w: more than one document", ErrInvalid)
	}
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// refuseKeys names a registration or an inline secret before the strict
// decode would only call it an unknown field.
func refuseKeys(root *yaml.Node) error {
	if len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return nil
	}
	top := root.Content[0]
	for i := 0; i+1 < len(top.Content); i += 2 {
		if key := top.Content[i].Value; registrationKey(key) {
			return fmt.Errorf("%w: key %q", ErrRegistration, key)
		}
	}
	return refuseSecretKeys(top, "")
}

func refuseSecretKeys(n *yaml.Node, path string) error {
	if n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		key, value := n.Content[i].Value, n.Content[i+1]
		if value.Kind != yaml.MappingNode && secretKey(key) {
			return fmt.Errorf("%w: key %q", ErrInlineSecret, path+key)
		}
		if err := refuseSecretKeys(value, path+key+"."); err != nil {
			return err
		}
	}
	return nil
}

func secretKey(key string) bool {
	k := strings.ToLower(key)
	if strings.HasSuffix(k, "_file") {
		return false
	}
	for _, word := range []string{"secret", "password", "token", "kek", "key"} {
		if strings.Contains(k, word) {
			return true
		}
	}
	return false
}

func (c Config) validate() error {
	if len(c.IAM.EtcdEndpoints) == 0 {
		return fmt.Errorf("%w: iam.etcd_endpoints is empty", ErrInvalid)
	}
	for _, e := range c.IAM.EtcdEndpoints {
		if err := checkEndpoint(e); err != nil {
			return err
		}
	}
	if c.IAM.TLS.CAFile == "" {
		return fmt.Errorf("%w: iam.tls.ca_file is required", ErrInvalid)
	}
	if c.Credentials.KEKFile == "" {
		return fmt.Errorf("%w: credentials.kek_file is required", ErrInvalid)
	}
	files := []struct{ name, value string }{
		{"iam.tls.ca_file", c.IAM.TLS.CAFile},
		{"iam.tls.cert_file", c.IAM.TLS.CertFile},
		{"iam.tls.key_file", c.IAM.TLS.KeyFile},
		{"credentials.kek_file", c.Credentials.KEKFile},
		{"credentials.mtls.ca_file", c.Credentials.MTLS.CAFile},
		{"credentials.mtls.cert_file", c.Credentials.MTLS.CertFile},
		{"credentials.mtls.key_file", c.Credentials.MTLS.KeyFile},
	}
	for _, f := range files {
		if f.value != "" && !filePath(f.value) {
			return fmt.Errorf("%w: %s", ErrInlineSecret, f.name)
		}
	}
	for name, t := range map[string]TLSFiles{"iam.tls": c.IAM.TLS, "credentials.mtls": c.Credentials.MTLS} {
		if (t.CertFile == "") != (t.KeyFile == "") {
			return fmt.Errorf("%w: %s.cert_file and %s.key_file are set together", ErrInvalid, name, name)
		}
	}
	listeners := []struct{ name, value string }{
		{"console", c.Listeners.Console},
		{"ec2", c.Listeners.EC2},
		{"s3", c.Listeners.S3},
		{"iam", c.Listeners.IAM},
		{"ops", c.Listeners.Ops},
	}
	for _, l := range listeners {
		if l.value != "" && !hostPort(l.value) {
			return fmt.Errorf("%w: listeners.%s %q is not host:port", ErrInvalid, l.name, l.value)
		}
	}
	if !projectName(c.DefaultProject) {
		return fmt.Errorf("%w: default_project %q", ErrInvalid, c.DefaultProject)
	}
	return nil
}

func checkEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: iam.etcd_endpoints holds an entry that is not a URL", ErrInvalid)
	}
	if u.User != nil {
		return fmt.Errorf("%w: iam.etcd_endpoints carries user info", ErrInlineSecret)
	}
	if u.Scheme != "https" || !hostPort(u.Host) || (u.Path != "" && u.Path != "/") ||
		u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%w: iam.etcd_endpoints holds an entry that is not https://host:port", ErrInvalid)
	}
	return nil
}

func filePath(s string) bool {
	return filepath.IsAbs(s) && filepath.Clean(s) == s && !strings.ContainsFunc(s, unicode.IsControl)
}

func hostPort(s string) bool {
	_, port, err := net.SplitHostPort(s)
	if err != nil {
		return false
	}
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n < 65536
}

// projectName follows a Proxmox pool id, which a project maps to.
func projectName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i, r := range s {
		alnum := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
		if !alnum && (i == 0 || r != '-' && r != '_' && r != '.') {
			return false
		}
	}
	return true
}
