package share

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type Remote struct {
	LocalHost  string `json:"lh,omitempty"`
	LocalPort  string `json:"lp,omitempty"`
	RemoteHost string `json:"rh,omitempty"`
	RemotePort string `json:"rp,omitempty"`
	Reverse    bool   `json:"rev,omitempty"`
	Socks      bool   `json:"socks,omitempty"`
}

type Config struct {
	Version string    `json:"v"`
	Remotes []*Remote `json:"r"`
}

func EncodeConfig(c Config) []byte {
	b, _ := json.Marshal(c)
	return b
}

func DecodeConfig(b []byte) (*Config, error) {
	c := &Config{}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, errors.New("invalid config")
	}
	return c, nil
}

func DecodeRemote(s string) (*Remote, error) {
	r := &Remote{}
	if strings.HasPrefix(s, "R:") {
		r.Reverse = true
		s = s[2:]
	}
	if s == "socks" {
		r.Socks = true
		r.LocalHost = "127.0.0.1"
		r.LocalPort = "1080"
		return r, nil
	}
	parts := strings.Split(s, ":")
	if len(parts) == 2 && parts[1] == "socks" {
		r.Socks = true
		r.LocalHost = "0.0.0.0"
		r.LocalPort = parts[0]
		return r, nil
	}
	switch len(parts) {
	case 3:
		if !isPort(parts[0]) || !isPort(parts[2]) {
			return nil, fmt.Errorf("invalid port in remote: %s", s)
		}
		r.LocalHost = "0.0.0.0"
		r.LocalPort = parts[0]
		r.RemoteHost = parts[1]
		r.RemotePort = parts[2]
	case 4:
		if !isPort(parts[1]) || !isPort(parts[3]) {
			return nil, fmt.Errorf("invalid port in remote: %s", s)
		}
		r.LocalHost = parts[0]
		r.LocalPort = parts[1]
		r.RemoteHost = parts[2]
		r.RemotePort = parts[3]
	default:
		return nil, fmt.Errorf("invalid remote: %s", s)
	}
	return r, nil
}

func (r *Remote) String() string {
	sb := &strings.Builder{}
	if r.Reverse {
		sb.WriteString("R:")
	}
	if r.Socks {
		if r.LocalPort != "1080" {
			fmt.Fprintf(sb, "%s:socks", r.LocalPort)
		} else {
			sb.WriteString("socks")
		}
		return sb.String()
	}
	fmt.Fprintf(sb, "%s:%s:%s:%s", r.LocalHost, r.LocalPort, r.RemoteHost, r.RemotePort)
	return sb.String()
}

func (r *Remote) Local() string {
	return r.LocalHost + ":" + r.LocalPort
}

func (r *Remote) RemoteAddr() string {
	if r.Socks {
		return "socks"
	}
	return r.RemoteHost + ":" + r.RemotePort
}

func isPort(s string) bool {
	n, err := strconv.Atoi(s)
	return err == nil && n > 0 && n <= 65535
}
