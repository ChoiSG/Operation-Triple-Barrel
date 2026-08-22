package agent

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"strings"
	"time"

	"barrel-shot/share"

	"github.com/armon/go-socks5"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

type Config struct {
	Server        string
	Fingerprint   string
	Auth          string
	Remotes       []string
	KeepAlive     time.Duration
	MaxRetry      int
	RetryInterval time.Duration
	Verbose       bool
	TLSSkipVerify bool
}

type Agent struct {
	config      *Config
	remotes     []*share.Remote
	server      string
	socksServer *socks5.Server
}

func New(c *Config) (*Agent, error) {
	applyEmbedded(c)
	if c.Server == "" {
		return nil, fmt.Errorf("server URL required")
	}
	a := &Agent{config: c}
	for _, s := range c.Remotes {
		r, err := share.DecodeRemote(s)
		if err != nil {
			return nil, fmt.Errorf("invalid remote %q: %w", s, err)
		}
		a.remotes = append(a.remotes, r)
	}

	server := c.Server
	if strings.HasPrefix(server, "https://") {
		server = "wss://" + server[8:]
	} else if strings.HasPrefix(server, "http://") {
		server = "ws://" + server[7:]
	} else if !strings.HasPrefix(server, "ws") {
		server = "wss://" + server
	}
	a.server = server

	hasSocks := false
	for _, r := range a.remotes {
		if r.Socks {
			hasSocks = true
			break
		}
	}
	if hasSocks {
		a.socksServer, _ = socks5.New(&socks5.Config{})
	}

	return a, nil
}

func (a *Agent) Run(ctx context.Context) error {
	return a.connectionLoop(ctx)
}

func (a *Agent) connectionLoop(ctx context.Context) error {
	attempt := 0
	interval := a.config.RetryInterval
	if interval <= 0 {
		interval = time.Second
	}
	maxInterval := 5 * time.Minute

	for {
		wasConnected, err := a.connectOnce(ctx)

		if ctx.Err() != nil {
			return nil
		}

		if wasConnected {
			attempt = 0
			interval = a.config.RetryInterval
			if interval <= 0 {
				interval = time.Second
			}
		}

		if err != nil && err != io.EOF {
			if a.config.MaxRetry > 0 {
				log.Printf("[agent] Connection error: %v (attempt %d/%d)", err, attempt+1, a.config.MaxRetry)
			} else {
				log.Printf("[agent] Connection error: %v", err)
			}
		}

		attempt++
		if a.config.MaxRetry > 0 && attempt >= a.config.MaxRetry {
			return fmt.Errorf("max retries (%d) exhausted", a.config.MaxRetry)
		}

		// exponential backoff with jitter (0-30%)
		jitter := time.Duration(float64(interval) * 0.3 * rand.Float64())
		wait := interval + jitter
		log.Printf("[agent] Retrying in %s...", wait.Truncate(time.Millisecond))

		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return nil
		}

		// exponential increase capped at 5m
		interval = interval * 2
		if interval > maxInterval {
			interval = maxInterval
		}
	}
}

func (a *Agent) connectOnce(ctx context.Context) (connected bool, err error) {
	select {
	case <-ctx.Done():
		return false, nil
	default:
	}

	dialer := websocket.Dialer{
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: a.config.TLSSkipVerify},
		HandshakeTimeout: 30 * time.Second,
	}

	log.Printf("[agent] Connecting to %s", a.server)

	wsConn, _, err := dialer.DialContext(ctx, a.server, nil)
	if err != nil {
		return false, fmt.Errorf("dial: %w", err)
	}

	conn := share.NewWSConn(wsConn)

	var user, pass string
	if a.config.Auth != "" {
		parts := strings.SplitN(a.config.Auth, ":", 2)
		if len(parts) == 2 {
			user, pass = parts[0], parts[1]
		}
	}

	sshConfig := &ssh.ClientConfig{
		User:            user,
		ClientVersion:   "SSH-2.0-" + share.ProtocolVersion,
		HostKeyCallback: a.verifyServer,
		Timeout:         30 * time.Second,
	}
	if pass != "" {
		sshConfig.Auth = []ssh.AuthMethod{ssh.Password(pass)}
	}

	t0 := time.Now()
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, "", sshConfig)
	if err != nil {
		return false, fmt.Errorf("ssh: %w", err)
	}
	defer sshConn.Close()

	cfg := share.Config{
		Version: share.ProtocolVersion,
		Remotes: a.remotes,
	}
	_, configErr, err := sshConn.SendRequest("config", true, share.EncodeConfig(cfg))
	if err != nil {
		return false, fmt.Errorf("config: %w", err)
	}
	if len(configErr) > 0 {
		return false, fmt.Errorf("config rejected: %s", configErr)
	}

	log.Printf("[agent] Connected (latency %s)", time.Since(t0).Truncate(time.Millisecond))

	go func() {
		for r := range reqs {
			if r == nil {
				break
			}
			switch r.Type {
			case "ping":
				r.Reply(true, []byte("pong"))
			}
		}
	}()

	if a.config.KeepAlive > 0 {
		go func() {
			ticker := time.NewTicker(a.config.KeepAlive)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					_, _, err := sshConn.SendRequest("ping", true, nil)
					if err != nil {
						sshConn.Close()
						return
					}
				}
			}
		}()
	}

	go func() {
		<-ctx.Done()
		sshConn.Close()
	}()

	for newCh := range chans {
		go a.handleChannel(newCh)
	}

	log.Printf("[agent] Disconnected")
	return time.Since(t0) > 5*time.Second, nil
}

func (a *Agent) verifyServer(hostname string, remote net.Addr, key ssh.PublicKey) error {
	if a.config.Fingerprint == "" {
		return nil
	}
	got := share.FingerprintKey(key)
	if got != a.config.Fingerprint {
		return fmt.Errorf("fingerprint mismatch: got %s", got)
	}
	return nil
}

func (a *Agent) handleChannel(newCh ssh.NewChannel) {
	if newCh.ChannelType() != share.ChannelType {
		newCh.Reject(ssh.UnknownChannelType, "unknown channel type")
		return
	}

	target := string(newCh.ExtraData())

	if target == "socks" {
		a.handleSocksChannel(newCh)
		return
	}

	dst, err := net.DialTimeout("tcp", target, 30*time.Second)
	if err != nil {
		newCh.Reject(ssh.ConnectionFailed, err.Error())
		return
	}

	ch, reqs, err := newCh.Accept()
	if err != nil {
		dst.Close()
		return
	}
	go ssh.DiscardRequests(reqs)

	if a.config.Verbose {
		log.Printf("[agent] Tunnel -> %s", target)
	}

	share.Pipe(ch, dst)
}

func (a *Agent) handleSocksChannel(newCh ssh.NewChannel) {
	if a.socksServer == nil {
		newCh.Reject(ssh.Prohibited, "SOCKS5 not enabled")
		return
	}

	ch, reqs, err := newCh.Accept()
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)

	a.socksServer.ServeConn(share.NewRWCConn(ch))
}
