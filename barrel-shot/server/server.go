package server

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"barrel-shot/share"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

type Config struct {
	Listen    string
	KeyFile   string
	Auth      string
	TLSCert   string
	TLSKey    string
	Backend   string
	KeepAlive time.Duration
	Verbose   bool
}

type Server struct {
	config      *Config
	sshConfig   *ssh.ServerConfig
	fingerprint string
	proxy       *httputil.ReverseProxy
	sessCount   int32
	user, pass  string
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func New(c *Config) (*Server, error) {
	s := &Server{config: c}

	if c.Auth != "" {
		parts := strings.SplitN(c.Auth, ":", 2)
		if len(parts) != 2 || parts[0] == "" {
			return nil, fmt.Errorf("invalid auth, expected user:pass")
		}
		s.user, s.pass = parts[0], parts[1]
	}

	var pemBytes []byte
	var err error
	if c.KeyFile != "" {
		pemBytes, err = os.ReadFile(c.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("read key file: %w", err)
		}
	} else {
		pemBytes, err = share.GenerateKey()
		if err != nil {
			return nil, fmt.Errorf("generate key: %w", err)
		}
	}

	private, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}

	s.fingerprint = share.FingerprintKey(private.PublicKey())

	s.sshConfig = &ssh.ServerConfig{
		ServerVersion: "SSH-2.0-" + share.ProtocolVersion,
	}
	if s.user != "" {
		s.sshConfig.PasswordCallback = s.authUser
	} else {
		s.sshConfig.NoClientAuth = true
	}
	s.sshConfig.AddHostKey(private)

	if c.Backend != "" {
		u, err := url.Parse(c.Backend)
		if err != nil {
			return nil, fmt.Errorf("parse backend: %w", err)
		}
		s.proxy = httputil.NewSingleHostReverseProxy(u)
		s.proxy.Director = func(r *http.Request) {
			r.URL.Scheme = u.Scheme
			r.URL.Host = u.Host
			r.Host = u.Host
		}
	}

	return s, nil
}

func (s *Server) Run(ctx context.Context) error {
	log.Printf("[server] Fingerprint %s", s.fingerprint)

	var tlsConfig *tls.Config
	if s.config.TLSCert != "" && s.config.TLSKey != "" {
		cert, err := tls.LoadX509KeyPair(s.config.TLSCert, s.config.TLSKey)
		if err != nil {
			return fmt.Errorf("load TLS cert: %w", err)
		}
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	} else {
		cert, err := share.GenerateSelfSignedCert()
		if err != nil {
			return fmt.Errorf("generate TLS cert: %w", err)
		}
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	}

	ln, err := net.Listen("tcp", s.config.Listen)
	if err != nil {
		return err
	}
	ln = tls.NewListener(ln, tlsConfig)

	log.Printf("[server] Listening on %s", s.config.Listen)

	srv := &http.Server{Handler: http.HandlerFunc(s.handleHTTP)}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()

	err = srv.Serve(ln)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (s *Server) Fingerprint() string {
	return s.fingerprint
}

func (s *Server) authUser(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	if subtle.ConstantTimeCompare([]byte(s.user), []byte(conn.User())) != 1 ||
		subtle.ConstantTimeCompare([]byte(s.pass), password) != 1 {
		log.Printf("[server] Auth failed: user=%q addr=%s", conn.User(), conn.RemoteAddr())
		return nil, fmt.Errorf("auth failed")
	}
	return nil, nil
}

func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.ToLower(r.Header.Get("Upgrade")) == "websocket" {
		s.handleWebSocket(w, r)
		return
	}
	if s.proxy != nil {
		s.proxy.ServeHTTP(w, r)
		return
	}
	w.WriteHeader(200)
	w.Write([]byte("OK\n"))
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	id := atomic.AddInt32(&s.sessCount, 1)
	remoteAddr := r.RemoteAddr

	wsConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[session#%d] WS upgrade failed: %v", id, err)
		return
	}

	conn := share.NewWSConn(wsConn)

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.sshConfig)
	if err != nil {
		if s.config.Verbose {
			log.Printf("[session#%d] SSH handshake failed: %v", id, err)
		}
		return
	}
	defer sshConn.Close()

	var req *ssh.Request
	select {
	case req = <-reqs:
	case <-time.After(10 * time.Second):
		log.Printf("[session#%d] Config timeout", id)
		return
	}

	if req == nil || req.Type != "config" {
		log.Printf("[session#%d] Expected config request", id)
		return
	}

	cfg, err := share.DecodeConfig(req.Payload)
	if err != nil {
		req.Reply(false, []byte(err.Error()))
		return
	}
	req.Reply(true, nil)

	if s.config.Verbose {
		log.Printf("[+] Agent connected: %s", remoteAddr)
	} else {
		log.Printf("[+] Agent connected")
	}
	for _, rm := range cfg.Remotes {
		if rm.Socks {
			log.Printf("[+] SOCKS5: %s", rm.Local())
		} else {
			log.Printf("[+] Tunnel: %s -> %s", rm.Local(), rm.RemoteAddr())
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		for r := range reqs {
			if r == nil {
				break
			}
			switch r.Type {
			case "ping":
				r.Reply(true, []byte("pong"))
			default:
				if r.WantReply {
					r.Reply(false, nil)
				}
			}
		}
		cancel()
	}()

	go func() {
		for ch := range chans {
			ch.Reject(ssh.Prohibited, "not supported")
		}
	}()

	if s.config.KeepAlive > 0 {
		go s.keepAlive(ctx, sshConn, s.config.KeepAlive)
	}

	var wg sync.WaitGroup
	for _, rm := range cfg.Remotes {
		if !rm.Reverse {
			continue
		}
		wg.Add(1)
		go func(remote *share.Remote) {
			defer wg.Done()
			s.bindReverseTunnel(ctx, id, sshConn, remote)
		}(rm)
	}

	sshConn.Wait()
	cancel()
	wg.Wait()

	if s.config.Verbose {
		log.Printf("[-] Agent disconnected: %s", remoteAddr)
	} else {
		log.Printf("[-] Agent disconnected")
	}
}

func (s *Server) bindReverseTunnel(ctx context.Context, sessID int32, sshConn ssh.Conn, remote *share.Remote) {
	addr := remote.Local()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("[session#%d] Listen failed %s: %v", sessID, addr, err)
		return
	}
	defer ln.Close()

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
			default:
				log.Printf("[session#%d] Accept error %s: %v", sessID, addr, err)
			}
			return
		}
		go s.handleTunnelConn(sshConn, conn, remote)
	}
}

func (s *Server) handleTunnelConn(sshConn ssh.Conn, src net.Conn, remote *share.Remote) {
	defer src.Close()

	chanData := remote.RemoteAddr()
	ch, reqs, err := sshConn.OpenChannel(share.ChannelType, []byte(chanData))
	if err != nil {
		if s.config.Verbose {
			log.Printf("[tunnel] Channel failed -> %s: %v", chanData, err)
		}
		return
	}
	go ssh.DiscardRequests(reqs)

	share.Pipe(src, ch)
}

func (s *Server) keepAlive(ctx context.Context, sshConn ssh.Conn, interval time.Duration) {
	ticker := time.NewTicker(interval)
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
}
