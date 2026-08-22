package agent

import "strings"

// Set at build time via -ldflags:
//
//	-X 'barrel-shot/agent.embeddedServer=wss://operator.com'
//	-X 'barrel-shot/agent.embeddedAuth=op:secret'
//	-X 'barrel-shot/agent.embeddedFingerprint=xK8q3...Ym4='
//	-X 'barrel-shot/agent.embeddedRemotes=R:13389:10.10.5.50:3389,R:socks'
//	-X 'barrel-shot/agent.embeddedTLSSkip=1'
var (
	embeddedServer      string
	embeddedAuth        string
	embeddedFingerprint string
	embeddedRemotes     string
	embeddedTLSSkip     string
	embeddedTrigger     string
)

func HasEmbeddedConfig() bool {
	return embeddedServer != ""
}

func applyEmbedded(c *Config) {
	if c.Server == "" && embeddedServer != "" {
		c.Server = embeddedServer
	}
	if c.Auth == "" && embeddedAuth != "" {
		c.Auth = embeddedAuth
	}
	if c.Fingerprint == "" && embeddedFingerprint != "" {
		c.Fingerprint = embeddedFingerprint
	}
	if len(c.Remotes) == 0 && embeddedRemotes != "" {
		c.Remotes = strings.Split(embeddedRemotes, ",")
	}
	if embeddedTLSSkip == "1" {
		c.TLSSkipVerify = true
	}
}
