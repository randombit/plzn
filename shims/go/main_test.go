package main

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

func framedRequest(payload []byte, replySize uint32) []byte {
	request := make([]byte, appHeaderSize+len(payload))
	copy(request, appMagic)
	binary.BigEndian.PutUint32(request[4:8], uint32(len(request)))
	binary.BigEndian.PutUint32(request[8:12], replySize)
	copy(request[appHeaderSize:], payload)
	return request
}

func TestAppResponderBuffersFragmentedRequests(t *testing.T) {
	request := framedRequest([]byte("fragmented"), 37)
	var responder appResponder
	if got := responder.receive(request[:5]); len(got) != 0 {
		t.Fatalf("partial header produced %d replies", len(got))
	}
	if got := responder.receive(request[5 : len(request)-2]); len(got) != 0 {
		t.Fatalf("partial body produced %d replies", len(got))
	}
	got := responder.receive(request[len(request)-2:])
	if len(got) != 1 || len(got[0]) != 37 {
		t.Fatalf("got reply lengths %#v, want one 37-byte reply", replyLengths(got))
	}
	if want := randomReply(request, 37); !equalBytes(got[0], want) {
		t.Fatal("reply is not the deterministic protocol response")
	}
}

func TestAppResponderHandlesCoalescedAndLegacyData(t *testing.T) {
	one := framedRequest([]byte("one"), 4)
	two := framedRequest([]byte("two"), 7)
	var responder appResponder
	got := responder.receive(append(one, two...))
	if len(got) != 2 || len(got[0]) != 4 || len(got[1]) != 7 {
		t.Fatalf("got reply lengths %#v", replyLengths(got))
	}

	legacy := []byte("ordinary application data")
	got = responder.receive(legacy)
	if len(got) != 1 || !equalBytes(got[0], legacy) {
		t.Fatalf("legacy data was not echoed: %q", got)
	}
}

func TestPreflightRejectsUnenforceableTLS13CipherPolicy(t *testing.T) {
	version := uint16(0x0304)
	cfg := config{
		Role:         "server",
		Protocol:     "tls",
		Runner:       endpoint{Port: 443},
		MinVersion:   &version,
		MaxVersion:   &version,
		CipherSuites: []uint16{0x1301},
		AppData:      appDataConfig{Mode: "echo"},
	}
	err := preflight(&cfg)
	var shimErr *shimError
	if !errors.As(err, &shimErr) || shimErr.result != resultUnsupportedConfig {
		t.Fatalf("preflight error = %#v, want unsupported_config", err)
	}
}

func TestPreflightAcceptsBaselineTLS(t *testing.T) {
	version := uint16(0x0303)
	cfg := config{
		Role:       "client",
		Protocol:   "tls",
		Runner:     endpoint{Port: 443},
		MinVersion: &version,
		MaxVersion: &version,
		Curves:     []uint16{23, 29},
		AppData:    appDataConfig{Mode: "echo"},
	}
	if err := preflight(&cfg); err != nil {
		t.Fatalf("baseline TLS rejected: %v", err)
	}
}

func TestPreflightRejectsStatefulSessionIDResumption(t *testing.T) {
	cfg := config{
		Role: "server", Protocol: "tls", Runner: endpoint{Port: 443},
		AppData:  appDataConfig{Mode: "echo"},
		Requires: requiresConfig{SessionIDResumption: true},
	}
	err := preflight(&cfg)
	var shimErr *shimError
	if !errors.As(err, &shimErr) || shimErr.result != resultUnsupportedConfig || !strings.Contains(shimErr.detail, "session_id_resumption") {
		t.Fatalf("preflight error = %#v, want unsupported session-ID resumption", err)
	}
}

func TestPreflightSessionTicketCount(t *testing.T) {
	version := uint16(0x0304)
	one := uint32(1)
	cfg := config{
		Role:           "server",
		Protocol:       "tls",
		Runner:         endpoint{Port: 443},
		MinVersion:     &version,
		MaxVersion:     &version,
		SessionTickets: &one,
		AppData:        appDataConfig{Mode: "echo"},
	}

	if err := preflight(&cfg); err != nil {
		t.Fatalf("one session ticket rejected: %v", err)
	}

	two := uint32(2)
	cfg.SessionTickets = &two
	err := preflight(&cfg)
	var shimErr *shimError
	if !errors.As(err, &shimErr) || shimErr.result != resultUnsupportedConfig || !strings.Contains(shimErr.detail, "uut.session_tickets") {
		t.Fatalf("preflight error = %#v, want unsupported_config for session_tickets", err)
	}
}

func replyLengths(replies [][]byte) []int {
	lengths := make([]int, len(replies))
	for i := range replies {
		lengths[i] = len(replies[i])
	}
	return lengths
}
