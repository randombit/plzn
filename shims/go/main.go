// go_tls_shim exposes Go's standard-library crypto/tls implementation through
// the plzn config-file shim protocol.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	resultOK                  = 0
	resultLocalError          = 10
	resultIOError             = 11
	resultHandshakeFailed     = 12
	resultExpectationMismatch = 13
	resultUnexpectedSuccess   = 14
	resultUnsupportedConfig   = 16
)

type endpoint struct {
	Host string `json:"host"`
	Port uint16 `json:"port"`
	IPv6 bool   `json:"ipv6"`
}

type chain struct {
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
	KeyType  string `json:"key_type"`
}

type credentials struct {
	CertFile     string  `json:"cert_file"`
	KeyFile      string  `json:"key_file"`
	TrustFile    string  `json:"trust_file"`
	OCSPFile     string  `json:"ocsp_file"`
	SecondCert   string  `json:"second_cert_file"`
	SecondKey    string  `json:"second_key_file"`
	Chains       []chain `json:"chains"`
	ClientChains []chain `json:"client_chains"`
}

type verifyConfig struct {
	Peer              bool    `json:"peer"`
	RequireClientCert bool    `json:"require_client_cert"`
	RequestClientCert bool    `json:"request_client_cert"`
	Fail              bool    `json:"fail"`
	ExpectPeerCN      *string `json:"expect_peer_subject_cn"`
}

type alpnConfig struct {
	Advertise  []string `json:"advertise"`
	Select     string   `json:"select"`
	SelectFrom []string `json:"select_from"`
	Expect     *string  `json:"expect"`
	Decline    bool     `json:"decline"`
}

type appDataConfig struct {
	Mode          string `json:"mode"`
	Send          string `json:"send"`
	ShimShutsDown bool   `json:"shim_shuts_down"`
}

type keyMaterialConfig struct {
	Connection uint32  `json:"connection"`
	Kind       string  `json:"kind"`
	Label      string  `json:"label"`
	Context    *string `json:"context"`
	Length     uint32  `json:"length"`
}

type expectations struct {
	Version            *uint16 `json:"version"`
	Cipher             *uint16 `json:"cipher"`
	ALPN               *string `json:"alpn"`
	Resumed            *bool   `json:"resumed"`
	HRR                *bool   `json:"hrr"`
	HandshakeError     *string `json:"handshake_error"`
	HandshakeAbandoned bool    `json:"handshake_abandoned"`
}

type requiresConfig struct {
	AnySuite            []uint16 `json:"any_suite"`
	AnyGroup            []uint16 `json:"any_group"`
	VirtualClock        bool     `json:"virtual_clock"`
	DynamicTimeout      bool     `json:"dynamic_timeout"`
	SessionIDResumption bool     `json:"session_id_resumption"`
	ServerKey           []string `json:"server_key"`
}

type pskConfig struct {
	Identity  string `json:"identity"`
	SecretHex string `json:"secret_hex"`
}

type config struct {
	Role               string              `json:"role"`
	Protocol           string              `json:"protocol"`
	Runner             endpoint            `json:"runner"`
	ShimID             uint64              `json:"shim_id"`
	ResumeCount        uint32              `json:"resume_count"`
	MinVersion         *uint16             `json:"min_version"`
	MaxVersion         *uint16             `json:"max_version"`
	ConnectionVersions []uint16            `json:"connection_versions"`
	CipherSuites       []uint16            `json:"cipher_suites"`
	Curves             []uint16            `json:"curves"`
	SigningPrefs       []uint16            `json:"signing_prefs"`
	VerifyPrefs        []uint16            `json:"verify_prefs"`
	ServerName         string              `json:"server_name"`
	ExpectServerName   *string             `json:"expect_server_name"`
	Credentials        credentials         `json:"credentials"`
	Verify             verifyConfig        `json:"verify"`
	ALPN               alpnConfig          `json:"alpn"`
	AppData            appDataConfig       `json:"app_data"`
	KeyMaterial        []keyMaterialConfig `json:"key_material"`
	Expect             expectations        `json:"expect"`
	Requires           requiresConfig      `json:"requires"`
	PSK                pskConfig           `json:"psk"`
	SRTPProfiles       []uint16            `json:"srtp_profiles"`
	ExpectSRTPProfile  *uint16             `json:"expect_srtp_profile"`
	RawPublicKey       bool                `json:"raw_public_key"`
	ServerCertTypes    []uint8             `json:"server_certificate_types"`
	ClientCertTypes    []uint8             `json:"client_certificate_types"`
	CompressCert       bool                `json:"compress_certificate"`
	RenegotiateFreely  bool                `json:"renegotiate_freely"`
	ServerPreference   *bool               `json:"server_preference"`
	Renegotiation      *string             `json:"renegotiation"`
	SessionTickets     *uint32             `json:"session_tickets"`
	MaxEarlyData       *uint32             `json:"max_early_data"`
	EarlyDataSend      uint32              `json:"early_data_send"`
	EarlyDataExpect    uint32              `json:"early_data_expect"`
	ExpectEarlyData    *bool               `json:"expect_early_data_accepted"`
	MaxCertList        *uint32             `json:"max_cert_list"`
	RecordSizeLimit    *uint32             `json:"record_size_limit"`
	RecordsPerKey      *uint32             `json:"records_per_traffic_key"`
	KeyUpdate          bool                `json:"key_update"`
	ExtendedMS         *string             `json:"extended_master_secret"`
	EncryptThenMAC     *bool               `json:"encrypt_then_mac"`
	MiddleboxCompat    *bool               `json:"middlebox_compat"`
	MinKeyUpdateMS     *uint32             `json:"min_key_update_interval_ms"`
	RenegotiateAfter   bool                `json:"renegotiate_after_handshake"`
	HelloRequestAfter  bool                `json:"hello_request_after_app_data"`
	RequireCertOnReneg bool                `json:"require_client_cert_on_renegotiation"`
	HalfRTTData        []string            `json:"half_rtt_data"`
	PostHandshakeAuth  *string             `json:"post_handshake_auth"`
	DTLS               json.RawMessage     `json:"dtls"`
}

type shimError struct {
	result int
	detail string
}

func (e *shimError) Error() string { return e.detail }

func fail(result int, format string, args ...interface{}) error {
	return &shimError{result: result, detail: fmt.Sprintf(format, args...)}
}

func unsupported(knob, why string) error {
	return fail(resultUnsupportedConfig, "uut.%s: %s", knob, why)
}

func resultName(result int) string {
	switch result {
	case resultOK:
		return "ok"
	case resultLocalError:
		return "local_error"
	case resultIOError:
		return "io_error"
	case resultHandshakeFailed:
		return "handshake_failed"
	case resultExpectationMismatch:
		return "expectation_mismatch"
	case resultUnexpectedSuccess:
		return "unexpected_success"
	case resultUnsupportedConfig:
		return "unsupported_config"
	default:
		return "failure"
	}
}

func report(result int, detail string) int {
	detail = strings.ReplaceAll(detail, "\n", "; ")
	fmt.Fprintf(os.Stderr, "PLZN-RESULT case=%s detail=%s\n", resultName(result), detail)
	return result
}

func main() {
	exitWhenOrphaned()
	os.Exit(run(os.Args[1:]))
}

// exitWhenOrphaned exits once the parent plzn runner is gone: a runner killed
// mid-case leaves nothing to read the result, so do not linger.
func exitWhenOrphaned() {
	parent := os.Getppid()
	go func() {
		for {
			time.Sleep(time.Second)
			if os.Getppid() != parent {
				os.Exit(resultIOError)
			}
		}
	}()
}

func run(args []string) int {
	configPath := ""
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--plzn-shim-info":
			fmt.Println(`{"protocol":"plzn-shim","protocol_version":1,"name":"go","expectations":"go-expectations.json"}`)
			return 0
		case (args[i] == "-config" || args[i] == "--config") && i+1 < len(args):
			i++
			configPath = args[i]
		case strings.HasPrefix(args[i], "-config="):
			configPath = strings.TrimPrefix(args[i], "-config=")
		}
	}
	if configPath == "" {
		return report(resultLocalError, "usage: go_tls_shim -config <file.json> | --plzn-shim-info")
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return report(resultLocalError, "config error: "+err.Error())
	}
	var cfg config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return report(resultLocalError, "config error: "+err.Error())
	}
	if cfg.Role == "" {
		cfg.Role = "server"
	}
	if cfg.Protocol == "" {
		cfg.Protocol = "tls"
	}
	if cfg.Runner.Host == "" {
		cfg.Runner.Host = "127.0.0.1"
	}
	if cfg.AppData.Mode == "" {
		cfg.AppData.Mode = "echo"
	}

	if err := preflight(&cfg); err != nil {
		return reportError(err)
	}
	tlsConfig, err := makeTLSConfig(&cfg)
	if err != nil {
		return reportError(err)
	}

	expectFailure := cfg.Expect.HandshakeError != nil
	for i := uint32(0); i <= cfg.ResumeCount; i++ {
		connectionTLSConfig := tlsConfig
		if cfg.Role == "client" && int(i) < len(cfg.ConnectionVersions) {
			connectionTLSConfig = tlsConfig.Clone()
			connectionTLSConfig.MinVersion = cfg.ConnectionVersions[i]
			connectionTLSConfig.MaxVersion = cfg.ConnectionVersions[i]
		}
		err = runConnection(&cfg, connectionTLSConfig, i)
		if err != nil {
			var se *shimError
			if errors.As(err, &se) && (se.result == resultHandshakeFailed || se.result == resultIOError) &&
				(expectFailure || cfg.Expect.HandshakeAbandoned) {
				return report(resultOK, se.detail)
			}
			return reportError(err)
		}
	}
	if expectFailure && !cfg.Expect.HandshakeAbandoned {
		return report(resultUnexpectedSuccess, "expected the flow to fail but it completed")
	}
	return report(resultOK, "")
}

func reportError(err error) int {
	var se *shimError
	if errors.As(err, &se) {
		return report(se.result, se.detail)
	}
	return report(resultLocalError, err.Error())
}

func preflight(cfg *config) error {
	if cfg.Role != "client" && cfg.Role != "server" {
		return fail(resultLocalError, "invalid role %q", cfg.Role)
	}
	if cfg.Protocol != "tls" {
		return unsupported("protocol", "Go crypto/tls does not implement DTLS")
	}
	for _, version := range []*uint16{cfg.MinVersion, cfg.MaxVersion} {
		if version != nil && *version != tls.VersionTLS10 && *version != tls.VersionTLS11 && *version != tls.VersionTLS12 && *version != tls.VersionTLS13 {
			return unsupported("versions", fmt.Sprintf("Go shim does not support 0x%04x", *version))
		}
	}
	if cfg.MinVersion != nil && cfg.MaxVersion != nil && *cfg.MinVersion > *cfg.MaxVersion {
		return fail(resultLocalError, "min_version exceeds max_version")
	}
	if cfg.Runner.Port == 0 {
		return fail(resultLocalError, "runner.port must be non-zero")
	}
	if cfg.AppData.Mode != "echo" && cfg.AppData.Mode != "shim_writes" && cfg.AppData.Mode != "shutdown_only" {
		return fail(resultLocalError, "invalid app_data.mode %q", cfg.AppData.Mode)
	}

	if cfg.Requires.SessionIDResumption {
		return unsupported("session_id_resumption", "Go supports TLS 1.2 ticket resumption, not stateful session-ID resumption")
	}
	supportedSuites := goCipherSuites()
	for _, suite := range cfg.CipherSuites {
		if suite >= 0x1301 && suite <= 0x1303 {
			return unsupported("cipher_suites", "Go does not expose TLS 1.3 cipher-suite configuration")
		}
		if !supportedSuites[suite] {
			return unsupported("cipher_suites", fmt.Sprintf("Go does not implement 0x%04x", suite))
		}
	}
	if len(cfg.Requires.AnySuite) != 0 {
		common := false
		for _, suite := range cfg.Requires.AnySuite {
			if supportedSuites[suite] || (suite >= 0x1301 && suite <= 0x1303) {
				common = true
				break
			}
		}
		if !common {
			return unsupported("peer.capabilities", "Go implements none of the offered cipher suites")
		}
	}

	// Keep this in sync with the public CurveID constants implemented by the
	// linked crypto/tls. Go 1.27 adds the three standardized hybrids and pure
	// ML-KEM-1024; rejecting them here used to discard valid corpus cells before
	// crypto/tls had a chance to negotiate them.
	supportedGroups := map[uint16]bool{
		23: true, 24: true, 25: true, 29: true,
		4587: true, 4588: true, 4589: true, 514: true,
	}
	for _, group := range cfg.Curves {
		if !supportedGroups[group] {
			return unsupported("groups", fmt.Sprintf("Go shim does not expose requested group 0x%04x", group))
		}
	}
	if len(cfg.Requires.AnyGroup) != 0 {
		common := false
		for _, group := range cfg.Requires.AnyGroup {
			if supportedGroups[group] {
				common = true
				break
			}
		}
		if !common {
			return unsupported("peer.capabilities", "Go implements none of the offered groups")
		}
	}
	if len(cfg.SigningPrefs) != 0 || len(cfg.VerifyPrefs) != 0 {
		return unsupported("signature_algorithms", "Go does not expose signature-scheme preference configuration")
	}
	if cfg.PSK.SecretHex != "" {
		return unsupported("psk", "Go crypto/tls has no external PSK API")
	}
	if cfg.RawPublicKey || len(cfg.ServerCertTypes) != 0 || len(cfg.ClientCertTypes) != 0 ||
		cfg.CompressCert || len(cfg.SRTPProfiles) != 0 || cfg.ExpectSRTPProfile != nil {
		return unsupported("extension", "raw public keys, certificate compression, and DTLS-SRTP are not exposed by Go")
	}
	if cfg.Requires.VirtualClock || cfg.Requires.DynamicTimeout || len(cfg.DTLS) != 0 {
		return unsupported("dtls", "Go crypto/tls does not implement DTLS")
	}
	if cfg.Expect.HRR != nil {
		return unsupported("expect.hrr", "Go does not expose whether HelloRetryRequest occurred")
	}
	if cfg.Verify.ExpectPeerCN != nil {
		return unsupported("verify", "peer subject-CN expectations are not wired in the Go shim")
	}
	if cfg.ServerPreference != nil && !*cfg.ServerPreference {
		return unsupported("server_preference", "Go servers always choose by their own preference order")
	}
	if cfg.Renegotiation != nil && *cfg.Renegotiation != "none" {
		return unsupported("renegotiation", "Go servers do not renegotiate and the shim does not enable client renegotiation")
	}
	if cfg.RenegotiateFreely || cfg.RenegotiateAfter || cfg.HelloRequestAfter || cfg.RequireCertOnReneg {
		return unsupported("renegotiation", "the requested renegotiation behavior is not available in Go crypto/tls")
	}
	if cfg.PostHandshakeAuth != nil || len(cfg.HalfRTTData) != 0 {
		return unsupported("post_handshake", "post-handshake authentication and half-RTT writes are not exposed by Go")
	}
	if cfg.SessionTickets != nil && *cfg.SessionTickets > 1 {
		return unsupported("session_tickets", "Go crypto/tls supports zero or one ticket per handshake")
	}
	if cfg.MaxEarlyData != nil || cfg.EarlyDataSend != 0 || cfg.EarlyDataExpect != 0 || cfg.ExpectEarlyData != nil {
		return unsupported("early_data", "Go crypto/tls does not expose TLS 1.3 early data")
	}
	if cfg.RecordSizeLimit != nil {
		return unsupported("record_size_limit", "Go crypto/tls exposes no RFC 8449 record_size_limit policy")
	}
	loadedChains := cfg.Credentials.Chains
	if cfg.Role == "client" {
		loadedChains = cfg.Credentials.ClientChains
	}
	for _, chain := range loadedChains {
		if chain.KeyType == "rsa-pss" {
			return unsupported("credentials", "Go x509 cannot parse an RSA-PSS-restricted PKCS#8 private key")
		}
	}
	if cfg.MaxCertList != nil || cfg.RecordsPerKey != nil || cfg.ExtendedMS != nil ||
		cfg.MiddleboxCompat != nil || cfg.MinKeyUpdateMS != nil {
		return unsupported("policy", "one or more requested TLS policy controls are not exposed by Go")
	}
	if cfg.KeyUpdate {
		return unsupported("key_update", "manual post-handshake KeyUpdate initiation is not exposed by Go crypto/tls")
	}
	if cfg.EncryptThenMAC != nil && *cfg.EncryptThenMAC {
		return unsupported("encrypt_then_mac", "Go does not implement encrypt-then-MAC")
	}
	if len(cfg.Requires.ServerKey) != 0 {
		common := false
		for _, key := range cfg.Requires.ServerKey {
			switch strings.ReplaceAll(strings.ToLower(key), "-", "_") {
			case "rsa", "rsa_2048", "rsa_pss", "ecdsa", "ecdsa_p256", "ecdsa_p384", "ecdsa_p521", "ed25519":
				common = true
			}
		}
		if !common {
			return unsupported("server_key", "Go can verify none of the server certificate key types")
		}
	}
	return nil
}

func goCipherSuites() map[uint16]bool {
	result := make(map[uint16]bool)
	for _, suite := range goCipherSuiteList() {
		result[suite] = true
	}
	return result
}

func goCipherSuiteList() []uint16 {
	var result []uint16
	for _, suite := range tls.CipherSuites() {
		result = append(result, suite.ID)
	}
	for _, suite := range tls.InsecureCipherSuites() {
		result = append(result, suite.ID)
	}
	return result
}

func makeTLSConfig(cfg *config) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS10,
		MaxVersion: tls.VersionTLS13,
		ServerName: cfg.ServerName,
	}
	if cfg.MinVersion != nil {
		tlsCfg.MinVersion = *cfg.MinVersion
	}
	if cfg.MaxVersion != nil {
		tlsCfg.MaxVersion = *cfg.MaxVersion
	}
	if len(cfg.CipherSuites) != 0 {
		tlsCfg.CipherSuites = append([]uint16(nil), cfg.CipherSuites...)
	} else {
		// The shim is a conformance surface, not an application security
		// profile. Make every TLS 1.2 suite crypto/tls still implements
		// reachable; tests constrain the peer offer when they need one.
		tlsCfg.CipherSuites = goCipherSuiteList()
	}
	configuredGroups := cfg.Curves
	if len(configuredGroups) == 0 {
		// Enable implemented groups selected by the corpus even when they are
		// absent from this Go build's evolving default preference set.
		configuredGroups = cfg.Requires.AnyGroup
	}
	for _, group := range configuredGroups {
		tlsCfg.CurvePreferences = append(tlsCfg.CurvePreferences, tls.CurveID(group))
	}
	if cfg.SessionTickets != nil && *cfg.SessionTickets == 0 {
		tlsCfg.SessionTicketsDisabled = true
	}

	if cfg.Role == "server" {
		tlsCfg.NextProtos = serverALPN(cfg)
		certs, err := loadCertificates(cfg.Credentials.Chains, cfg.Credentials)
		if err != nil {
			return nil, fail(resultLocalError, "load server certificate: %v", err)
		}
		tlsCfg.Certificates = certs
		if cfg.Verify.RequireClientCert || cfg.Verify.RequestClientCert || cfg.Verify.Peer {
			roots, err := loadCertPool(cfg.Credentials.TrustFile)
			if err != nil {
				return nil, err
			}
			tlsCfg.ClientCAs = roots
			switch {
			case cfg.Verify.RequireClientCert || cfg.Verify.Peer:
				tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
			case cfg.Credentials.TrustFile != "":
				tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
			default:
				tlsCfg.ClientAuth = tls.RequestClientCert
			}
		}
	} else {
		tlsCfg.NextProtos = append([]string(nil), cfg.ALPN.Advertise...)
		tlsCfg.InsecureSkipVerify = !cfg.Verify.Peer // Test harness mode is explicit in the shim config.
		if cfg.Verify.Peer {
			roots, err := loadCertPool(cfg.Credentials.TrustFile)
			if err != nil {
				return nil, err
			}
			tlsCfg.RootCAs = roots
			if cfg.ServerName == "" {
				return nil, fail(resultLocalError, "verify.peer requires server_name")
			}
		}
		certs, err := loadCertificates(cfg.Credentials.ClientChains, cfg.Credentials)
		if err != nil {
			return nil, fail(resultLocalError, "load client certificate: %v", err)
		}
		tlsCfg.Certificates = certs
		if cfg.SessionTickets == nil || *cfg.SessionTickets != 0 {
			tlsCfg.ClientSessionCache = tls.NewLRUClientSessionCache(int(cfg.ResumeCount) + 1)
		}
	}
	if cfg.Verify.Fail {
		tlsCfg.VerifyConnection = func(tls.ConnectionState) error {
			return errors.New("verification forced to fail by shim config")
		}
	}
	return tlsCfg, nil
}

func serverALPN(cfg *config) []string {
	if cfg.ALPN.Decline {
		return nil
	}
	if len(cfg.ALPN.SelectFrom) != 0 {
		protocols := append([]string(nil), cfg.ALPN.SelectFrom...)
		if cfg.ALPN.Select != "" {
			protocols = append([]string{cfg.ALPN.Select}, protocols...)
		}
		return protocols
	}
	if cfg.ALPN.Select == "" {
		return nil
	}
	return []string{cfg.ALPN.Select}
}

func loadCertificates(chains []chain, legacy credentials) ([]tls.Certificate, error) {
	if len(chains) == 0 && legacy.CertFile != "" {
		chains = append(chains, chain{CertFile: legacy.CertFile, KeyFile: legacy.KeyFile})
		if legacy.SecondCert != "" {
			chains = append(chains, chain{CertFile: legacy.SecondCert, KeyFile: legacy.SecondKey})
		}
	}
	certs := make([]tls.Certificate, 0, len(chains))
	for _, pair := range chains {
		cert, err := tls.LoadX509KeyPair(pair.CertFile, pair.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("%s / %s: %w", pair.CertFile, pair.KeyFile, err)
		}
		if legacy.OCSPFile != "" {
			staple, err := os.ReadFile(legacy.OCSPFile)
			if err != nil {
				return nil, fmt.Errorf("read OCSP staple: %w", err)
			}
			cert.OCSPStaple = staple
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func loadCertPool(path string) (*x509.CertPool, error) {
	if path == "" {
		pool, err := x509.SystemCertPool()
		if err != nil {
			return nil, fail(resultLocalError, "load system trust store: %v", err)
		}
		return pool, nil
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fail(resultLocalError, "read trust file %s: %v", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fail(resultLocalError, "trust file %s contains no PEM certificates", path)
	}
	return pool, nil
}

func runConnection(cfg *config, tlsCfg *tls.Config, connectionIndex uint32) error {
	address := net.JoinHostPort(cfg.Runner.Host, strconv.Itoa(int(cfg.Runner.Port)))
	raw, err := net.Dial("tcp", address)
	if err != nil {
		return fail(resultIOError, "dial runner: %v", err)
	}
	defer raw.Close()
	var shimID [8]byte
	binary.LittleEndian.PutUint64(shimID[:], cfg.ShimID)
	if err := writeAll(raw, shimID[:]); err != nil {
		return fail(resultIOError, "write ShimID: %v", err)
	}

	var conn *tls.Conn
	if cfg.Role == "server" {
		conn = tls.Server(raw, tlsCfg)
	} else {
		conn = tls.Client(raw, tlsCfg)
	}
	if err := conn.Handshake(); err != nil {
		preserveTLSAlert(raw)
		return fail(resultHandshakeFailed, "handshake: %v", err)
	}
	if err := checkExpectations(cfg, conn.ConnectionState()); err != nil {
		return err
	}
	state := conn.ConnectionState()
	for _, request := range cfg.KeyMaterial {
		if request.Connection != connectionIndex {
			continue
		}
		var material []byte
		switch request.Kind {
		case "exporter":
			var context []byte
			if request.Context != nil {
				context = []byte(*request.Context)
			}
			material, err = state.ExportKeyingMaterial(request.Label, context, int(request.Length))
			if err != nil {
				return fail(resultLocalError, "export keying material: %v", err)
			}
		case "tls_unique", "tls_unique_unavailable":
			if request.Kind == "tls_unique_unavailable" {
				if len(state.TLSUnique) != 0 {
					return fail(resultExpectationMismatch, "tls-unique unexpectedly available")
				}
				material = []byte{1}
				break
			}
			if len(state.TLSUnique) == 0 {
				return unsupported("key_material", "Go does not expose tls-unique for this connection")
			}
			material = state.TLSUnique
		default:
			return fail(resultLocalError, "unknown key_material kind %q", request.Kind)
		}
		if err := writeAll(conn, material); err != nil {
			return fail(resultIOError, "write key material: %v", err)
		}
	}
	if err := exchangeApplicationData(cfg, conn); err != nil {
		preserveTLSAlert(raw)
		return err
	}
	_ = conn.Close()
	return nil
}

// crypto/tls writes a fatal alert before returning a TLS protocol error. Closing
// a TCP socket with unread peer data can turn that queued alert into a reset, so
// half-close the write side and briefly drain the peer before the deferred
// close. This gives the runner a deterministic opportunity to receive the
// alert without extending successful connections.
func preserveTLSAlert(raw net.Conn) {
	tcp, ok := raw.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tcp.CloseWrite()
	_ = tcp.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	_, _ = io.Copy(io.Discard, tcp)
}

func checkExpectations(cfg *config, state tls.ConnectionState) error {
	if cfg.Expect.Version != nil && state.Version != *cfg.Expect.Version {
		return fail(resultExpectationMismatch, "version mismatch: expected %d, got %d", *cfg.Expect.Version, state.Version)
	}
	if cfg.Expect.Cipher != nil && state.CipherSuite != *cfg.Expect.Cipher {
		return fail(resultExpectationMismatch, "cipher mismatch: expected 0x%04x, got 0x%04x", *cfg.Expect.Cipher, state.CipherSuite)
	}
	if cfg.Expect.Resumed != nil && state.DidResume != *cfg.Expect.Resumed {
		return fail(resultExpectationMismatch, "session-resumption expectation mismatch: expected %t, got %t", *cfg.Expect.Resumed, state.DidResume)
	}
	expectALPN := cfg.ALPN.Expect
	if expectALPN == nil {
		expectALPN = cfg.Expect.ALPN
	}
	if expectALPN != nil && state.NegotiatedProtocol != *expectALPN {
		return fail(resultExpectationMismatch, "ALPN mismatch: expected %q, got %q", *expectALPN, state.NegotiatedProtocol)
	}
	if cfg.ExpectServerName != nil && state.ServerName != *cfg.ExpectServerName {
		return fail(resultExpectationMismatch, "SNI mismatch: expected %q, got %q", *cfg.ExpectServerName, state.ServerName)
	}
	return nil
}

func exchangeApplicationData(cfg *config, conn *tls.Conn) error {
	if cfg.AppData.ShimShutsDown || cfg.AppData.Mode == "shutdown_only" {
		return nil
	}
	if cfg.AppData.Mode == "shim_writes" {
		if err := writeAll(conn, []byte(cfg.AppData.Send)); err != nil {
			return fail(resultHandshakeFailed, "send application data: %v", err)
		}
		return nil
	}

	responder := appResponder{}
	buf := make([]byte, 18*1024)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			for _, reply := range responder.receive(buf[:n]) {
				if writeErr := writeAll(conn, reply); writeErr != nil {
					return fail(resultHandshakeFailed, "send application data response: %v", writeErr)
				}
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			// crypto/tls reports its own warning-level no_renegotiation alert as
			// a local read error. The peer has already observed the wire alert,
			// so this is a successful refusal rather than a shim self-check
			// failure. Go cannot be configured to accept renegotiation here.
			if strings.Contains(err.Error(), "tls: no renegotiation") {
				return nil
			}
			return fail(resultHandshakeFailed, "receive application data: %v", err)
		}
	}
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) != 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

type appResponder struct {
	pending []byte
}

var appMagic = []byte{'P', 'L', 'Z', 'N'}

const (
	appHeaderSize = 12
	appMaxSize    = 1 << 20
)

func (r *appResponder) receive(data []byte) [][]byte {
	r.pending = append(r.pending, data...)
	var replies [][]byte
	for len(r.pending) != 0 {
		prefix := len(r.pending)
		if prefix > len(appMagic) {
			prefix = len(appMagic)
		}
		if !equalBytes(r.pending[:prefix], appMagic[:prefix]) {
			reply := append([]byte(nil), r.pending...)
			r.pending = r.pending[:0]
			return append(replies, reply)
		}
		if len(r.pending) < appHeaderSize {
			break
		}
		requestSize := int(binary.BigEndian.Uint32(r.pending[4:8]))
		replySize := int(binary.BigEndian.Uint32(r.pending[8:12]))
		if requestSize < appHeaderSize || requestSize > appMaxSize || replySize > appMaxSize {
			reply := append([]byte(nil), r.pending...)
			r.pending = r.pending[:0]
			return append(replies, reply)
		}
		if len(r.pending) < requestSize {
			break
		}
		if replySize != 0 {
			replies = append(replies, randomReply(r.pending[:requestSize], replySize))
		}
		r.pending = r.pending[requestSize:]
	}
	return replies
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func randomReply(request []byte, size int) []byte {
	state := uint64(0xcbf29ce484222325)
	for _, value := range request {
		state ^= uint64(value)
		state *= 0x100000001b3
	}
	if state == 0 {
		state = 0x9e3779b97f4a7c15
	}
	reply := make([]byte, size)
	for i := range reply {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		reply[i] = byte(state)
	}
	return reply
}
