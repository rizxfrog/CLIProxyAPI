package helps

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	tls "github.com/refraction-networking/utls"
	internalcache "github.com/router-for-me/CLIProxyAPI/v7/internal/cache"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/proxyutil"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/proxy"
)

const qoderCNRoundTripperCacheCapacity = 32

var qoderCNRoundTripperCache = internalcache.NewBoundedLRU[string, http.RoundTripper](
	qoderCNRoundTripperCacheCapacity,
	func(_ string, roundTripper http.RoundTripper) {
		if transport, ok := roundTripper.(interface{ CloseIdleConnections() }); ok {
			transport.CloseIdleConnections()
		}
	},
)

// qoderCNTLSClientHelloSpec reproduces the Node 24 / OpenSSL 3.5 ClientHello
// captured from the official Qoder CN CLI 1.1.55 talking to the Qoder model
// server (JA3 d67b094811e5145139d7cea5f014309f).
//
// Distinctive traits, all load-bearing:
//   - TLS 1.3 ciphers first (4866, 4867, 4865), then the OpenSSL 1.2 order
//   - X25519MLKEM768 (4588) leads the supported groups
//   - the full 26-entry signature_algorithms list
//   - ALPN advertises http/1.1 only; the model server is not used over h2
//   - no GREASE anywhere
//
// See docs/qoder-cn-client-analysis.md and the captured ja3str in the
// reverse-engineering artifact directory.
func qoderCNTLSClientHelloSpec() *tls.ClientHelloSpec {
	return &tls.ClientHelloSpec{
		TLSVersMin:         tls.VersionTLS12,
		TLSVersMax:         tls.VersionTLS13,
		CompressionMethods: []uint8{0},
		CipherSuites: []uint16{
			4866, 4867, 4865, 49199, 49195, 49200, 49196, 158,
			49191, 103, 49192, 107, 163, 159, 52393, 52392, 52394,
			49325, 49311, 49245, 49249, 49239, 49235, 162, 49324,
			49310, 49244, 49248, 49238, 49234, 49188, 106, 49187,
			64, 49162, 49172, 57, 56, 49161, 49171, 51, 50, 157,
			49309, 49233, 156, 49308, 49232, 61, 60, 53, 47,
		},
		Extensions: []tls.TLSExtension{
			&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
			&tls.SNIExtension{},
			&tls.SupportedPointsExtension{SupportedPoints: []byte{0, 1, 2}},
			&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
				tls.X25519MLKEM768,
				tls.X25519,
				tls.CurveID(23),
				tls.CurveID(30),
				tls.CurveID(24),
				tls.CurveID(25),
				tls.CurveID(256),
				tls.CurveID(257),
			}},
			&tls.SessionTicketExtension{},
			&tls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}},
			&tls.GenericExtension{Id: 22},
			&tls.ExtendedMasterSecretExtension{},
			&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.SignatureScheme(2309), tls.SignatureScheme(2310), tls.SignatureScheme(2308),
				tls.SignatureScheme(1027), tls.SignatureScheme(1283), tls.SignatureScheme(1539),
				tls.SignatureScheme(2055), tls.SignatureScheme(2056), tls.SignatureScheme(2074),
				tls.SignatureScheme(2075), tls.SignatureScheme(2076), tls.SignatureScheme(2057),
				tls.SignatureScheme(2058), tls.SignatureScheme(2059), tls.SignatureScheme(2052),
				tls.SignatureScheme(2053), tls.SignatureScheme(2054), tls.SignatureScheme(1025),
				tls.SignatureScheme(1281), tls.SignatureScheme(1537), tls.SignatureScheme(771),
				tls.SignatureScheme(769), tls.SignatureScheme(770), tls.SignatureScheme(1026),
				tls.SignatureScheme(1282), tls.SignatureScheme(1538),
			}},
			&tls.SupportedVersionsExtension{Versions: []uint16{tls.VersionTLS13, tls.VersionTLS12}},
			&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
			&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
				{Group: tls.X25519MLKEM768},
				{Group: tls.X25519},
			}},
		},
	}
}

func newQoderCNRoundTripper(proxyURL string) http.RoundTripper {
	var dialer proxy.Dialer = proxy.Direct
	if proxyURL != "" {
		proxyDialer, mode, errBuild := proxyutil.BuildDialer(proxyURL)
		if errBuild != nil {
			log.Errorf("qoder-cn tls: failed to configure proxy dialer for %q: %v", proxyutil.Redact(proxyURL), errBuild)
		} else if mode != proxyutil.ModeInherit && proxyDialer != nil {
			dialer = proxyDialer
		}
	}

	return &http.Transport{
		// The captured ClientHello negotiates http/1.1 only, so HTTP/2 must stay
		// disabled or the transport would request an h2 upgrade unsupported by
		// the fingerprint.
		ForceAttemptHTTP2: false,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var (
				conn net.Conn
				err  error
			)
			if contextDialer, ok := dialer.(proxy.ContextDialer); ok {
				conn, err = contextDialer.DialContext(ctx, network, addr)
			} else {
				conn, err = dialer.Dial(network, addr)
			}
			if err != nil {
				return nil, fmt.Errorf("qoder-cn tls: dial upstream: %w", err)
			}

			host, _, errSplit := net.SplitHostPort(addr)
			if errSplit != nil {
				_ = conn.Close()
				return nil, fmt.Errorf("qoder-cn tls: split upstream address: %w", errSplit)
			}
			tlsConn := tls.UClient(conn, &tls.Config{
				ServerName:             host,
				SessionTicketsDisabled: true,
			}, tls.HelloCustom)
			if errPreset := tlsConn.ApplyPreset(qoderCNTLSClientHelloSpec()); errPreset != nil {
				_ = tlsConn.Close()
				return nil, fmt.Errorf("qoder-cn tls: apply ClientHello: %w", errPreset)
			}
			if errHandshake := tlsConn.HandshakeContext(ctx); errHandshake != nil {
				_ = tlsConn.Close()
				return nil, fmt.Errorf("qoder-cn tls: handshake upstream: %w", errHandshake)
			}
			return tlsConn, nil
		},
	}
}

func cachedQoderCNRoundTripper(proxyURL string) http.RoundTripper {
	return qoderCNRoundTripperCache.GetOrAdd(proxyURL, func() http.RoundTripper {
		return newQoderCNRoundTripper(proxyURL)
	})
}

// NewQoderCNHTTPClient creates a proxy-aware HTTP client that reproduces the
// official Qoder CN CLI TLS fingerprint for Qoder model-server and OpenAPI
// requests.
func NewQoderCNHTTPClient(ctx context.Context, cfg *config.Config, auth *cliproxyauth.Auth, timeout time.Duration) *http.Client {
	var proxyURL string
	if auth != nil {
		proxyURL = strings.TrimSpace(auth.ProxyURL)
	}
	if proxyURL == "" && cfg != nil {
		proxyURL = strings.TrimSpace(cfg.ProxyURL)
	}

	var roundTripper http.RoundTripper
	if proxyURL == "" && ctx != nil {
		roundTripper, _ = ctx.Value("cliproxy.roundtripper").(http.RoundTripper)
	}
	if roundTripper == nil {
		roundTripper = cachedQoderCNRoundTripper(proxyURL)
	}

	client := &http.Client{Transport: roundTripper}
	if timeout > 0 {
		client.Timeout = timeout
	}
	return client
}
