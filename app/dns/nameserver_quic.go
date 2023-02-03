package dns

import (
	"context"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/dns"
	"github.com/xtls/xray-core/common/session"
	dns_feature "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/net/http2"
)

// NextProtoDQ - During connection establishment, DNS/QUIC support is indicated
// by selecting the ALPN token "dq" in the crypto handshake.
const NextProtoDQ = "doq-i00"

const handshakeTimeout = time.Second * 8

// QUICNameServer implemented DNS over QUIC
type QUICNameServer struct {
	sync.RWMutex
	reqID       uint32
	name        string
	destination *net.Destination
	connection  quic.Connection
	updateIP    func(req *dnsRequest, ipRec *IPRecord)
}

// NewQUICNameServer creates DNS-over-QUIC client object for local resolving
func NewQUICNameServer(url *url.URL, _ routing.Dispatcher) (NameServerImpl, error) {
	newError("DNS: created Local DNS-over-QUIC client for ", url.String()).AtInfo().WriteToLog()

	var err error
	port := net.Port(784)
	if url.Port() != "" {
		port, err = net.PortFromString(url.Port())
		if err != nil {
			return nil, err
		}
	}
	dest := net.UDPDestination(net.ParseAddress(url.Hostname()), port)

	s := &QUICNameServer{
		name:        url.String(),
		destination: &dest,
	}

	return s, nil
}

// Name returns client name
func (s *QUICNameServer) Name() string {
	return s.name
}

func (s *QUICNameServer) SetUpdateCallback(updater func(req *dnsRequest, ipRec *IPRecord)) {
	s.updateIP = updater
}

// Cleanup clears expired items from cache
func (s *QUICNameServer) Cleanup() error {
	return nil
}

func (s *QUICNameServer) newReqID() uint16 {
	return uint16(atomic.AddUint32(&s.reqID, 1))
}

func (s *QUICNameServer) SendQuery(ctx context.Context, domain string, clientIP net.IP, option dns_feature.IPOption) {
	newError(s.name, " querying: ", domain).AtInfo().WriteToLog(session.ExportIDToError(ctx))

	reqs := buildReqMsgs(domain, option, s.newReqID, genEDNS0Options(clientIP))

	var deadline time.Time
	if d, ok := ctx.Deadline(); ok {
		deadline = d
	} else {
		deadline = time.Now().Add(time.Second * 5)
	}

	for _, req := range reqs {
		go func(r *dnsRequest) {
			// generate new context for each req, using same context
			// may cause reqs all aborted if any one encounter an error
			dnsCtx := ctx

			// reserve internal dns server requested Inbound
			if inbound := session.InboundFromContext(ctx); inbound != nil {
				dnsCtx = session.ContextWithInbound(dnsCtx, inbound)
			}

			dnsCtx = session.ContextWithContent(dnsCtx, &session.Content{
				Protocol:       "quic",
				SkipDNSResolve: true,
			})

			var cancel context.CancelFunc
			dnsCtx, cancel = context.WithDeadline(dnsCtx, deadline)
			defer cancel()

			b, err := dns.PackMessage(r.msg)
			if err != nil {
				newError("failed to pack dns query").Base(err).AtError().WriteToLog()
				return
			}

			conn, err := s.openStream(dnsCtx)
			if err != nil {
				newError("failed to open quic connection").Base(err).AtError().WriteToLog()
				return
			}

			_, err = conn.Write(b.Bytes())
			if err != nil {
				newError("failed to send query").Base(err).AtError().WriteToLog()
				return
			}

			_ = conn.Close()

			respBuf := buf.New()
			defer respBuf.Release()
			n, err := respBuf.ReadFrom(conn)
			if err != nil && n == 0 {
				newError("failed to read response").Base(err).AtError().WriteToLog()
				return
			}

			rec, err := parseResponse(respBuf.Bytes())
			if err != nil {
				newError("failed to handle response").Base(err).AtError().WriteToLog()
				return
			}
			s.updateIP(r, rec)
		}(req)
	}
}

func isActive(s quic.Connection) bool {
	select {
	case <-s.Context().Done():
		return false
	default:
		return true
	}
}

func (s *QUICNameServer) getConnection() (quic.Connection, error) {
	var conn quic.Connection
	s.RLock()
	conn = s.connection
	if conn != nil && isActive(conn) {
		s.RUnlock()
		return conn, nil
	}
	if conn != nil {
		// we're recreating the connection, let's create a new one
		_ = conn.CloseWithError(0, "")
	}
	s.RUnlock()

	s.Lock()
	defer s.Unlock()

	var err error
	conn, err = s.openConnection()
	if err != nil {
		// This does not look too nice, but QUIC (or maybe quic-go)
		// doesn't seem stable enough.
		// Maybe retransmissions aren't fully implemented in quic-go?
		// Anyways, the simple solution is to make a second try when
		// it fails to open the QUIC connection.
		conn, err = s.openConnection()
		if err != nil {
			return nil, err
		}
	}
	s.connection = conn
	return conn, nil
}

func (s *QUICNameServer) openConnection() (quic.Connection, error) {
	tlsConfig := tls.Config{}
	quicConfig := &quic.Config{
		HandshakeIdleTimeout: handshakeTimeout,
	}
	tlsConfig.ServerName = s.destination.Address.String()
	conn, err := quic.DialAddr(context.Background(), s.destination.NetAddr(), tlsConfig.GetTLSConfig(tls.WithNextProto("http/1.1", http2.NextProtoTLS, NextProtoDQ)), quicConfig)
	log.Record(&log.AccessMessage{
		From:   "DNS",
		To:     s.destination,
		Status: log.AccessAccepted,
		Detour: "local",
	})
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func (s *QUICNameServer) openStream(ctx context.Context) (quic.Stream, error) {
	conn, err := s.getConnection()
	if err != nil {
		return nil, err
	}

	// open a new stream
	return conn.OpenStreamSync(ctx)
}

func init() {
	RegisterProtocol("quic+local", NewQUICNameServer) // DNS-over-QUIC Local mode
}
