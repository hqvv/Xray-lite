package dns

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/protocol/dns"
	"github.com/xtls/xray-core/common/session"
	dns_feature "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet"
)

// TCPNameServer implemented DNS over TCP (RFC7766).
type TCPNameServer struct {
	name        string
	destination *net.Destination
	reqID       uint32
	dial        func(context.Context) (net.Conn, error)
	updateIP    func(req *dnsRequest, ipRec *IPRecord)
}

// NewTCPNameServer creates DNS over TCP server object for remote resolving.
func NewTCPNameServer(url *url.URL, dispatcher routing.Dispatcher) (NameServerImpl, error) {
	s, err := baseTCPNameServer(url, "TCP")
	if err != nil {
		return nil, err
	}

	s.dial = func(ctx context.Context) (net.Conn, error) {
		link, err := dispatcher.Dispatch(toDnsContext(ctx, s.destination.String()), *s.destination)
		if err != nil {
			return nil, err
		}

		return cnc.NewConnection(
			cnc.ConnectionInputMulti(link.Writer),
			cnc.ConnectionOutputMulti(link.Reader),
		), nil
	}

	return s, nil
}

// NewTCPLocalNameServer creates DNS over TCP client object for local resolving
func NewTCPLocalNameServer(url *url.URL, _ routing.Dispatcher) (NameServerImpl, error) {
	s, err := baseTCPNameServer(url, "TCPL")
	if err != nil {
		return nil, err
	}

	s.dial = func(ctx context.Context) (net.Conn, error) {
		return internet.DialSystem(ctx, *s.destination, nil)
	}

	return s, nil
}

func baseTCPNameServer(url *url.URL, prefix string) (*TCPNameServer, error) {
	port := net.Port(53)
	if url.Port() != "" {
		var err error
		if port, err = net.PortFromString(url.Port()); err != nil {
			return nil, err
		}
	}
	dest := net.TCPDestination(net.ParseAddress(url.Hostname()), port)

	s := &TCPNameServer{
		destination: &dest,
		name:        prefix + "//" + dest.NetAddr(),
	}
	return s, nil
}

// Name implements Server.
func (s *TCPNameServer) Name() string {
	return s.name
}

func (s *TCPNameServer) SetUpdateCallback(updater func(req *dnsRequest, ipRec *IPRecord)) {
	s.updateIP = updater
}

// Cleanup clears expired items from cache
func (s *TCPNameServer) Cleanup() error {
	return nil
}

func (s *TCPNameServer) newReqID() uint16 {
	return uint16(atomic.AddUint32(&s.reqID, 1))
}

func (s *TCPNameServer) SendQuery(ctx context.Context, domain string, clientIP net.IP, option dns_feature.IPOption) {
	newError(s.name, " querying DNS for: ", domain).AtDebug().WriteToLog(session.ExportIDToError(ctx))

	reqs := buildReqMsgs(domain, option, s.newReqID, genEDNS0Options(clientIP))

	var deadline time.Time
	if d, ok := ctx.Deadline(); ok {
		deadline = d
	} else {
		deadline = time.Now().Add(time.Second * 5)
	}

	for _, req := range reqs {
		go func(r *dnsRequest) {
			dnsCtx := ctx

			if inbound := session.InboundFromContext(ctx); inbound != nil {
				dnsCtx = session.ContextWithInbound(dnsCtx, inbound)
			}

			dnsCtx = session.ContextWithContent(dnsCtx, &session.Content{
				Protocol:       "dns",
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

			conn, err := s.dial(dnsCtx)
			if err != nil {
				newError("failed to dial namesever").Base(err).AtError().WriteToLog()
				return
			}
			defer conn.Close()
			dnsReqBuf := buf.New()
			binary.Write(dnsReqBuf, binary.BigEndian, uint16(b.Len()))
			dnsReqBuf.Write(b.Bytes())
			b.Release()

			_, err = conn.Write(dnsReqBuf.Bytes())
			if err != nil {
				newError("failed to send query").Base(err).AtError().WriteToLog()
				return
			}
			dnsReqBuf.Release()

			respBuf := buf.New()
			defer respBuf.Release()
			n, err := respBuf.ReadFullFrom(conn, 2)
			if err != nil && n == 0 {
				newError("failed to read response length").Base(err).AtError().WriteToLog()
				return
			}
			var length int16
			err = binary.Read(bytes.NewReader(respBuf.Bytes()), binary.BigEndian, &length)
			if err != nil {
				newError("failed to parse response length").Base(err).AtError().WriteToLog()
				return
			}
			respBuf.Clear()
			n, err = respBuf.ReadFullFrom(conn, int32(length))
			if err != nil && n == 0 {
				newError("failed to read response length").Base(err).AtError().WriteToLog()
				return
			}

			rec, err := parseResponse(respBuf.Bytes())
			if err != nil {
				newError("failed to parse DNS over TCP response").Base(err).AtError().WriteToLog()
				return
			}

			s.updateIP(r, rec)
		}(req)
	}
}

func init() {
	RegisterProtocol("tcp", NewTCPNameServer)            // DNS-over-TCP Remote mode
	RegisterProtocol("tcp+local", NewTCPLocalNameServer) // DNS-over-TCP Local mode
}
