package dns

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/protocol/dns"
	"github.com/xtls/xray-core/common/session"
	dns_feature "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet"
)

// DoHNameServer implemented DNS over HTTPS (RFC8484) Wire Format,
// which is compatible with traditional dns over udp(RFC1035),
// thus most of the DOH implementation is copied from udpns.go
type DoHNameServer struct {
	dispatcher routing.Dispatcher
	reqID      uint32
	httpClient *http.Client
	dohURL     string
	name       string
	updateIP   func(req *dnsRequest, ipRec *IPRecord)
}

// NewDoHNameServer creates DOH server object for remote resolving.
func NewDoHNameServer(url *url.URL, dispatcher routing.Dispatcher) (NameServerImpl, error) {
	newError("DNS: created Remote DOH client for ", url.String()).AtInfo().WriteToLog()
	s := baseDOHNameServer(url, "DOH")

	s.dispatcher = dispatcher
	tr := &http.Transport{
		MaxIdleConns:        30,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 30 * time.Second,
		ForceAttemptHTTP2:   true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dest, err := net.ParseDestination(network + ":" + addr)
			if err != nil {
				return nil, err
			}
			link, err := s.dispatcher.Dispatch(toDnsContext(ctx, s.dohURL), dest)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:

			}
			if err != nil {
				return nil, err
			}

			cc := common.ChainedClosable{}
			if cw, ok := link.Writer.(common.Closable); ok {
				cc = append(cc, cw)
			}
			if cr, ok := link.Reader.(common.Closable); ok {
				cc = append(cc, cr)
			}
			return cnc.NewConnection(
				cnc.ConnectionInputMulti(link.Writer),
				cnc.ConnectionOutputMulti(link.Reader),
				cnc.ConnectionOnClose(cc),
			), nil
		},
	}
	s.httpClient = &http.Client{
		Timeout:   time.Second * 180,
		Transport: tr,
	}

	return s, nil
}

// NewDoHLocalNameServer creates DOH client object for local resolving
func NewDoHLocalNameServer(url *url.URL, _ routing.Dispatcher) (NameServerImpl, error) {
	url.Scheme = "https"
	s := baseDOHNameServer(url, "DOHL")
	tr := &http.Transport{
		IdleConnTimeout:   90 * time.Second,
		ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dest, err := net.ParseDestination(network + ":" + addr)
			if err != nil {
				return nil, err
			}
			conn, err := internet.DialSystem(ctx, dest, nil)
			log.Record(&log.AccessMessage{
				From:   "DNS",
				To:     s.dohURL,
				Status: log.AccessAccepted,
				Detour: "local",
			})
			if err != nil {
				return nil, err
			}
			return conn, nil
		},
	}
	s.httpClient = &http.Client{
		Timeout:   time.Second * 180,
		Transport: tr,
	}
	newError("DNS: created Local DOH client for ", url.String()).AtInfo().WriteToLog()
	return s, nil
}

func baseDOHNameServer(url *url.URL, prefix string) *DoHNameServer {
	s := &DoHNameServer{
		name:   prefix + "//" + url.Host,
		dohURL: url.String(),
	}
	return s
}

// Name implements Server.
func (s *DoHNameServer) Name() string {
	return s.name
}

func (s *DoHNameServer) SetUpdateCallback(updater func(req *dnsRequest, ipRec *IPRecord)) {
	s.updateIP = updater
}

// Cleanup clears expired items from cache
func (s *DoHNameServer) Cleanup() error {
	return nil
}

func (s *DoHNameServer) newReqID() uint16 {
	return uint16(atomic.AddUint32(&s.reqID, 1))
}

func (s *DoHNameServer) SendQuery(ctx context.Context, domain string, clientIP net.IP, option dns_feature.IPOption) {
	newError(s.name, " querying: ", domain).AtInfo().WriteToLog(session.ExportIDToError(ctx))

	if s.name+"." == "DOH//"+domain {
		newError(s.name, " tries to resolve itself! Use IP or set \"hosts\" instead.").AtError().WriteToLog(session.ExportIDToError(ctx))
		return
	}

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
				Protocol:       "https",
				SkipDNSResolve: true,
			})

			// forced to use mux for DOH
			// dnsCtx = session.ContextWithMuxPrefered(dnsCtx, true)

			var cancel context.CancelFunc
			dnsCtx, cancel = context.WithDeadline(dnsCtx, deadline)
			defer cancel()

			b, err := dns.PackMessage(r.msg)
			if err != nil {
				newError("failed to pack dns query for ", domain).Base(err).AtError().WriteToLog()
				return
			}
			resp, err := s.dohHTTPSContext(dnsCtx, b.Bytes())
			if err != nil {
				newError("failed to retrieve response for ", domain).Base(err).AtError().WriteToLog()
				return
			}
			rec, err := parseResponse(resp)
			if err != nil {
				newError("failed to handle DOH response for ", domain).Base(err).AtError().WriteToLog()
				return
			}
			s.updateIP(r, rec)
		}(req)
	}
}

func (s *DoHNameServer) dohHTTPSContext(ctx context.Context, b []byte) ([]byte, error) {
	body := bytes.NewBuffer(b)
	req, err := http.NewRequest("POST", s.dohURL, body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Accept", "application/dns-message")
	req.Header.Add("Content-Type", "application/dns-message")

	hc := s.httpClient

	resp, err := hc.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body) // flush resp.Body so that the conn is reusable
		return nil, fmt.Errorf("DOH server returned code %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

func init() {
	RegisterProtocol("https", NewDoHNameServer)            // DOH Remote mode
	RegisterProtocol("https+local", NewDoHLocalNameServer) // DOH Local mode
}
