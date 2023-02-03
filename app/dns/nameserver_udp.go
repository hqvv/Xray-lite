package dns

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/dns"
	udp_proto "github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/common/session"
	dns_feature "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/udp"
	"golang.org/x/net/dns/dnsmessage"
)

// ClassicNameServer implemented traditional UDP DNS.
type ClassicNameServer struct {
	sync.RWMutex
	name      string
	address   *net.Destination
	requests  map[uint16]*dnsRequest
	udpServer *udp.Dispatcher
	reqID     uint32
	updater   func(req *dnsRequest, ipRec *IPRecord)
}

// NewClassicNameServer creates udp server object for remote resolving.
func NewClassicNameServer(address net.Destination, dispatcher routing.Dispatcher) *ClassicNameServer {
	// default to 53 if unspecific
	if address.Port == 0 {
		address.Port = net.Port(53)
	}

	s := &ClassicNameServer{
		address:  &address,
		requests: make(map[uint16]*dnsRequest),
		name:     strings.ToUpper(address.String()),
	}
	s.udpServer = udp.NewDispatcher(dispatcher, s.HandleResponse)
	newError("DNS: created UDP client initialized for ", address.NetAddr()).AtInfo().WriteToLog()
	return s
}

// Name implements Server.
func (s *ClassicNameServer) Name() string {
	return s.name
}

// Cleanup clears expired items from cache
func (s *ClassicNameServer) Cleanup() error {
	now := time.Now()
	s.Lock()
	defer s.Unlock()

	for id, req := range s.requests {
		if req.expire.Before(now) {
			delete(s.requests, id)
		}
	}

	if len(s.requests) == 0 {
		s.requests = make(map[uint16]*dnsRequest)
	}

	return nil
}

func (s *ClassicNameServer) SetUpdateCallback(updater func(req *dnsRequest, ipRec *IPRecord)) {
	s.updater = updater
}

// HandleResponse handles udp response packet from remote DNS server.
func (s *ClassicNameServer) HandleResponse(ctx context.Context, packet *udp_proto.Packet) {
	ipRec, err := parseResponse(packet.Payload.Bytes())
	if err != nil {
		newError(s.name, " fail to parse responded DNS udp").AtError().WriteToLog()
		return
	}

	s.Lock()
	id := ipRec.ReqID
	req, ok := s.requests[id]
	if ok {
		// remove the pending request
		delete(s.requests, id)
	}
	s.Unlock()
	if !ok {
		newError(s.name, " cannot find the pending request").AtError().WriteToLog()
		return
	}

	var rec record
	switch req.reqType {
	case dnsmessage.TypeA:
		rec.A = ipRec
	case dnsmessage.TypeAAAA:
		rec.AAAA = ipRec
	}

	elapsed := time.Since(req.start)
	newError(s.name, " got answer: ", req.domain, " ", req.reqType, " -> ", ipRec.IP, " ", elapsed).AtInfo().WriteToLog()
	if len(req.domain) > 0 && (rec.A != nil || rec.AAAA != nil) {
		s.updater(req, ipRec)
	}
}

func (s *ClassicNameServer) newReqID() uint16 {
	return uint16(atomic.AddUint32(&s.reqID, 1))
}

func (s *ClassicNameServer) addPendingRequest(req *dnsRequest) {
	s.Lock()
	defer s.Unlock()

	id := req.msg.ID
	req.expire = time.Now().Add(time.Second * 8)
	s.requests[id] = req
}

func (s *ClassicNameServer) SendQuery(ctx context.Context, domain string, clientIP net.IP, option dns_feature.IPOption) {
	newError(s.name, " querying DNS for: ", domain).AtDebug().WriteToLog(session.ExportIDToError(ctx))

	reqs := buildReqMsgs(domain, option, s.newReqID, genEDNS0Options(clientIP))

	for _, req := range reqs {
		s.addPendingRequest(req)
		b, _ := dns.PackMessage(req.msg)
		s.udpServer.Dispatch(toDnsContext(ctx, s.address.String()), *s.address, b)
	}
}
