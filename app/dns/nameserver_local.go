package dns

import (
	"context"
	"strings"
	"time"

	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/dns/localdns"
)

// LocalNameServer is an wrapper over local DNS feature.
type LocalNameServer struct {
	client *localdns.Client
}

const errEmptyResponse = "No address associated with hostname"

// QueryIP implements Server.
func (s *LocalNameServer) QueryIP(_ context.Context, domain string, _ net.IP, option dns.IPOption) (ips []net.IP, ttl uint32, err error) {
	start := time.Now()
	ips, err = s.client.LookupIP(domain, option)

	if err != nil && strings.HasSuffix(err.Error(), errEmptyResponse) {
		err = dns.ErrEmptyResponse
	}

	if len(ips) > 0 {
		newError("Localhost got answer: ", domain, " -> ", ips).AtInfo().WriteToLog()
		log.Record(&log.DNSLog{Server: s.Name(), Domain: domain, Result: ips, Status: log.DNSQueried, Elapsed: time.Since(start), Error: err})
	}

	return ips, dns.DefaultTTL, err
}

func (s *LocalNameServer) QueryCachedIP(ctx context.Context, domain string, option dns.IPOption) ([]net.IP, uint32, error) {
	return nil, 0, errRecordNotFound
}

// Name implements Server.
func (s *LocalNameServer) Name() string {
	return "localhost"
}

// NewLocalNameServer creates localdns server object for directly lookup in system DNS.
func NewLocalNameServer() *LocalNameServer {
	newError("DNS: created localhost client").AtInfo().WriteToLog()
	return &LocalNameServer{
		client: localdns.New(),
	}
}

// NewLocalDNSClient creates localdns client object for directly lookup in system DNS.
func NewLocalDNSClient() *Client {
	return &Client{server: NewLocalNameServer()}
}
