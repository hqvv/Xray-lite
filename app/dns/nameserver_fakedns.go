package dns

import (
	"context"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
)

type FakeDNSServer struct {
	fakeDNSEngine dns.FakeDNSEngine
}

func NewFakeDNSServer() *FakeDNSServer {
	return &FakeDNSServer{}
}

func (FakeDNSServer) Name() string {
	return "FakeDNS"
}

func (f *FakeDNSServer) QueryCachedIP(ctx context.Context, domain string, opt dns.IPOption) ([]net.IP, uint32, error) {
	return nil, 0, errRecordNotFound
}

func (f *FakeDNSServer) QueryIP(ctx context.Context, domain string, _ net.IP, opt dns.IPOption) ([]net.IP, uint32, error) {
	if f.fakeDNSEngine == nil {
		if err := core.RequireFeatures(ctx, func(fd dns.FakeDNSEngine) {
			f.fakeDNSEngine = fd
		}); err != nil {
			return nil, 0, newError("Unable to locate a fake DNS Engine").Base(err).AtError()
		}
	}
	var ips []net.Address
	if fkr0, ok := f.fakeDNSEngine.(dns.FakeDNSEngineRev0); ok {
		ips = fkr0.GetFakeIPForDomain3(domain, opt.IPv4Enable, opt.IPv6Enable)
	} else {
		ips = f.fakeDNSEngine.GetFakeIPForDomain(domain)
	}

	netIP, err := toNetIP(ips)
	if err != nil {
		return nil, 0, newError("Unable to convert IP to net ip").Base(err).AtError()
	}

	newError(f.Name(), " got answer: ", domain, " -> ", ips).AtInfo().WriteToLog()

	if len(netIP) > 0 {
		return netIP, dns.DefaultTTLFakeDNS, nil
	}
	return nil, 0, dns.ErrEmptyResponse
}
