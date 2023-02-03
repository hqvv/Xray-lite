package dns

import (
	"context"
	"fmt"
	"net/url"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal/pubsub"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
)

type NameServerInit func(url *url.URL, dispatcher routing.Dispatcher) (NameServerImpl, error)

type NameServerImpl interface {
	Name() string
	Cleanup() error
	SendQuery(ctx context.Context, domain string, clientIP net.IP, option dns.IPOption)
	SetUpdateCallback(callback func(req *dnsRequest, ipRec *IPRecord))
}

type NameServerBase struct {
	sync.RWMutex
	name          string
	queryStrategy QueryStrategy
	ips           map[string]*record
	ipsPeak       int
	pub           *pubsub.Service
	stats         stats.Manager
	cleanup       *task.Periodic
	impl          NameServerImpl
	lastErr       error
}

func NewNameServer(ctx context.Context, impl NameServerImpl, queryStrategy QueryStrategy) *NameServerBase {
	s := &NameServerBase{
		ips:           make(map[string]*record),
		pub:           pubsub.NewService(),
		name:          impl.Name(),
		impl:          impl,
		queryStrategy: queryStrategy,
	}
	s.cleanup = &task.Periodic{
		Interval: time.Minute,
		Execute: func() error {
			s.cleanUp()
			return s.impl.Cleanup()
		},
	}
	if c := core.FromContext(ctx); c != nil {
		_ = c.RequireFeatures(func(sm stats.Manager) {
			s.stats = sm
		})
	}
	s.impl.SetUpdateCallback(s.updateIP)
	return s
}

func InitNameServer(ctx context.Context, i NameServerInit, u *url.URL, d routing.Dispatcher, queryStrategy QueryStrategy) (*NameServerBase, error) {
	impl, err := i(u, d)
	if err != nil {
		return nil, err
	}
	return NewNameServer(ctx, impl, queryStrategy), nil
}

func (s *NameServerBase) Name() string {
	return s.name
}

func (s *NameServerBase) emitCounter(suffix string, value int64) {
	if s.stats != nil {
		name := "dns>>>" + s.name + ">>>cache>>>" + suffix
		if c, _ := stats.GetOrRegisterCounter(s.stats, name); c != nil {
			c.Add(value)
		}
	}
}

func (s *NameServerBase) emitValue(suffix string, value int64) {
	if s.stats != nil {
		name := "dns>>>" + s.name + ">>>cache>>>" + suffix
		if c, _ := stats.GetOrRegisterCounter(s.stats, name); c != nil {
			c.Set(value)
		}
	}
}

func (s *NameServerBase) get(v string) (*record, bool) {
	s.RLock()
	defer s.RUnlock()
	r, ok := s.ips[v]
	return r, ok
}

func (s *NameServerBase) findIPsForDomain(domain string, option dns.IPOption) ([]net.IP, uint32, error) {
	r, found := s.get(domain)
	if !found {
		return nil, 0, errRecordNotFound
	}

	var err4 error
	var err6 error
	var ips []net.Address
	var ip6 []net.Address
	var ttl uint32 = dns.DefaultTTL

	if option.IPv4Enable {
		if ips, err4 = r.A.getIPs(); err4 == nil {
			ttl = uint32(time.Until(r.A.Expire) / time.Second)
		}
	}

	if option.IPv6Enable {
		if ip6, err6 = r.AAAA.getIPs(); err6 == nil {
			ips = append(ips, ip6...)
			ttl6 := uint32(time.Until(r.AAAA.Expire) / time.Second)
			if ttl6 < ttl {
				ttl = ttl6
			}
		}
	}

	if len(ips) > 0 {
		ipsResult, err := toNetIP(ips)
		return ipsResult, ttl, err
	}

	if err4 != nil {
		return nil, 0, err4
	}

	if err6 != nil {
		return nil, 0, err6
	}

	if (option.IPv4Enable && r.A != nil) || (option.IPv6Enable && r.AAAA != nil) {
		return nil, 0, dns.ErrEmptyResponse
	}

	return nil, 0, errRecordNotFound
}

func (s *NameServerBase) QueryCachedIP(ctx context.Context, domain string, option dns.IPOption) ([]net.IP, uint32, error) {
	fqdn := Fqdn(domain)

	ips, ttl, err := s.findIPsForDomain(fqdn, option)
	if err != errRecordNotFound {
		s.emitCounter("cache_hits", 1)
		newError(s.name, " cache HIT ", domain, " -> ", ips).Base(err).AtDebug().WriteToLog()
		log.Record(&log.DNSLog{Server: s.name, Domain: domain, Result: ips, Status: log.DNSCacheHit, Elapsed: 0, Error: err})
	} else {
		s.emitCounter("cache_misses", 1)
	}
	return ips, ttl, err
}

func (s *NameServerBase) updateIP(req *dnsRequest, ipRec *IPRecord) {
	elapsed := time.Since(req.start)

	rec, found := s.get(req.domain)
	if !found {
		rec = &record{}
	}
	updated := false

	switch req.reqType {
	case dnsmessage.TypeA:
		if isNewer(rec.A, ipRec) {
			rec.A = ipRec
			updated = true
		}
	case dnsmessage.TypeAAAA:
		addr := make([]net.Address, 0)
		for _, ip := range ipRec.IP {
			if len(ip.IP()) == net.IPv6len {
				addr = append(addr, ip)
			}
		}
		ipRec.IP = addr
		if isNewer(rec.AAAA, ipRec) {
			rec.AAAA = ipRec
			updated = true
		}
	}
	newError(s.name, " got answer: ", req.domain, " ", req.reqType, " -> ", ipRec.IP, " ", elapsed).AtInfo().WriteToLog()

	s.Lock()
	if updated {
		s.ips[req.domain] = rec
		if s.ipsPeak < len(s.ips) {
			s.ipsPeak = len(s.ips)
		}
		s.emitValue("cache_alloc", int64(s.ipsPeak))
		s.emitValue("cache_size", int64(len(s.ips)))
	}
	switch req.reqType {
	case dnsmessage.TypeA:
		s.pub.Publish(req.domain+"4", nil)
	case dnsmessage.TypeAAAA:
		s.pub.Publish(req.domain+"6", nil)
	}
	s.Unlock()
	common.Must(s.cleanup.Start())
}

func (s *NameServerBase) cleanUp() {
	s.Lock()
	defer s.Unlock()
	s.emitCounter("cache_cleanup", 1)

	for domain, r := range s.ips {
		if ips, _ := r.A.getIPs(); len(ips) == 0 {
			r.A = nil
		}
		if ips, _ := r.AAAA.getIPs(); len(ips) == 0 {
			r.AAAA = nil
		}

		if r.A == nil && r.AAAA == nil {
			newError(s.name, " cleanup ", domain).AtDebug().WriteToLog()
			s.emitCounter("cache_expire", 1)
			delete(s.ips, domain)
		} else {
			s.ips[domain] = r
		}
	}

	if len(s.ips) == 0 {
		s.ips = make(map[string]*record)
		s.emitCounter("cache_flush", 1)
		s.ipsPeak = 0
	}

	if s.ipsPeak < len(s.ips) {
		s.ipsPeak = len(s.ips)
	}
	s.emitValue("cache_alloc", int64(s.ipsPeak))
	s.emitValue("cache_size", int64(len(s.ips)))
}

func (s *NameServerBase) QueryIP(ctx context.Context, domain string, clientIP net.IP, option dns.IPOption) ([]net.IP, uint32, error) {
	fqdn := Fqdn(domain)

	option = ResolveIpOptionOverride(s.queryStrategy, option)
	if !option.IPv4Enable && !option.IPv6Enable {
		return nil, 0, dns.ErrEmptyResponse
	}

	// ipv4 and ipv6 belong to different subscription groups
	var sub4, sub6 *pubsub.Subscriber
	if option.IPv4Enable {
		sub4 = s.pub.Subscribe(fqdn + "4")
		defer sub4.Close()
	}
	if option.IPv6Enable {
		sub6 = s.pub.Subscribe(fqdn + "6")
		defer sub6.Close()
	}
	done := make(chan interface{})
	go func() {
		if sub4 != nil {
			select {
			case <-sub4.Wait():
			case <-ctx.Done():
			}
		}
		if sub6 != nil {
			select {
			case <-sub6.Wait():
			case <-ctx.Done():
			}
		}
		close(done)
	}()
	s.impl.SendQuery(ctx, fqdn, clientIP, option)
	start := time.Now()

	for {
		if ips, ttl, err := s.findIPsForDomain(fqdn, option); err != errRecordNotFound {
			log.Record(&log.DNSLog{Server: s.name, Domain: domain, Result: ips, Status: log.DNSQueried, Elapsed: time.Since(start), Error: err})
			if len(ips) > 0 {
				s.emitCounter("query_success", 1)
			} else if err == dns.ErrEmptyResponse {
				s.emitCounter("query_empty", 1)
			} else {
				thisErr := err
				if rcode, ok := err.(dns.RCodeError); ok {
					thisErr = errors.New(dnsmessage.RCode(rcode).String())
				}
				ipv4Flag := "-"
				ipv6Flag := "-"
				fakeFlag := "-"
				s.Lock()
				if option.IPv4Enable {
					ipv4Flag = "+"
				}
				if option.IPv6Enable {
					ipv6Flag = "+"
				}
				if option.FakeEnable {
					fakeFlag = "+"
				}
				s.lastErr = fmt.Errorf(`query "%v" [%vIPv4 %vIPv6 %vFakeDNS] failed: %v`, fqdn, ipv4Flag, ipv6Flag, fakeFlag, thisErr)
				s.Unlock()
				s.emitCounter("query_failure", 1)
			}
			return ips, ttl, err
		}

		select {
		case <-ctx.Done():
			s.emitCounter("query_timeout", 1)
			return nil, 0, ctx.Err()
		case <-done:
		}
	}
}
