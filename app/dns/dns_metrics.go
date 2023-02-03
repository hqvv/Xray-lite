// Package dns is an implementation of core.DNS feature.
package dns

import (
	"github.com/xtls/xray-core/features/dns"
)

type DumpCacheItem struct {
	A          []string `json:"A"`
	AExpire    int64    `json:"A_expire"`
	AAAA       []string `json:"AAAA"`
	AAAAExpire int64    `json:"AAAA_expire"`
}

type DumpCache struct {
	Cache     map[string]*DumpCacheItem `json:"cache"`
	LastError string                    `json:"last_error"`
}

func (s *DNS) DumpCache() map[string]*DumpCache {
	s.Lock()
	defer s.Unlock()
	result := make(map[string]*DumpCache, len(s.clients))
	for _, x := range s.clients {
		name := x.Name()
		if b, ok := x.server.(*NameServerBase); ok {
			d := &DumpCache{
				Cache:     map[string]*DumpCacheItem{},
				LastError: "no errors",
			}
			if b.lastErr != nil {
				d.LastError = b.lastErr.Error()
			}
			for k, v := range b.ips {
				item := &DumpCacheItem{
					A:    []string{},
					AAAA: []string{},
				}
				if ipv4, err := v.A.getIPs(); err == nil {
					for _, i := range ipv4 {
						item.A = append(item.A, i.String())
					}
					item.AExpire = v.A.Expire.Unix()
				}
				if ipv6, err := v.AAAA.getIPs(); err == nil {
					for _, i := range ipv6 {
						item.AAAA = append(item.AAAA, i.String())
					}
					item.AAAAExpire = v.AAAA.Expire.Unix()
				}
				if len(item.A)+len(item.AAAA) > 0 {
					d.Cache[k] = item
				}
			}
			result[name] = d
		}
	}
	return result
}

func (s *DNS) DumpFakeDNS() []*dns.FakeDNSDump {
	s.Lock()
	defer s.Unlock()
	for _, x := range s.clients {
		if b, ok := x.server.(*FakeDNSServer); ok && b != nil && b.fakeDNSEngine != nil {
			return b.fakeDNSEngine.Dump()
		}
	}
	return nil
}
