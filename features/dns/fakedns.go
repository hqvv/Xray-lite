package dns

import (
	"github.com/xtls/xray-core/common/cache"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features"
)

type FakeDNSDump struct {
	Pool       string                              `json:"pool"`
	Size       uint32                              `json:"size"`
	Cap        uint32                              `json:"cap"`
	QueryKey   uint32                              `json:"query_key"`
	QueryValue uint32                              `json:"query_value"`
	Items      []*cache.LruElement[string, string] `json:"items"`
}

type FakeDNSEngine interface {
	features.Feature
	GetFakeIPForDomain(domain string) []net.Address
	GetDomainFromFakeDNS(ip net.Address) string
	Dump() []*FakeDNSDump
}

var (
	FakeIPv4Pool = "198.18.0.0/15"
	FakeIPv6Pool = "fc00::/18"
)

type FakeDNSEngineRev0 interface {
	FakeDNSEngine
	IsIPInIPPool(ip net.Address) bool
	GetFakeIPForDomain3(domain string, IPv4, IPv6 bool) []net.Address
}
