package metrics

import (
	"context"
	"expvar"
	"net/http"
	_ "net/http/pprof"
	"runtime"
	"strings"
	"time"

	"github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/app/observatory"
	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/core"
	feature_dns "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/extension"
	"github.com/xtls/xray-core/features/outbound"
	feature_stats "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport/internet/tls"
)

type MetricsHandler struct {
	ohm          outbound.Manager
	statsManager feature_stats.Manager
	observatory  extension.Observatory
	dns          *dns.DNS
	tag          string
	startTime    time.Time
}

// NewMetricsHandler creates a new metricsHandler based on the given config.
func NewMetricsHandler(ctx context.Context, config *Config) (*MetricsHandler, error) {
	c := &MetricsHandler{
		tag:       config.Tag,
		startTime: time.Now(),
	}
	common.Must(core.RequireFeatures(ctx, func(om outbound.Manager, sm feature_stats.Manager, d feature_dns.Client) {
		c.statsManager = sm
		c.ohm = om
		if dt, ok := d.(*dns.DNS); ok {
			c.dns = dt
		}
	}))
	expvar.Publish("version", expvar.Func(func() any {
		return map[string]interface{}{
			"version":           core.Version(),
			"version_statement": core.VersionStatement(),
		}
	}))
	expvar.Publish("random_tls_fingerprint", expvar.Func(func() any {
		return map[string]string{
			"client":  tls.PresetFingerprints["random"].Client,
			"version": tls.PresetFingerprints["random"].Version,
		}
	}))
	expvar.Publish("dns", expvar.Func(func() any {
		if c.dns == nil {
			return nil
		}
		return c.dns.DumpCache()
	}))
	expvar.Publish("fake_dns", expvar.Func(func() any {
		if c.dns == nil {
			return nil
		}
		return c.dns.DumpFakeDNS()
	}))
	expvar.Publish("core", expvar.Func(func() interface{} {
		var aesGcm int64 = 0
		if protocol.HasAESGCMHardwareSupport {
			aesGcm = 1
		}
		return map[string]map[string]int64{
			"runtime": {
				"numgos": int64(runtime.NumGoroutine()),
				"uptime": int64(time.Since(c.startTime).Seconds()),
			},
			"system": {
				"aesgcm": aesGcm,
				"numcpu": int64(runtime.NumCPU()),
			},
		}
	}))
	expvar.Publish("stats", expvar.Func(func() interface{} {
		manager, ok := c.statsManager.(*stats.Manager)
		if !ok {
			return nil
		}
		resp := map[string]map[string]map[string]int64{
			"inbound":  {},
			"outbound": {},
			"user":     {},
			"balancer": {},
			"dns":      {},
		}
		manager.VisitCounters(func(name string, counter feature_stats.Counter) bool {
			nameSplit := strings.Split(name, ">>>")
			typeName, tagOrUser, direction := nameSplit[0], nameSplit[1], nameSplit[3]
			if item, found := resp[typeName][tagOrUser]; found {
				item[direction] = counter.Value()
			} else {
				resp[typeName][tagOrUser] = map[string]int64{
					direction: counter.Value(),
				}
			}
			return true
		})
		return resp
	}))
	expvar.Publish("observatory", expvar.Func(func() interface{} {
		if c.observatory == nil {
			common.Must(core.RequireFeatures(ctx, func(observatory extension.Observatory) error {
				c.observatory = observatory
				return nil
			}))
			if c.observatory == nil {
				return nil
			}
		}
		resp := map[string]*observatory.OutboundStatus{}
		if o, err := c.observatory.GetObservation(context.Background()); err != nil {
			return err
		} else {
			for _, x := range o.(*observatory.ObservationResult).GetStatus() {
				resp[x.OutboundTag] = x
			}
		}
		return resp
	}))
	return c, nil
}

func (p *MetricsHandler) Type() interface{} {
	return (*MetricsHandler)(nil)
}

func (p *MetricsHandler) Start() error {
	listener := &OutboundListener{
		buffer: make(chan net.Conn, 4),
		done:   done.New(),
	}

	go func() {
		if err := http.Serve(listener, http.DefaultServeMux); err != nil {
			newError("failed to start metrics server").Base(err).AtError().WriteToLog()
		}
	}()

	if err := p.ohm.RemoveHandler(context.Background(), p.tag); err != nil {
		newError("failed to remove existing handler").WriteToLog()
	}

	return p.ohm.AddHandler(context.Background(), &Outbound{
		tag:      p.tag,
		listener: listener,
	})
}

func (p *MetricsHandler) Close() error {
	return nil
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, cfg interface{}) (interface{}, error) {
		return NewMetricsHandler(ctx, cfg.(*Config))
	}))
}
