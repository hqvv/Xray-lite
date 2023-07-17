package router

import (
	"context"

	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/extension"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/stats"
)

type BalancingStrategy interface {
	PickOutbound([]string) string
}

type RandomStrategy struct{}

func (s *RandomStrategy) PickOutbound(tags []string) string {
	n := len(tags)
	if n == 0 {
		panic("0 tags")
	}

	return tags[dice.Roll(n)]
}

type Balancer struct {
	tag       string
	selectors []string
	strategy  BalancingStrategy
	ohm       outbound.Manager
	sm        stats.Manager
}

func (b *Balancer) PickOutbound() (string, error) {
	hs, ok := b.ohm.(outbound.HandlerSelector)
	if !ok {
		return "", newError("outbound.Manager is not a HandlerSelector")
	}
	tags := hs.Select(b.selectors)
	if len(tags) == 0 {
		return "", newError("no available outbounds selected")
	}
	tag := b.strategy.PickOutbound(tags)
	if tag == "" {
		return "", newError("balancing strategy returns empty tag")
	}
	if b.sm != nil {
		name := "balancer>>>" + b.tag + ">>>pick>>>" + tag
		if c, _ := stats.GetOrRegisterCounter(b.sm, name); c != nil {
			c.Add(1)
		}
	}
	return tag, nil
}

func (b *Balancer) InjectContext(ctx context.Context) {
	if b.sm == nil {
		if x := core.FromContext(ctx); x != nil {
			_ = x.RequireFeatures(func(sm stats.Manager) {
				b.sm = sm
			})
		}
	}
	if contextReceiver, ok := b.strategy.(extension.ContextReceiver); ok {
		contextReceiver.InjectContext(ctx)
	}
}
