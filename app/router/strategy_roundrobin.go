package router

import (
	"context"

	"github.com/xtls/xray-core/app/observatory"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/extension"
)

type RoundRobinStrategy struct {
	ctx         context.Context
	observatory extension.Observatory
	index       int
}

func (l *RoundRobinStrategy) InjectContext(ctx context.Context) {
	l.ctx = ctx
}

func (l *RoundRobinStrategy) PickOutbound(tags []string) string {
	if l.observatory == nil {
		_ = core.RequireFeatures(l.ctx, func(observatory extension.Observatory) {
			l.observatory = observatory
		})
	}

	l.index++
	if l.observatory == nil {
		return tags[l.index%len(tags)]
	}
	observeReport, err := l.observatory.GetObservation(l.ctx)
	if err != nil {
		newError("cannot get observe report").Base(err).WriteToLog()
		return tags[l.index%len(tags)]
	}
	if result, ok := observeReport.(*observatory.ObservationResult); ok {
		aliveTags := make([]string, 0, len(result.Status))
		for _, v := range result.Status {
			for _, f := range tags {
				if v.OutboundTag == f {
					if v.Alive {
						aliveTags = append(aliveTags, v.OutboundTag)
					}
				}
			}
		}
		if len(aliveTags) == 0 {
			return tags[l.index%len(tags)]
		}
		return aliveTags[l.index%len(aliveTags)]
	}

	// No way to understand observeReport
	return tags[l.index%len(tags)]
}
