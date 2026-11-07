package engine

import (
	"context"
	"sync"
	"time"

	"ksu_proxy_manager/internal/clashapi"
)

type TrafficPoint struct {
	Time string `json:"t"`
	Up   int64  `json:"up"`
	Down int64  `json:"down"`
}

type TrafficSnapshot struct {
	Up          int64          `json:"up"`
	Down        int64          `json:"down"`
	UpTotal     int64          `json:"upTotal"`
	DownTotal   int64          `json:"downTotal"`
	Connections int            `json:"connections"`
	History     []TrafficPoint `json:"history"`
}

// trafficSampler derives throughput from the controller's connection totals,
// which both cores expose identically.
type trafficSampler struct {
	mu      sync.Mutex
	cancel  context.CancelFunc
	last    TrafficSnapshot
	lastAt  time.Time
	history []TrafficPoint
}

func newTrafficSampler() *trafficSampler { return &trafficSampler{} }

func (s *trafficSampler) start(parent context.Context, api *clashapi.Client) {
	s.reset()
	ctx, cancel := context.WithCancel(parent)
	s.mu.Lock()
	s.cancel = cancel
	s.mu.Unlock()
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				c, cancelReq := context.WithTimeout(ctx, 2*time.Second)
				conns, err := api.Connections(c)
				cancelReq()
				if err == nil {
					s.record(conns.UploadTotal, conns.DownloadTotal, len(conns.Connections))
				}
			}
		}
	}()
}

func (s *trafficSampler) record(up, down int64, n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if !s.lastAt.IsZero() {
		dt := now.Sub(s.lastAt).Seconds()
		if dt > 0 {
			s.last.Up = max64(0, int64(float64(up-s.last.UpTotal)/dt))
			s.last.Down = max64(0, int64(float64(down-s.last.DownTotal)/dt))
		}
	}
	s.last.UpTotal, s.last.DownTotal, s.last.Connections = up, down, n
	s.lastAt = now
	s.history = append(s.history, TrafficPoint{Time: now.UTC().Format("15:04:05"), Up: s.last.Up, Down: s.last.Down})
	if len(s.history) > 120 {
		s.history = s.history[len(s.history)-120:]
	}
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func (s *trafficSampler) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
	s.last = TrafficSnapshot{}
	s.lastAt = time.Time{}
	s.history = nil
}

func (s *trafficSampler) snapshot() TrafficSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.last
	out.History = append([]TrafficPoint(nil), s.history...)
	return out
}
