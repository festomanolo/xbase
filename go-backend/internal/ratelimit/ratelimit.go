// Package ratelimit is a sharded in-memory token-bucket limiter.
package ratelimit

import (
	"hash/fnv"
	"math"
	"sync"
	"time"
)

const shards = 16

type bucket struct {
	tokens float64
	last   time.Time
}

type shard struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

type Limiter struct {
	rate, burst float64
	shards      [shards]shard
}

func New(ratePerSec, burst float64) *Limiter {
	l := &Limiter{rate: math.Max(ratePerSec, 0.001), burst: math.Max(burst, 1)}
	for i := range l.shards {
		l.shards[i].buckets = make(map[string]*bucket)
	}
	return l
}

func (l *Limiter) Burst() int { return int(l.burst) }

func (l *Limiter) shard(key string) *shard {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return &l.shards[h.Sum32()%shards]
}

// AllowAt consumes a token for key. It returns the remaining tokens, or the
// wait before the next token when denied.
func (l *Limiter) AllowAt(key string, now time.Time) (ok bool, remaining int, retryAfter time.Duration) {
	s := l.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	b, found := s.buckets[key]
	if !found {
		b = &bucket{tokens: l.burst, last: now}
		s.buckets[key] = b
	}
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = math.Min(l.burst, b.tokens+elapsed*l.rate)
	}
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true, int(b.tokens), 0
	}
	return false, 0, time.Duration((1 - b.tokens) / l.rate * float64(time.Second))
}

func (l *Limiter) Allow(key string) (bool, int, time.Duration) { return l.AllowAt(key, time.Now()) }

// Sweep removes buckets idle long enough to have refilled completely.
func (l *Limiter) Sweep() {
	idle := time.Duration(l.burst/l.rate*float64(time.Second)) + time.Minute
	now := time.Now()
	for i := range l.shards {
		s := &l.shards[i]
		s.mu.Lock()
		for k, b := range s.buckets {
			if now.Sub(b.last) > idle {
				delete(s.buckets, k)
			}
		}
		s.mu.Unlock()
	}
}
