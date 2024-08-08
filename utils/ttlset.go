package utils

import (
	"sync"
	"sync/atomic"
	"time"
)

// TTLSet a set that can set ttl
// Attention: this is not a thread-safe set
type TTLSet[K comparable] struct {
	old map[K]time.Time
	m   map[K]time.Time

	expireAll atomic.Pointer[time.Time]
	ttl       time.Duration
	t         *time.Timer
	lock      sync.Mutex
}

func NewTTLSet[K comparable](ttl time.Duration) *TTLSet[K] {
	s := &TTLSet[K]{
		old: make(map[K]time.Time),
		m:   make(map[K]time.Time),
		ttl: ttl,
		t:   time.NewTimer(ttl),
	}
	now := new(time.Time)
	*now = time.Now()
	s.expireAll.Store(now)
	return s
}

func (s *TTLSet[K]) Add(k K) {
	s.checkRotate(true)

	expire := time.Now().Add(s.ttl)
	s.updateExpireAll(expire)

	s.lock.Lock()
	defer s.lock.Unlock()
	s.m[k] = expire
}

func (s *TTLSet[K]) Exist(k K) bool {
	s.checkRotate(true)

	entry, ok := s.old[k]
	if ok && entry.After(time.Now()) {
		return true
	}

	s.lock.Lock()
	defer s.lock.Unlock()
	entry, ok = s.m[k]
	return ok && entry.After(time.Now())
}

// Wait all key to be expired
func (s *TTLSet[K]) Wait() {
	s.t.Stop()
	s.checkRotate(false)

	for {
		offset := s.expireAll.Load().Sub(time.Now())
		if offset <= 0 {
			break
		}
		time.Sleep(offset)
	}
}

func (s *TTLSet[K]) checkRotate(rotate bool) {
	select {
	case <-s.t.C:
		if rotate {
			s.old = s.m
			s.m = make(map[K]time.Time)
		}
	default:
	}
}

func (s *TTLSet[K]) updateExpireAll(t time.Time) {
	for {
		old := s.expireAll.Load()
		if old.After(t) {
			return
		}
		if s.expireAll.CompareAndSwap(old, &t) {
			return
		}
	}
}
