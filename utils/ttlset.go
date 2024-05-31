package utils

import (
	"sync"
	"time"
)

// TTLSet a set that can set ttl
// Attention: this is not a thread-safe set
type TTLSet[K comparable] struct {
	m    map[K]time.Time
	ttl  time.Duration
	t    *time.Timer
	lock sync.Mutex
}

func NewTTLSet[K comparable](ttl time.Duration) *TTLSet[K] {
	s := &TTLSet[K]{}
	s.m = make(map[K]time.Time)
	s.ttl = ttl
	s.t = time.NewTimer(ttl)
	return s
}

func (s *TTLSet[K]) Add(k K) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.m[k] = time.Now().Add(s.ttl)
	select {
	case <-s.t.C:
		now := time.Now()
		for k, v := range s.m {
			if v.Before(now) {
				delete(s.m, k)
			}
		}
	default:
	}
}

// Take don't check ttl, also remove the key
func (s *TTLSet[K]) Take(k K) bool {
	s.lock.Lock()
	defer s.lock.Unlock()
	_, ok := s.m[k]
	if ok {
		delete(s.m, k)
	}
	return ok
}

// Wait all key to be expired
func (s *TTLSet[K]) Wait() {
	t := time.Now()
	for _, v := range s.m {
		if v.After(t) {
			t = v
		}
	}
	time.Sleep(t.Sub(time.Now()))
}
