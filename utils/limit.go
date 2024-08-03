package utils

import (
	"golang.org/x/time/rate"
	"time"
)

func ParseLimiter(r int) *rate.Limiter {
	var interval rate.Limit
	if r == -1 {
		interval = rate.Inf
	} else {
		interval = rate.Every(time.Duration(1/float64(r)) * time.Second)
	}
	return rate.NewLimiter(interval, 16)
}
