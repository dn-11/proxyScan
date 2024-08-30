package utils

import (
	"golang.org/x/time/rate"
	"log"
	"math"
	"time"
)

func ParseLimiter(r int) *rate.Limiter {
	var interval rate.Limit
	var b int
	if r <= 0 {
		log.Printf("rate unlimited mode")
		interval = rate.Inf
		b = math.MaxInt
	} else {
		log.Printf("rate %d/s", r)
		interval = rate.Every(time.Second / time.Duration(r))
		b = r / 200
	}

	return rate.NewLimiter(interval, b)
}
