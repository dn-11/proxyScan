package utils

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestTTLSet1(t *testing.T) {
	set := NewTTLSet[int](time.Second)
	set.Add(1)
	set.Add(2)
	assert.Equal(t, true, set.Exist(1))
	time.Sleep(time.Second)
	assert.Equal(t, false, set.Exist(1))
	set.Add(1)
	set.Add(2)
	wait := make(chan struct{})
	go func() {
		t1 := time.Now()
		set.Wait()
		dur := time.Since(t1)
		assert.Equal(t, true, dur > time.Duration(float64(time.Second)*1.4))
		wait <- struct{}{}
	}()
	time.Sleep(time.Second / 2)
	set.Add(3)
	<-wait
}
func TestTTLSet2(t *testing.T) {
	set := NewTTLSet[int](time.Second)
	go func() {
		for i := 0; i < 1000; i++ {
			set.Add(i)
			time.Sleep(time.Millisecond)
		}
	}()
	go func() {
		for i := 0; i < 1000; i++ {
			set.Exist(i)
			time.Sleep(time.Millisecond)
		}
	}()
	begin := time.Now()
	time.Sleep(time.Second / 2)
	set.Wait()
	t.Log(time.Since(begin))
}
