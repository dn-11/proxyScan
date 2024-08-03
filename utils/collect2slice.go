package utils

type Collector[T any] struct {
	C     chan T
	slice []T
	done  chan struct{}
}

func NewCollector[T any]() *Collector[T] {
	c := &Collector[T]{
		C:    make(chan T, 16),
		done: make(chan struct{}),
	}
	go func() {
		for v := range c.C {
			c.slice = append(c.slice, v)
		}
		c.done <- struct{}{}
	}()
	return c
}

func (c *Collector[T]) Return() []T {
	close(c.C)
	<-c.done
	return c.slice
}
