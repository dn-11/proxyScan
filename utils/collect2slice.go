package utils

type Collector[T any] struct {
	C     chan T
	slice []T
}

func NewCollector[T any]() *Collector[T] {
	c := &Collector[T]{
		C: make(chan T),
	}
	go func() {
		for v := range c.C {
			c.slice = append(c.slice, v)
		}
	}()
	return c
}

func (c *Collector[T]) Return() []T {
	close(c.C)
	return c.slice
}
