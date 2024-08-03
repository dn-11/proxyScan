package pool

import (
	"context"
	"log"
)

type Worker struct {
	ctx    context.Context
	cancel context.CancelFunc

	Func chan func()
}

func NewWorker(f chan func()) *Worker {
	w := &Worker{Func: f}
	w.ctx, w.cancel = context.WithCancel(context.Background())
	return w
}

func (w *Worker) Run() {
	defer func() {
		if r := recover(); r != nil {
			log.Println("Recovered ", r)
		}
	}()

	for {
		select {
		case f := <-w.Func:
			if f == nil {
				return
			}
			f()
		case <-w.ctx.Done():
			return
		}
	}
}

func (w *Worker) Cancel() {
	w.cancel()
}
