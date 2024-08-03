package pool

import (
	"context"
	"log"
)

type Worker struct {
	Func   chan func()
	Cancel context.CancelFunc
}

type Pool struct {
	Size    int
	Buffer  int
	tasks   chan func()
	workers []*Worker
}

func NewDefaultPool() *Pool {
	p := &Pool{Size: 128, Buffer: 1024}
	p.Init()
	return p
}

func (p *Pool) Init() {
	p.tasks = make(chan func(), p.Buffer)
	for i := 0; i < p.Size; i++ {
		worker := &Worker{
			Func: p.tasks,
		}
		p.workers = append(p.workers, worker)
		go worker.Run()
	}
}

func (p *Pool) Submit(f func()) {
	p.tasks <- f
}

func (w *Worker) Run() {
	defer func() {
		if r := recover(); r != nil {
			log.Println("Recovered ", r)
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	w.Cancel = cancel
	for {
		select {
		case f := <-w.Func:
			f()
		case <-ctx.Done():
			return
		}
	}
}

func (p *Pool) Close() {
	for _, w := range p.workers {
		w.Cancel()
	}
}
