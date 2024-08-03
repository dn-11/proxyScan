package pool

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
	p.workers = make([]*Worker, p.Size)
	for i := 0; i < p.Size; i++ {
		p.workers[i] = NewWorker(p.tasks)
		go p.workers[i].Run()
	}
}

func (p *Pool) Submit(f func()) {
	p.tasks <- f
}

func (p *Pool) Close() {
	for _, w := range p.workers {
		w.Cancel()
	}
}
