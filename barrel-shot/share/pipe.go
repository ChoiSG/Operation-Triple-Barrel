package share

import (
	"io"
	"sync"
)

func Pipe(a, b io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(b, a)
		closeWrite(b)
	}()
	go func() {
		defer wg.Done()
		io.Copy(a, b)
		closeWrite(a)
	}()
	wg.Wait()
	a.Close()
	b.Close()
}

type closeWriter interface {
	CloseWrite() error
}

func closeWrite(c io.ReadWriteCloser) {
	if cw, ok := c.(closeWriter); ok {
		cw.CloseWrite()
		return
	}
	c.Close()
}
