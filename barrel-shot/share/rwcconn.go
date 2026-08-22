package share

import (
	"io"
	"net"
	"time"
)

type rwcConn struct {
	io.ReadWriteCloser
}

func NewRWCConn(rwc io.ReadWriteCloser) net.Conn {
	return &rwcConn{ReadWriteCloser: rwc}
}

func (c *rwcConn) LocalAddr() net.Addr                { return dummyAddr{} }
func (c *rwcConn) RemoteAddr() net.Addr               { return dummyAddr{} }
func (c *rwcConn) SetDeadline(t time.Time) error      { return nil }
func (c *rwcConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *rwcConn) SetWriteDeadline(t time.Time) error { return nil }

func (c *rwcConn) CloseWrite() error {
	if cw, ok := c.ReadWriteCloser.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return c.Close()
}

type dummyAddr struct{}

func (dummyAddr) Network() string { return "tcp" }
func (dummyAddr) String() string  { return "pipe" }
