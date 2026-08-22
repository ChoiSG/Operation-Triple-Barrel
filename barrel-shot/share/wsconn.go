package share

import (
	"net"
	"time"

	"github.com/gorilla/websocket"
)

type wsConn struct {
	*websocket.Conn
	buff []byte
}

func NewWSConn(ws *websocket.Conn) net.Conn {
	return &wsConn{Conn: ws}
}

func (c *wsConn) Read(dst []byte) (int, error) {
	var src []byte
	if len(c.buff) > 0 {
		src = c.buff
		c.buff = nil
	} else if _, msg, err := c.Conn.ReadMessage(); err == nil {
		src = msg
	} else {
		return 0, err
	}
	n := copy(dst, src)
	if n < len(src) {
		c.buff = make([]byte, len(src)-n)
		copy(c.buff, src[n:])
	}
	return n, nil
}

func (c *wsConn) Write(b []byte) (int, error) {
	if err := c.Conn.WriteMessage(websocket.BinaryMessage, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *wsConn) SetDeadline(t time.Time) error {
	if err := c.Conn.SetReadDeadline(t); err != nil {
		return err
	}
	return c.Conn.SetWriteDeadline(t)
}
