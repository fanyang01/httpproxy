package httpproxy

import (
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"
	"sync/atomic"
	"time"
)

type BufferPool struct {
	pool sync.Pool
	size int
}

func NewBufferPool(size int) *BufferPool {
	return &BufferPool{
		size: size,
		pool: sync.Pool{
			New: func() interface{} {
				return make([]byte, size)
			},
		},
	}
}

func (bp *BufferPool) Get() []byte {
	if bp != nil {
		return bp.pool.Get().([]byte)
	}
	return make([]byte, 4096)
}

func (bp *BufferPool) Put(b []byte) {
	if bp != nil {
		bp.pool.Put(b)
	}
}

type flushWriter struct{ w io.Writer }

func (fw flushWriter) Write(p []byte) (n int, err error) {
	n, err = fw.w.Write(p)
	if f, ok := fw.w.(http.Flusher); ok {
		f.Flush()
	}
	return
}

type condReader struct {
	r    io.Reader
	quit uint32
}

func (cr condReader) Read(p []byte) (n int, err error) {
	if atomic.LoadUint32(&cr.quit) > 0 {
		return 0, io.EOF
	}
	return cr.r.Read(p)
}

type Proxy struct {
	BufferPool       *BufferPool
	ReverseProxy     *httputil.ReverseProxy
	Auth             func(*http.Request) bool
	Logger           *log.Logger
	CloseServerWrite bool
}

var DefaultReverseProxy = &httputil.ReverseProxy{
	Director: func(_ *http.Request) {},
}

func (p *Proxy) proxy(rw http.ResponseWriter, req *http.Request) {
	if p.ReverseProxy != nil {
		p.ReverseProxy.ServeHTTP(rw, req)
	} else {
		DefaultReverseProxy.ServeHTTP(rw, req)
	}
}

func (p *Proxy) auth(req *http.Request) bool {
	if p.Auth != nil {
		return p.Auth(req)
	}
	return true
}

func (p *Proxy) logf(fmt string, args ...interface{}) {
	if p.Logger == nil {
		log.Printf(fmt, args...)
	} else {
		p.Logger.Printf(fmt, args...)
	}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if !p.auth(req) {
		code := http.StatusProxyAuthRequired
		p.logf("[WARNING] %s: %v", http.StatusText(code), req.URL)
		w.WriteHeader(code)
		return
	} else if req.Method != "CONNECT" {
		p.proxy(w, req)
		return
	}

	srvConn, err := net.Dial("tcp", req.URL.Host)
	if err != nil {
		p.logf("[ERROR] %v", err)
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	p.logf("[DEBUG] connect to %v successfully", req.URL.Host)
	writeClosed := false
	defer func() {
		if !writeClosed {
			srvConn.Close()
		} else {
			srvConn.(*net.TCPConn).CloseRead()
		}
	}()

	header := w.Header()
	header["Date"] = nil
	header["Content-Type"] = nil
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	var (
		cliConn net.Conn
		rw      io.ReadWriter
	)
	if hijacker, ok := w.(http.Hijacker); ok {
		// HTTP/1.x
		conn, brw, err := hijacker.Hijack()
		if err != nil {
			p.logf("[ERROR] hijack connection: %v", err)
			return
		}
		defer conn.Close()
		defer brw.Flush()
		p.logf("[DEBUG] connection hijacked")

		cliConn, rw = conn, brw
	} else {
		// HTTP/2
		cliConn = &proxyConn{Request: req, ResponseWriter: w}
		rw = cliConn
	}

	up := make(chan struct{})
	down := make(chan struct{})
	// client -> server
	go func() {
		buf := p.BufferPool.Get()
		n, err := io.CopyBuffer(srvConn, rw, buf)
		if err != nil {
			p.logf("[ERROR] copy stream(client -> server): %v", err)
		}
		p.logf("[DEBUG] %v -> %v: %d bytes copied", cliConn.RemoteAddr(), srvConn.RemoteAddr(), n)
		p.BufferPool.Put(buf)
		close(up)
	}()
	// server -> client
	go func() {
		buf := p.BufferPool.Get()
		n, err := io.CopyBuffer(rw, srvConn, buf)
		if err != nil {
			p.logf("[ERROR] copy stream(server -> client): %v", err)
		}
		p.logf("[DEBUG] %v -> %v: %d bytes copied", srvConn.RemoteAddr(), cliConn.RemoteAddr(), n)
		p.BufferPool.Put(buf)
		close(down)
	}()

	if <-up; p.CloseServerWrite {
		srvConn.(*net.TCPConn).CloseWrite()
		writeClosed = true
	}
	<-down
}

type proxyConn struct {
	*http.Request
	http.ResponseWriter
}

func (p *proxyConn) Read(b []byte) (n int, err error) {
	return p.Request.Body.Read(b)
}

func (p *proxyConn) Write(b []byte) (n int, err error) {
	return p.ResponseWriter.Write(b)
}

func (p *proxyConn) Close() error {
	return p.Request.Body.Close()
}

func (p *proxyConn) LocalAddr() net.Addr {
	// go1.7
	// return p.Request.Context().Value(http.LocalAddrContextKey).(net.Addr)
	addr, _ := net.ResolveTCPAddr("tcp", "0.0.0.0:80")
	return addr
}

func (p *proxyConn) RemoteAddr() net.Addr {
	addr, _ := net.ResolveTCPAddr("tcp", p.Request.RemoteAddr)
	return addr
}

func (p *proxyConn) SetDeadline(t time.Time) error      { return nil }
func (p *proxyConn) SetReadDeadline(t time.Time) error  { return nil }
func (p *proxyConn) SetWriteDeadline(t time.Time) error { return nil }
