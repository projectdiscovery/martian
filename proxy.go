// Copyright 2015 Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package martian

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/projectdiscovery/martian/v3/log"
	"github.com/projectdiscovery/martian/v3/mitm"
	"github.com/projectdiscovery/martian/v3/nosigpipe"
	"github.com/projectdiscovery/martian/v3/proxyutil"
	"github.com/projectdiscovery/martian/v3/trafficshape"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"golang.org/x/net/proxy"
)

var (
	errClientClosedConnection = errors.New("client closed connections")
	errWebSocketNotSupported  = errors.New("web socket not supported")
	errClose                  = errors.New("closing connection")
	errWinWsa                 = errors.New("windows wsarecv/wsasend")
)

var noop = Noop("martian")

func isCloseable(err error) bool {
	if err == nil {
		return false
	}

	if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
		return true
	}

	if errors.Is(err, errWebSocketNotSupported) {
		return true
	}

	// ignore client aborted websocket connection (due to websocket)
	if errors.Is(err, errClientClosedConnection) {
		return true
	}

	// Ignore windows wsarecv/wsasend trying to send data on websocket aborted connection
	if errors.Is(err, errWinWsa) {
		return true
	}

	switch err {
	case io.EOF, io.ErrClosedPipe, errClose:
		return true
	}

	return false
}

type Miscellaneous struct {
	// Set "Connection" header on incoming requests when using HTTP/1
	SetH1ConnectionHeader bool
	// Strip Proxy-* headers in incoming requests
	StripProxyHeaders bool
	// Ignore web socket errors
	IgnoreWebSocketError bool
	// Ignore client closed connections
	IgnoreClientClosedConnection bool
}

// Proxy is an HTTP proxy with support for TLS MITM and customizable behavior.
type Proxy struct {
	Miscellaneous      Miscellaneous
	TLSPassthroughFunc func(req *http.Request) bool // Callback function to skip mitm
	roundTripper       http.RoundTripper
	dialContext        func(context.Context, string, string) (net.Conn, error)
	timeout            time.Duration
	mitm               *mitm.Config
	proxyURL           *url.URL
	conns              sync.WaitGroup
	connsMu            sync.Mutex // protects conns.Add/Wait from concurrent access
	closing            chan bool
	reqmod             RequestModifier
	resmod             ResponseModifier
}

// NewProxy returns a new HTTP proxy.
func NewProxy() *Proxy {
	proxy := &Proxy{
		roundTripper: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
		},
		timeout: 5 * time.Minute,
		closing: make(chan bool),
		reqmod:  noop,
		resmod:  noop,
	}
	proxy.SetDialContext((&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext)
	return proxy
}

// GetRoundTripper gets the http.RoundTripper of the proxy.
func (p *Proxy) GetRoundTripper() http.RoundTripper {
	return p.roundTripper
}

// SetRoundTripper sets the http.RoundTripper of the proxy.
func (p *Proxy) SetRoundTripper(rt http.RoundTripper) {
	p.roundTripper = rt

	if tr, ok := p.roundTripper.(*http.Transport); ok {
		tr.Proxy = http.ProxyURL(p.proxyURL)
		tr.DialContext = p.dialContext
	}
}

// SetDownstreamProxy sets the proxy that receives requests from the upstream
// proxy.
func (p *Proxy) SetDownstreamProxy(proxyURL *url.URL) {
	p.proxyURL = proxyURL

	if tr, ok := p.roundTripper.(*http.Transport); ok {
		tr.Proxy = http.ProxyURL(p.proxyURL)
	}
}

// SetTimeout sets the request timeout of the proxy.
func (p *Proxy) SetTimeout(timeout time.Duration) {
	p.timeout = timeout
}

// SetMITM sets the config to use for MITMing of CONNECT requests.
func (p *Proxy) SetMITM(config *mitm.Config) {
	p.mitm = config
}

type DialFunc func(context.Context, string, string) (net.Conn, error)

// SetDial sets the dial func used to establish a connection.
func (p *Proxy) SetDialContext(dialContext DialFunc) {
	p.dialContext = func(ctx context.Context, a, b string) (net.Conn, error) {
		c, e := dialContext(ctx, a, b)
		nosigpipe.IgnoreSIGPIPE(c)
		return c, e
	}

	if tr, ok := p.roundTripper.(*http.Transport); ok {
		tr.DialContext = p.dialContext
	}
}

// Close sets the proxy to the closing state so it stops receiving new connections,
// finishes processing any inflight requests, and closes existing connections without
// reading anymore requests from them.
func (p *Proxy) Close() {
	log.Infof("martian: closing down proxy")

	close(p.closing)

	log.Infof("martian: waiting for connections to close")
	p.connsMu.Lock()
	p.conns.Wait()
	p.connsMu.Unlock()
	log.Infof("martian: all connections closed")
}

// Closing returns whether the proxy is in the closing state.
func (p *Proxy) Closing() bool {
	select {
	case <-p.closing:
		return true
	default:
		return false
	}
}

// SetRequestModifier sets the request modifier.
func (p *Proxy) SetRequestModifier(reqmod RequestModifier) {
	if reqmod == nil {
		reqmod = noop
	}

	p.reqmod = reqmod
}

// SetResponseModifier sets the response modifier.
func (p *Proxy) SetResponseModifier(resmod ResponseModifier) {
	if resmod == nil {
		resmod = noop
	}

	p.resmod = resmod
}

// Serve accepts connections from the listener and handles the requests.
func (p *Proxy) Serve(l net.Listener) error {
	defer l.Close()

	var delay time.Duration
	for {
		if p.Closing() {
			return nil
		}

		conn, err := l.Accept()
		nosigpipe.IgnoreSIGPIPE(conn)
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				if delay == 0 {
					delay = 5 * time.Millisecond
				} else {
					delay *= 2
				}
				if max := time.Second; delay > max {
					delay = max
				}

				log.Debugf("martian: temporary error on accept: %v", err)
				time.Sleep(delay)
				continue
			}

			if errors.Is(err, net.ErrClosed) {
				log.Debugf("martian: listener closed, returning")
				return err
			}

			log.Errorf("martian: failed to accept: %v", err)
			return err
		}
		delay = 0
		log.Debugf("martian: accepted connection from %s", conn.RemoteAddr())

		if tconn, ok := conn.(*net.TCPConn); ok {
			if err := tconn.SetKeepAlive(true); err != nil {
				log.Debugf("%s\n", err)
			}
			if err := tconn.SetKeepAlivePeriod(3 * time.Second); err != nil {
				log.Debugf("%s\n", err)
			}
		}

		// clients create new connection to proxy server
		// everytime request is sent to different connection
		p.conns.Add(1)

		go p.handleLoop(conn)
	}
}

func (p *Proxy) handleLoop(conn net.Conn) {
	// p.connsMu.Lock()
	// p.conns.Add(1)
	// p.connsMu.Unlock()
	defer p.conns.Done()
	defer conn.Close()
	if p.Closing() {
		return
	}

	brw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))

	s, err := newSession(conn, brw)
	if err != nil {
		log.Errorf("martian: failed to create session: %v", err)
		return
	}

	ctx, err := withSession(s)
	if err != nil {
		log.Errorf("martian: failed to create context: %v", err)
		return
	}

	for {
		deadline := time.Now().Add(p.timeout)
		if err := conn.SetDeadline(deadline); err != nil {
			log.Debugf("%s\n", err)
		}

		if err := p.handle(ctx, conn, brw); isCloseable(err) {
			log.Debugf("martian: closing connection: %v", conn.RemoteAddr())
			return
		}
	}
}

func (p *Proxy) readRequest(ctx *Context, conn net.Conn, brw *bufio.ReadWriter) (*http.Request, error) {
	var req *http.Request
	reqc := make(chan *http.Request, 1)
	errc := make(chan error, 1)
	go func() {
		r, err := http.ReadRequest(brw.Reader)

		hasWebSocket := r != nil && r.Header.Get("upgrade") == "websocket"
		if hasWebSocket && p.Miscellaneous.IgnoreWebSocketError {
			err = errWebSocketNotSupported
		}

		// Ref: https://groups.google.com/g/golang-nuts/c/QDyL1fz8FNQ/m/0yT7NunPGY8J
		clientClosedConnection := r == nil && errors.Is(err, io.EOF)
		if clientClosedConnection && p.Miscellaneous.IgnoreClientClosedConnection {
			err = errors.Join(err, errClientClosedConnection)
		}

		// win trying to wsasend/wsarecv on websocket aborted conn
		if err != nil && stringsutil.ContainsAnyI(err.Error(), "wsarecv", "wsasend") {
			err = errors.Join(err, errWinWsa)
		}

		if err != nil {
			errc <- err
			return
		}

		// Miscellaneous Changes
		if p.Miscellaneous.SetH1ConnectionHeader && r.Header != nil {
			r.Header.Set("Connection", "close")
		}
		if p.Miscellaneous.StripProxyHeaders && r.Header != nil {
			for k := range r.Header {
				if stringsutil.HasPrefixI(k, "Proxy-") {
					r.Header.Del(k)
				}
			}
		}
		reqc <- r
	}()
	select {
	case err := <-errc:
		if isCloseable(err) {
			log.Debugf("martian: connection closed prematurely: %v", err)
		} else {
			log.Errorf("martian: failed to read request: %v", err)
		}

		// TODO: TCPConn.WriteClose() to avoid sending an RST to the client.

		return nil, errClose
	case req = <-reqc:
	case <-p.closing:
		return nil, errClose
	}

	// Setup a Reusable request body
	var tempBody io.ReadCloser = nil
	if req.ContentLength > 0 {
		bin, err := io.ReadAll(req.Body)
		if err == nil {
			tempBody = io.NopCloser(bytes.NewReader(bin))
		}
	}
	if tempBody != nil {
		req.Body = tempBody
	}
	return req, nil
}

func (p *Proxy) handleConnectRequest(ctx *Context, req *http.Request, session *Session, brw *bufio.ReadWriter, conn net.Conn) error {
	if err := p.reqmod.ModifyRequest(req); err != nil {
		log.Errorf("martian: error modifying CONNECT request: %v", err)
		proxyutil.Warning(req.Header, err)
	}
	if session.Hijacked() {
		log.Debugf("martian: connection hijacked by request modifier")
		return nil
	}

	shouldMitm := false
	// check if proxy should setup mitm for this connection
	if p.mitm != nil {
		shouldMitm = true
	}

	if p.TLSPassthroughFunc != nil {
		shouldMitm = !p.TLSPassthroughFunc(req)
	}

	// Setup Mitm Connection
	if shouldMitm {
		log.Debugf("martian: attempting MITM for connection: %s / %s", req.Host, req.URL.String())

		res := proxyutil.NewResponse(http.StatusOK, nil, req)

		if err := p.resmod.ModifyResponse(res); err != nil {
			log.Debugf("martian: error modifying CONNECT response: %v", err)
			proxyutil.Warning(res.Header, err)
		}
		if session.Hijacked() {
			log.Debugf("martian: connection hijacked by response modifier")
			return nil
		}

		if err := res.Write(brw); err != nil {
			log.Debugf("martian: got error while writing response back to client: %v", err)
		}
		if err := brw.Flush(); err != nil {
			log.Debugf("martian: got error while flushing response back to client: %v", err)
		}

		log.Debugf("martian: completed MITM for connection: %s", req.Host)

		var (
			b   []byte
			err error
		)
		b, err = brw.Peek(1)
		if err != nil {
			log.Debugf("martian: error peeking message through CONNECT tunnel to determine type: %v", err)
			return err
		}

		// Drain all of the rest of the buffered data.
		buf := make([]byte, brw.Reader.Buffered())
		if _, err := brw.Read(buf); err != nil {
			log.Debugf("%s\n", err)
		}

		// 22 is the TLS handshake.
		// https://tools.ietf.org/html/rfc5246#section-6.2.1
		// change_cipher_spec(20), alert(21), handshake(22),
		// application_data(23), (255)
		if b[0] == 22 {
			// Prepend the previously read data to be read again by
			// http.ReadRequest.
			tlsconn := tls.Server(&peekedConn{conn, io.MultiReader(bytes.NewReader(buf), conn)}, p.mitm.TLSForHost(req.Host))

			if err := tlsconn.Handshake(); err != nil {
				p.mitm.HandshakeErrorCallback(req, err)
				return err
			}
			if tlsconn.ConnectionState().NegotiatedProtocol == "h2" {
				return p.mitm.H2Config().Proxy(p.closing, tlsconn, req.URL)
			}

			var nconn net.Conn
			nconn = tlsconn
			// If the original connection is a traffic shaped connection, wrap the tls
			// connection inside a traffic shaped connection too.
			if ptsconn, ok := conn.(*trafficshape.Conn); ok {
				nconn = ptsconn.Listener.GetTrafficShapedConn(tlsconn)
			}
			brw.Writer.Reset(nconn)
			brw.Reader.Reset(nconn)
			return p.handle(ctx, nconn, brw)
		}

		// Prepend the previously read data to be read again by http.ReadRequest.
		brw.Reader.Reset(io.MultiReader(bytes.NewReader(buf), conn))
		return p.handle(ctx, conn, brw)
	}

	log.Debugf("martian: attempting to establish CONNECT tunnel: %s", req.URL.Host)
	res, cconn, cerr := p.connect(req)
	if cerr != nil {
		log.Errorf("martian: failed to CONNECT: %v", cerr)
		res = proxyutil.NewResponse(http.StatusBadGateway, nil, req)
		proxyutil.Warning(res.Header, cerr)

		if err := p.resmod.ModifyResponse(res); err != nil {
			log.Errorf("martian: error modifying CONNECT response: %v", err)
			proxyutil.Warning(res.Header, err)
		}
		if session.Hijacked() {
			log.Debugf("martian: connection hijacked by response modifier")
			return nil
		}

		if err := res.Write(brw); err != nil {
			log.Debugf("martian: got error while writing response back to client: %v", err)
		}
		err := brw.Flush()
		if err != nil {
			log.Debugf("martian: got error while flushing response back to client: %v", err)
		}
		return err
	}
	defer res.Body.Close()
	defer cconn.Close()

	if err := p.resmod.ModifyResponse(res); err != nil {
		log.Debugf("martian: error modifying CONNECT response: %v", err)
		proxyutil.Warning(res.Header, err)
	}
	if session.Hijacked() {
		log.Debugf("martian: connection hijacked by response modifier")
		return nil
	}

	res.ContentLength = -1
	if err := res.Write(brw); err != nil {
		log.Debugf("martian: got error while writing response back to client: %v", err)
	}
	if err := brw.Flush(); err != nil {
		log.Debugf("martian: got error while flushing response back to client: %v", err)
	}

	cbw := bufio.NewWriter(cconn)
	cbr := bufio.NewReader(cconn)
	defer cbw.Flush()

	copySync := func(w io.Writer, r io.Reader, donec chan<- bool, hostname string) {
		if _, err := io.Copy(w, r); err != nil && err != io.EOF {
			log.Debugf("martian: failed to copy CONNECT tunnel for %v: %v", hostname, err)
		}

		log.Debugf("martian: CONNECT tunnel finished copying")
		donec <- true
	}

	donec := make(chan bool, 2)
	go copySync(cbw, brw, donec, req.Host)
	go copySync(brw, cbr, donec, req.Host)

	log.Debugf("martian: established CONNECT tunnel, proxying traffic")
	<-donec
	<-donec
	log.Debugf("martian: closed CONNECT tunnel")

	return errClose
}

func (p *Proxy) handle(ctx *Context, conn net.Conn, brw *bufio.ReadWriter) error {
	log.Debugf("martian: waiting for request: %v", conn.RemoteAddr())

	req, err := p.readRequest(ctx, conn, brw)
	if err != nil {
		return err
	}
	defer req.Body.Close()

	session := ctx.Session()
	ctx, err = withSession(session)
	if err != nil {
		log.Errorf("martian: failed to build new context: %v", err)
		return err
	}

	link(req, ctx)
	defer unlink(req)

	// if tsconn, ok := conn.(*trafficshape.Conn); ok {
	// 	wrconn := tsconn.GetWrappedConn()
	// 	if sconn, ok := wrconn.(*tls.Conn); ok {
	// 		session.MarkSecure()

	// 		cs := sconn.ConnectionState()
	// 		req.TLS = &cs
	// 	}
	// }

	if tconn, ok := conn.(*tls.Conn); ok {
		// session.MarkSecure()

		cs := tconn.ConnectionState()
		req.TLS = &cs
	}

	if req.URL.Scheme == "" {
		// upgrade to https by default
		req.URL.Scheme = "https"
	}
	// do not alter scheme
	// req.URL.Scheme = "http"
	// if session.IsSecure() {
	// 	log.Debugf("martian: forcing HTTPS inside secure session")
	// 	req.URL.Scheme = "https"
	// }

	req.RemoteAddr = conn.RemoteAddr().String()
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}

	if req.Method == "CONNECT" {
		return p.handleConnectRequest(ctx, req, session, brw, conn)
	}

	// Not a CONNECT request
	if err := p.reqmod.ModifyRequest(req); err != nil {
		log.Errorf("martian: error modifying request: %v", err)
		proxyutil.Warning(req.Header, err)
	}
	// if session.Hijacked() {
	// 	return nil
	// }

	// perform the HTTP roundtrip
	res, err := p.roundTrip(ctx, req)
	if err != nil {
		log.Errorf("martian: failed to round trip: %v", err)
		res = proxyutil.NewResponse(502, nil, req)
		proxyutil.Warning(res.Header, err)
	}
	defer res.Body.Close()

	// set request to original request manually, res.Request may be changed in transport.
	// see https://github.com/projectdiscovery/martian/issues/298
	res.Request = req

	if err := p.resmod.ModifyResponse(res); err != nil {
		log.Errorf("martian: error modifying response: %v", err)
		proxyutil.Warning(res.Header, err)
	}
	if session.Hijacked() {
		log.Debugf("martian: connection hijacked by response modifier")
		return nil
	}

	var closing error
	if req.Close || res.Close || p.Closing() {
		log.Debugf("martian: received close request: %v", req.RemoteAddr)
		res.Close = true
		closing = errClose
	}

	// // check if conn is a traffic shaped connection.
	// if ptsconn, ok := conn.(*trafficshape.Conn); ok {
	// 	ptsconn.Context = &trafficshape.Context{}
	// 	// Check if the request URL matches any URLRegex in Shapes. If so, set the connections's Context
	// 	// with the required information, so that the Write() method of the Conn has access to it.
	// 	for urlregex, buckets := range ptsconn.LocalBuckets {
	// 		if match, _ := regexp.MatchString(urlregex, req.URL.String()); match {
	// 			if rangeStart := proxyutil.GetRangeStart(res); rangeStart > -1 {
	// 				dump, err := httputil.DumpResponse(res, false)
	// 				if err != nil {
	// 					return err
	// 				}
	// 				ptsconn.Context = &trafficshape.Context{
	// 					Shaping:            true,
	// 					Buckets:            buckets,
	// 					GlobalBucket:       ptsconn.GlobalBuckets[urlregex],
	// 					URLRegex:           urlregex,
	// 					RangeStart:         rangeStart,
	// 					ByteOffset:         rangeStart,
	// 					HeaderLen:          int64(len(dump)),
	// 					HeaderBytesWritten: 0,
	// 				}
	// 				// Get the next action to perform, if there.
	// 				ptsconn.Context.NextActionInfo = ptsconn.GetNextActionFromByte(rangeStart)
	// 				// Check if response lies in a throttled byte range.
	// 				ptsconn.Context.ThrottleContext = ptsconn.GetCurrentThrottle(rangeStart)
	// 				if ptsconn.Context.ThrottleContext.ThrottleNow {
	// 					ptsconn.Context.Buckets.WriteBucket.SetCapacity(
	// 						ptsconn.Context.ThrottleContext.Bandwidth)
	// 				}
	// 				gologger.Print().Msgf(
	// 					"trafficshape: Request %s with Range Start: %d matches a Shaping request %s. Enforcing Traffic shaping.",
	// 					req.URL, rangeStart, urlregex)
	// 			}
	// 			break
	// 		}
	// 	}
	// }

	err = res.Write(brw)
	if err != nil {
		log.Errorf("martian: got error while writing response back to client: %v", err)
		if _, ok := err.(*trafficshape.ErrForceClose); ok {
			closing = errClose
		}
		// closes if upstream stop responding
		if errors.Is(err, io.ErrUnexpectedEOF) {
			closing = errClose
		}
	}
	err = brw.Flush()
	if err != nil {
		log.Debugf("martian: got error while flushing response back to client: %v", err)
		if _, ok := err.(*trafficshape.ErrForceClose); ok {
			closing = errClose
		}
	}
	return closing
}

// A peekedConn subverts the net.Conn.Read implementation, primarily so that
// sniffed bytes can be transparently prepended.
type peekedConn struct {
	net.Conn
	r io.Reader
}

// Read allows control over the embedded net.Conn's read data. By using an
// io.MultiReader one can read from a conn, and then replace what they read, to
// be read again.
func (c *peekedConn) Read(buf []byte) (int, error) { return c.r.Read(buf) }

func (p *Proxy) roundTrip(ctx *Context, req *http.Request) (*http.Response, error) {
	if ctx.SkippingRoundTrip() {
		log.Debugf("martian: skipping round trip")
		return proxyutil.NewResponse(200, nil, req), nil
	}

	return p.roundTripper.RoundTrip(req)
}

func (p *Proxy) connect(req *http.Request) (*http.Response, net.Conn, error) {
	var (
		conn net.Conn
		err  error
	)

	if p.proxyURL != nil {
		log.Debugf("martian: CONNECT with downstream proxy: %s", p.proxyURL.Host)

		log.Debugf("martian: CONNECT with downstream proxy: %s", p.proxyURL.Host)

		var dialer proxy.Dialer
		dialer, err = proxy.FromURL(
			p.proxyURL, &net.Dialer{
				Timeout:   3 * time.Second,
				KeepAlive: 3 * time.Second,
			},
		)
		if err != nil {
			return nil, nil, err
		}

		conn, err = dialer.Dial("tcp", req.URL.Host)
	} else {
		log.Debugf("martian: CONNECT to host directly: %s", req.URL.Host)
		conn, err = p.dialContext(req.Context(), "tcp", req.URL.Host)
	}

	if err != nil {
		return nil, nil, err
	}

	return proxyutil.NewResponse(http.StatusOK, nil, req), conn, nil
}
