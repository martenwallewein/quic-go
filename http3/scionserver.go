package http3

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/marten-seemann/qpack"
	"github.com/martenwallewein/quic-go"
	"github.com/martenwallewein/quic-go/internal/utils"
	"github.com/onsi/ginkgo"
	"github.com/scionproto/scion/go/lib/snet"
	"io"
	"net"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// Server is a HTTP2 server listening for QUIC connections.
type SCIONServer struct {
	*http.Server

	// By providing a quic.Config, it is possible to set parameters of the QUIC connection.
	// If nil, it uses reasonable default values.
	QuicConfig *quic.Config

	port uint32 // used atomically

	mutex     sync.Mutex
	listeners map[*quic.Listener]struct{}
	closed    utils.AtomicBool

	logger utils.Logger
	Local  *snet.Addr
}

// ListenAndServe listens on the UDP address s.Addr and calls s.Handler to handle HTTP/3 requests on incoming connections.
func (s *SCIONServer) ListenAndServe() error {
	if s.Server == nil {
		return errors.New("use of http3.Server without http.Server")
	}
	return s.serveImpl(s.TLSConfig, nil)
}

// ListenAndServeTLS listens on the UDP address s.Addr and calls s.Handler to handle HTTP/3 requests on incoming connections.
func (s *SCIONServer) ListenAndServeTLS(certFile, keyFile string) error {
	var err error
	certs := make([]tls.Certificate, 1)
	certs[0], err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	// We currently only use the cert-related stuff from tls.Config,
	// so we don't need to make a full copy.
	config := &tls.Config{
		Certificates:       certs,
		InsecureSkipVerify: true,
		NextProtos:         []string{nextProtoH3},
	}
	return s.serveImpl(config, nil)
}

// Serve an existing UDP connection.
// It is possible to reuse the same connection for outgoing connections.
// Closing the server does not close the packet conn.
func (s *SCIONServer) Serve(conn net.PacketConn) error {
	return s.serveImpl(s.TLSConfig, conn)
}

func (s *SCIONServer) serveImpl(tlsConf *tls.Config, conn net.PacketConn) error {
	fmt.Println("Serve SCION")
	if s.closed.Get() {
		return http.ErrServerClosed
	}
	if s.Server == nil {
		return errors.New("use of http3.Server without http.Server")
	}
	s.logger = utils.DefaultLogger.WithPrefix("server")

	if tlsConf == nil {
		tlsConf = &tls.Config{}
	} else {
		tlsConf = tlsConf.Clone()
	}
	// Replace existing ALPNs by H3
	tlsConf.NextProtos = []string{nextProtoH3}
	tlsConf.InsecureSkipVerify = true
	if tlsConf.GetConfigForClient != nil {
		getConfigForClient := tlsConf.GetConfigForClient
		tlsConf.GetConfigForClient = func(ch *tls.ClientHelloInfo) (*tls.Config, error) {
			conf, err := getConfigForClient(ch)
			if err != nil || conf == nil {
				return conf, err
			}
			conf = conf.Clone()
			conf.InsecureSkipVerify = true
			conf.NextProtos = []string{nextProtoH3}
			return conf, nil
		}
	}
	fmt.Printf("%s", tlsConf.NextProtos)

	var ln quic.Listener
	var err error
	/*if conn == nil {
		ln, err = quicListenAddr(s.Addr, tlsConf, s.QuicConfig)
	} else {
		ln, err = quicListen(conn, tlsConf, s.QuicConfig)
	}*/
	ln, err = listenScion(s.Local)
	if err != nil {
		return err
	}
	s.addListener(&ln)
	defer s.removeListener(&ln)

	for {
		sess, err := ln.Accept(context.Background())
		if err != nil {
			return err
		}
		go s.handleConn(sess)
	}
}

// We store a pointer to interface in the map set. This is safe because we only
// call trackListener via Serve and can track+defer untrack the same pointer to
// local variable there. We never need to compare a Listener from another caller.
func (s *SCIONServer) addListener(l *quic.Listener) {
	s.mutex.Lock()
	if s.listeners == nil {
		s.listeners = make(map[*quic.Listener]struct{})
	}
	s.listeners[l] = struct{}{}
	s.mutex.Unlock()
}

func (s *SCIONServer) removeListener(l *quic.Listener) {
	s.mutex.Lock()
	delete(s.listeners, l)
	s.mutex.Unlock()
}

func (s *SCIONServer) handleConn(sess quic.Session) {
	// TODO: accept control streams
	decoder := qpack.NewDecoder(nil)

	// send a SETTINGS frame
	str, err := sess.OpenUniStream()
	if err != nil {
		s.logger.Debugf("Opening the control stream failed.")
		return
	}
	buf := bytes.NewBuffer([]byte{0})
	(&settingsFrame{}).Write(buf)
	str.Write(buf.Bytes())

	for {
		str, err := sess.AcceptStream(context.Background())
		if err != nil {
			s.logger.Debugf("Accepting stream failed: %s", err)
			return
		}
		go func() {
			defer ginkgo.GinkgoRecover()
			rerr := s.handleRequest(sess, str, decoder, func() {
				sess.CloseWithError(quic.ErrorCode(errorFrameUnexpected), "")
			})
			if rerr.err != nil || rerr.streamErr != 0 || rerr.connErr != 0 {
				s.logger.Debugf("Handling request failed: %s", err)
				if rerr.streamErr != 0 {
					str.CancelWrite(quic.ErrorCode(rerr.streamErr))
				}
				if rerr.connErr != 0 {
					var reason string
					if rerr.err != nil {
						reason = rerr.err.Error()
					}
					sess.CloseWithError(quic.ErrorCode(rerr.connErr), reason)
				}
				return
			}
			str.Close()
		}()
	}
}

func (s *SCIONServer) maxHeaderBytes() uint64 {
	if s.Server.MaxHeaderBytes <= 0 {
		return http.DefaultMaxHeaderBytes
	}
	return uint64(s.Server.MaxHeaderBytes)
}

func (s *SCIONServer) handleRequest(sess quic.Session, str quic.Stream, decoder *qpack.Decoder, onFrameError func()) requestError {
	frame, err := parseNextFrame(str)
	if err != nil {
		return newStreamError(errorRequestIncomplete, err)
	}
	hf, ok := frame.(*headersFrame)
	if !ok {
		return newConnError(errorFrameUnexpected, errors.New("expected first frame to be a HEADERS frame"))
	}
	if hf.Length > s.maxHeaderBytes() {
		return newStreamError(errorFrameError, fmt.Errorf("HEADERS frame too large: %d bytes (max: %d)", hf.Length, s.maxHeaderBytes()))
	}
	headerBlock := make([]byte, hf.Length)
	if _, err := io.ReadFull(str, headerBlock); err != nil {
		return newStreamError(errorRequestIncomplete, err)
	}
	hfs, err := decoder.DecodeFull(headerBlock)
	if err != nil {
		// TODO: use the right error code
		return newConnError(errorGeneralProtocolError, err)
	}
	req, err := requestFromHeaders(hfs)
	if err != nil {
		// TODO: use the right error code
		return newStreamError(errorGeneralProtocolError, err)
	}

	req.RemoteAddr = sess.RemoteAddr().String()
	req.Body = newRequestBody(str, onFrameError)

	if s.logger.Debug() {
		s.logger.Infof("%s %s%s, on stream %d", req.Method, req.Host, req.RequestURI, str.StreamID())
	} else {
		s.logger.Infof("%s %s%s", req.Method, req.Host, req.RequestURI)
	}

	req = req.WithContext(str.Context())
	responseWriter := newResponseWriter(str, s.logger)
	handler := s.Handler
	if handler == nil {
		handler = http.DefaultServeMux
	}

	var panicked, readEOF bool
	func() {
		defer func() {
			if p := recover(); p != nil {
				// Copied from net/http/server.go
				const size = 64 << 10
				buf := make([]byte, size)
				buf = buf[:runtime.Stack(buf, false)]
				s.logger.Errorf("http: panic serving: %v\n%s", p, buf)
				panicked = true
			}
		}()
		handler.ServeHTTP(responseWriter, req)
		// read the eof
		if _, err = str.Read([]byte{0}); err == io.EOF {
			readEOF = true
		}
	}()

	if panicked {
		responseWriter.WriteHeader(500)
	} else {
		responseWriter.WriteHeader(200)
	}

	if !readEOF {
		str.CancelRead(quic.ErrorCode(errorEarlyResponse))
	}
	return requestError{}
}

// Close the server immediately, aborting requests and sending CONNECTION_CLOSE frames to connected clients.
// Close in combination with ListenAndServe() (instead of Serve()) may race if it is called before a UDP socket is established.
func (s *SCIONServer) Close() error {
	s.closed.Set(true)

	s.mutex.Lock()
	defer s.mutex.Unlock()

	var err error
	for ln := range s.listeners {
		if cerr := (*ln).Close(); cerr != nil && err == nil {
			err = cerr
		}
	}
	return err
}

// CloseGracefully shuts down the server gracefully. The server sends a GOAWAY frame first, then waits for either timeout to trigger, or for all running requests to complete.
// CloseGracefully in combination with ListenAndServe() (instead of Serve()) may race if it is called before a UDP socket is established.
func (s *SCIONServer) CloseGracefully(timeout time.Duration) error {
	// TODO: implement
	return nil
}

// SetQuicHeaders can be used to set the proper headers that announce that this server supports QUIC.
// The values that are set depend on the port information from s.Server.Addr, and currently look like this (if Addr has port 443):
//  Alt-Svc: quic=":443"; ma=2592000; v="33,32,31,30"
func (s *SCIONServer) SetQuicHeaders(hdr http.Header) error {
	port := atomic.LoadUint32(&s.port)

	if port == 0 {
		// Extract port from s.Server.Addr
		_, portStr, err := net.SplitHostPort(s.Server.Addr)
		if err != nil {
			return err
		}
		portInt, err := net.LookupPort("tcp", portStr)
		if err != nil {
			return err
		}
		port = uint32(portInt)
		atomic.StoreUint32(&s.port, port)
	}

	hdr.Add("Alt-Svc", fmt.Sprintf(`%s=":%d"; ma=2592000`, nextProtoH3, port))

	return nil
}

// ListenAndServeQUIC listens on the UDP network address addr and calls the
// handler for HTTP/3 requests on incoming connections. http.DefaultServeMux is
// used when handler is nil.
func ListenAndServeSCION(addr, certFile, keyFile string, local *snet.Addr, handler http.Handler) error {
	server := &SCIONServer{
		Server: &http.Server{
			Addr:    addr,
			Handler: handler,
		},
		Local: local,
	}
	return server.ListenAndServeTLS(certFile, keyFile)
}

func listenScion(address *snet.Addr) (quic.Listener, error) {
	if err := InitScion(address.IA); err != nil {
		return nil, err
	}
	if err := InitSQUICCerts(); err != nil {
		return nil, err
	}
	conn, err := ListenSCION(nil, address, &quic.Config{KeepAlive: true})
	if err != nil {
		return nil, err
	}
	return conn, nil
}
