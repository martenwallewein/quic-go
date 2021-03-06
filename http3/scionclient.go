package http3

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/spath"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/marten-seemann/qpack"
	quic "github.com/martenwallewein/quic-go"
	"github.com/martenwallewein/quic-go/internal/utils"
	"github.com/scionproto/scion/go/lib/snet"
)

var Path string

func dialSCIONPath(local, targetAddr *snet.Addr) (quic.Session, error) {
	if err := InitScion(local.IA); err != nil {
		return nil, err
	}
	if err := InitSQUICCerts(); err != nil {
		return nil, err
	}

	// targetAddr, ok := addr.(*snet.Addr)
	// if !ok {
	//	return nil, fmt.Errorf("sdial: invalid addr type: %s", addr.String())
	// }
	// Copy the snet addr -> To ensure we won't manipulate the old addr by attaching hops/path
	snetAddr := targetAddr.Copy()
	str := local.String()
	front := str[:strings.LastIndex(str, ":")]
	newAddr, err := snet.AddrFromString(front)
	if err != nil {
		return nil, err
	}

	if !snetAddr.IA.Equal(newAddr.IA) {
		// query paths from here to there:
		pathMgr := snet.DefNetwork.PathResolver()
		pathSet := pathMgr.Query(context.Background(), newAddr.IA, snetAddr.IA, sciond.PathReqFlags{})
		if len(pathSet) == 0 {
			return nil, fmt.Errorf("No Paths")
		}
		// print all paths. Also pick one path. Here we chose the path with least hops:
		i := 0
		minLength, argMinPath := 999, (*sciond.PathReplyEntry)(nil)
		fmt.Println("Available paths:")
		for _, path := range pathSet {
			fmt.Printf("[%2d] %d %s\n", i, len(path.Entry.Path.Interfaces)/2, path.Entry.Path.String())
			if len(path.Entry.Path.Interfaces) < minLength {
				minLength = len(path.Entry.Path.Interfaces)
				argMinPath = path.Entry
			}
			i++
		}

		fmt.Println("Chosen path:", argMinPath.Path.String())
		Path = argMinPath.Path.String()
		// we need to copy the path to the destination (destination is the whole selected path)
		snetAddr.Path = spath.New(argMinPath.Path.FwdPath)
		snetAddr.Path.InitOffsets()
		snetAddr.NextHop, _ = argMinPath.HostInfo.Overlay()
		// get a connection object using that path:
	}

	sess, err := DialSCION(nil, newAddr, snetAddr, &quic.Config{
		KeepAlive: true,
	})

	if err != nil {
		return nil, err
	}

	return sess, nil
}

// client is a HTTP3 client doing requests
type SCIONClient struct {
	tlsConf *tls.Config
	config  *quic.Config
	opts    *roundTripperOpts

	dialOnce     sync.Once
	dialer       func(network, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.Session, error)
	handshakeErr error

	requestWriter *requestWriter

	decoder *qpack.Decoder

	hostname string
	session  quic.Session

	logger utils.Logger
	local  *snet.Addr
	remote *snet.Addr
}

func SCIONNewClient(
	hostname string,
	tlsConf *tls.Config,
	opts *roundTripperOpts,
	quicConfig *quic.Config,
	local *snet.Addr,
	remote *snet.Addr,
) *SCIONClient {
	if tlsConf == nil {
		tlsConf = &tls.Config{}
	} else {
		tlsConf = tlsConf.Clone()
	}
	// Replace existing ALPNs by H3
	tlsConf.NextProtos = []string{nextProtoH3}
	tlsConf.InsecureSkipVerify = true
	if quicConfig == nil {
		quicConfig = defaultQuicConfig
	}
	quicConfig.MaxIncomingStreams = -1 // don't allow any bidirectional streams
	logger := utils.DefaultLogger.WithPrefix("h3 client")

	fmt.Printf("%s", tlsConf.NextProtos)
	return &SCIONClient{
		hostname:      hostname, // authorityAddr("https", hostname),
		tlsConf:       tlsConf,
		requestWriter: newRequestWriter(logger),
		decoder:       qpack.NewDecoder(func(hf qpack.HeaderField) {}),
		config:        quicConfig,
		opts:          opts,
		logger:        logger,
		local:         local,
		remote:        remote,
	}
}

func (c *SCIONClient) dial() error {
	var err error
	// TODO: SCION Dial
	c.session, err = dialSCIONPath(c.local, c.remote)
	/*if c.dialer != nil {
		c.session, err = c.dialer("udp", c.hostname, c.tlsConf, c.config)
	} else {
		c.session, err = dialAddr(c.hostname, c.tlsConf, c.config)
	}
	*/
	if err != nil {
		return err
	}

	go func() {
		if err := c.setupSession(); err != nil {
			c.logger.Debugf("Setting up session failed: %s", err)
			c.session.CloseWithError(quic.ErrorCode(errorInternalError), "")
		}
	}()

	return nil
}

func (c *SCIONClient) setupSession() error {
	// open the control stream
	str, err := c.session.OpenUniStream()
	if err != nil {
		return err
	}
	buf := &bytes.Buffer{}
	// write the type byte
	buf.Write([]byte{0x0})
	// send the SETTINGS frame
	(&settingsFrame{}).Write(buf)
	if _, err := str.Write(buf.Bytes()); err != nil {
		return err
	}

	return nil
}

func (c *SCIONClient) Close() error {
	return c.session.Close()
}

func (c *SCIONClient) maxHeaderBytes() uint64 {
	if c.opts.MaxHeaderBytes <= 0 {
		return defaultMaxResponseHeaderBytes
	}
	return uint64(c.opts.MaxHeaderBytes)
}

// RoundTrip executes a request and returns a response
func (c *SCIONClient) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		return nil, errors.New("http3: unsupported scheme")
	}
	if authorityAddr("https", hostnameFromRequest(req)) != c.hostname {
		return nil, fmt.Errorf("http3 client BUG: RoundTrip called for the wrong client (expected %s, got %s)", c.hostname, req.Host)
	}

	c.dialOnce.Do(func() {
		c.handshakeErr = c.dial()
	})

	if c.handshakeErr != nil {
		return nil, c.handshakeErr
	}

	str, err := c.session.OpenStreamSync(context.Background())
	if err != nil {
		return nil, err
	}

	// Request Cancellation:
	// This go routine keeps running even after RoundTrip() returns.
	// It is shut down when the application is done processing the body.
	reqDone := make(chan struct{})
	go func() {
		select {
		case <-req.Context().Done():
			str.CancelWrite(quic.ErrorCode(errorRequestCanceled))
			str.CancelRead(quic.ErrorCode(errorRequestCanceled))
		case <-reqDone:
		}
	}()

	rsp, rerr := c.doRequest(req, str, reqDone)
	if rerr.err != nil { // if any error occurred
		close(reqDone)
		if rerr.streamErr != 0 { // if it was a stream error
			str.CancelWrite(quic.ErrorCode(rerr.streamErr))
		}
		if rerr.connErr != 0 { // if it was a connection error
			var reason string
			if rerr.err != nil {
				reason = rerr.err.Error()
			}
			c.session.CloseWithError(quic.ErrorCode(rerr.connErr), reason)
		}
	}
	return rsp, rerr.err
}

func (c *SCIONClient) doRequest(
	req *http.Request,
	str quic.Stream,
	reqDone chan struct{},
) (*http.Response, requestError) {
	var requestGzip bool
	if !c.opts.DisableCompression && req.Method != "HEAD" && req.Header.Get("Accept-Encoding") == "" && req.Header.Get("Range") == "" {
		requestGzip = true
	}
	if err := c.requestWriter.WriteRequest(str, req, requestGzip); err != nil {
		return nil, newStreamError(errorInternalError, err)
	}

	frame, err := parseNextFrame(str)
	if err != nil {
		return nil, newStreamError(errorFrameError, err)
	}
	hf, ok := frame.(*headersFrame)
	if !ok {
		return nil, newConnError(errorFrameUnexpected, errors.New("expected first frame to be a HEADERS frame"))
	}
	if hf.Length > c.maxHeaderBytes() {
		return nil, newStreamError(errorFrameError, fmt.Errorf("HEADERS frame too large: %d bytes (max: %d)", hf.Length, c.maxHeaderBytes()))
	}
	headerBlock := make([]byte, hf.Length)
	if _, err := io.ReadFull(str, headerBlock); err != nil {
		return nil, newStreamError(errorRequestIncomplete, err)
	}
	hfs, err := c.decoder.DecodeFull(headerBlock)
	if err != nil {
		// TODO: use the right error code
		return nil, newConnError(errorGeneralProtocolError, err)
	}

	res := &http.Response{
		Proto:      "HTTP/3",
		ProtoMajor: 3,
		Header:     http.Header{},
	}
	for _, hf := range hfs {
		switch hf.Name {
		case ":status":
			status, err := strconv.Atoi(hf.Value)
			if err != nil {
				return nil, newStreamError(errorGeneralProtocolError, errors.New("malformed non-numeric status pseudo header"))
			}
			res.StatusCode = status
			res.Status = hf.Value + " " + http.StatusText(status)
		default:
			res.Header.Add(hf.Name, hf.Value)
		}
	}
	respBody := newResponseBody(str, reqDone, func() {
		c.session.CloseWithError(quic.ErrorCode(errorFrameUnexpected), "")
	})
	if requestGzip && res.Header.Get("Content-Encoding") == "gzip" {
		res.Header.Del("Content-Encoding")
		res.Header.Del("Content-Length")
		res.ContentLength = -1
		res.Body = newGzipReader(respBody)
		res.Uncompressed = true
	} else {
		res.Body = respBody
	}

	return res, requestError{}
}
