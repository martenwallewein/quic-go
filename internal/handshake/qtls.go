package handshake

import (
	"crypto/tls"
	"net"
	"time"
	"unsafe"

	"github.com/marten-seemann/qtls"

	"github.com/martenwallewein/quic-go/internal/congestion"
)

type conn struct {
	localAddr, remoteAddr net.Addr
}

func newConn(local, remote net.Addr) net.Conn {
	return &conn{
		localAddr:  local,
		remoteAddr: remote,
	}
}

var _ net.Conn = &conn{}

func (c *conn) Read([]byte) (int, error)         { return 0, nil }
func (c *conn) Write([]byte) (int, error)        { return 0, nil }
func (c *conn) Close() error                     { return nil }
func (c *conn) RemoteAddr() net.Addr             { return c.remoteAddr }
func (c *conn) LocalAddr() net.Addr              { return c.localAddr }
func (c *conn) SetReadDeadline(time.Time) error  { return nil }
func (c *conn) SetWriteDeadline(time.Time) error { return nil }
func (c *conn) SetDeadline(time.Time) error      { return nil }

func tlsConfigToQtlsConfig(
	c *tls.Config,
	recordLayer qtls.RecordLayer,
	extHandler tlsExtensionHandler,
	rttStats *congestion.RTTStats,
	getDataForSessionState func() []byte,
	setDataFromSessionState func([]byte),
	accept0RTT func([]byte) bool,
	rejected0RTT func(),
	enable0RTT bool,
) *qtls.Config {
	if c == nil {
		c = &tls.Config{}
	}
	// Clone the config first. This executes the tls.Config.serverInit().
	// This sets the SessionTicketKey, if the user didn't supply one.
	c = c.Clone()
	// QUIC requires TLS 1.3 or newer
	minVersion := c.MinVersion
	if minVersion < qtls.VersionTLS13 {
		minVersion = qtls.VersionTLS13
	}
	maxVersion := c.MaxVersion
	if maxVersion < qtls.VersionTLS13 {
		maxVersion = qtls.VersionTLS13
	}
	var getConfigForClient func(ch *qtls.ClientHelloInfo) (*qtls.Config, error)
	if c.GetConfigForClient != nil {
		getConfigForClient = func(ch *qtls.ClientHelloInfo) (*qtls.Config, error) {
			tlsConf, err := c.GetConfigForClient((*tls.ClientHelloInfo)(unsafe.Pointer(ch)))
			if err != nil {
				return nil, err
			}
			if tlsConf == nil {
				return nil, nil
			}
			return tlsConfigToQtlsConfig(tlsConf, recordLayer, extHandler, rttStats, getDataForSessionState, setDataFromSessionState, accept0RTT, rejected0RTT, enable0RTT), nil
		}
	}
	var csc qtls.ClientSessionCache
	if c.ClientSessionCache != nil {
		csc = newClientSessionCache(c.ClientSessionCache, rttStats, getDataForSessionState, setDataFromSessionState)
	}
	conf := &qtls.Config{
		Rand:         c.Rand,
		Time:         c.Time,
		Certificates: *(*[]qtls.Certificate)(unsafe.Pointer(&c.Certificates)),
		// NameToCertificate is deprecated, but we still need to copy it if the user sets it.
		//nolint:staticcheck
		NameToCertificate:           *(*map[string]*qtls.Certificate)(unsafe.Pointer(&c.NameToCertificate)),
		GetCertificate:              *(*func(*qtls.ClientHelloInfo) (*qtls.Certificate, error))(unsafe.Pointer(&c.GetCertificate)),
		GetClientCertificate:        *(*func(*qtls.CertificateRequestInfo) (*qtls.Certificate, error))(unsafe.Pointer(&c.GetClientCertificate)),
		GetConfigForClient:          getConfigForClient,
		VerifyPeerCertificate:       c.VerifyPeerCertificate,
		RootCAs:                     c.RootCAs,
		NextProtos:                  c.NextProtos,
		EnforceNextProtoSelection:   true,
		ServerName:                  c.ServerName,
		ClientAuth:                  c.ClientAuth,
		ClientCAs:                   c.ClientCAs,
		InsecureSkipVerify:          c.InsecureSkipVerify,
		CipherSuites:                c.CipherSuites,
		PreferServerCipherSuites:    c.PreferServerCipherSuites,
		SessionTicketsDisabled:      c.SessionTicketsDisabled,
		SessionTicketKey:            c.SessionTicketKey,
		ClientSessionCache:          csc,
		MinVersion:                  minVersion,
		MaxVersion:                  maxVersion,
		CurvePreferences:            c.CurvePreferences,
		DynamicRecordSizingDisabled: c.DynamicRecordSizingDisabled,
		// no need to copy Renegotiation, it's not supported by TLS 1.3
		KeyLogWriter:           c.KeyLogWriter,
		AlternativeRecordLayer: recordLayer,
		GetExtensions:          extHandler.GetExtensions,
		ReceivedExtensions:     extHandler.ReceivedExtensions,
		Accept0RTT:             accept0RTT,
		Rejected0RTT:           rejected0RTT,
	}
	if enable0RTT {
		conf.Enable0RTT = true
		conf.MaxEarlyData = 0xffffffff
	}
	return conf
}

// qtlsConfigToTLSConfig is used to transform a qtls.Config to a tls.Config.
// It is used to create the tls.Config in the ClientHelloInfo.
// It doesn't copy all values, but only those used by ClientHelloInfo.SupportsCertificate.
func qtlsConfigToTLSConfig(config *qtls.Config) *tls.Config {
	return &tls.Config{
		MinVersion:       config.MinVersion,
		MaxVersion:       config.MaxVersion,
		CipherSuites:     config.CipherSuites,
		CurvePreferences: config.CurvePreferences,
	}
}
