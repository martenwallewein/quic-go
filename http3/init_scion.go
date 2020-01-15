package http3

import (
	"os"
	"sync"

	"crypto/tls"
	"github.com/martenwallewein/quic-go"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"

	"github.com/scionproto/scion/go/lib/sock/reliable"
)

var quicInit sync.Once
var scionInit sync.Once

// GetDefaultDispatcher returns the default SCION dispatcher service
func GetDefaultDispatcher() reliable.DispatcherService {
	return reliable.NewDispatcherService("")
}

// InitSQUICCerts reads certificate files from the os environment and Initializes the scion QUIC layer.
func InitSQUICCerts() error {
	var initErr error
	quicInit.Do(func() {
		initErr = Init(os.Getenv("SCION_CERT_KEY_FILE"), os.Getenv("SCION_CERT_FILE"))
	})
	return initErr
}

func InitScion(myAddr addr.IA) error {
	var initErr error
	scionInit.Do(func() {
		dispatcher := GetDefaultDispatcher()
		sciondPath := sciond.GetDefaultSCIONDPath(nil)
		initErr = snet.Init(myAddr, sciondPath, dispatcher)
	})
	return initErr
}

const (
	defKeyPath = "gen-certs/tls.key"
	defPemPath = "gen-certs/tls.pem"
)

var (
	// Don't verify the server's cert, as we are not using the TLS PKI.
	cliTlsCfg = &tls.Config{InsecureSkipVerify: true}
	srvTlsCfg = &tls.Config{}
)

func Init(keyPath, pemPath string) error {
	if keyPath == "" {
		keyPath = defKeyPath
	}
	if pemPath == "" {
		pemPath = defPemPath
	}
	cert, err := tls.LoadX509KeyPair(pemPath, keyPath)
	if err != nil {
		return common.NewBasicError("squic: Unable to load TLS cert/key", err)
	}
	srvTlsCfg.Certificates = []tls.Certificate{cert}
	return nil
}

func DialSCION(network *snet.SCIONNetwork, laddr, raddr *snet.Addr,
	quicConfig *quic.Config) (quic.Session, error) {

	return DialSCIONWithBindSVC(network, laddr, raddr, nil, addr.SvcNone, quicConfig)
}

func DialSCIONWithBindSVC(network *snet.SCIONNetwork, laddr, raddr, baddr *snet.Addr,
	svc addr.HostSVC, quicConfig *quic.Config) (quic.Session, error) {

	sconn, err := sListen(network, laddr, baddr, svc)
	if err != nil {
		return nil, err
	}

	cliTlsCfg.NextProtos = []string{nextProtoH3}
	// Use dummy hostname, as it's used for SNI, and we're not doing cert verification.
	return quic.Dial(sconn, raddr, "host:0", cliTlsCfg, quicConfig)
}

func ListenSCION(network *snet.SCIONNetwork, laddr *snet.Addr,
	quicConfig *quic.Config) (quic.Listener, error) {

	return ListenSCIONWithBindSVC(network, laddr, nil, addr.SvcNone, quicConfig)
}

func ListenSCIONWithBindSVC(network *snet.SCIONNetwork, laddr, baddr *snet.Addr,
	svc addr.HostSVC, quicConfig *quic.Config) (quic.Listener, error) {

	if len(srvTlsCfg.Certificates) == 0 {
		return nil, serrors.New("squic: No server TLS certificate configured")
	}
	sconn, err := sListen(network, laddr, baddr, svc)
	if err != nil {
		return nil, err
	}
	srvTlsCfg.NextProtos = []string{nextProtoH3}
	return quic.Listen(sconn, srvTlsCfg, quicConfig)
}

func sListen(network *snet.SCIONNetwork, laddr, baddr *snet.Addr,
	svc addr.HostSVC) (snet.Conn, error) {

	if network == nil {
		network = snet.DefNetwork
	}
	return network.ListenSCIONWithBindSVC("udp4", laddr, baddr, svc, 0)
}
