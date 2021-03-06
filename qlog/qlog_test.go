package qlog

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"time"

	"github.com/martenwallewein/quic-go/internal/congestion"
	"github.com/martenwallewein/quic-go/internal/protocol"
	"github.com/martenwallewein/quic-go/internal/wire"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type nopWriteCloserImpl struct{ io.Writer }

func (nopWriteCloserImpl) Close() error { return nil }

func nopWriteCloser(w io.Writer) io.WriteCloser {
	return &nopWriteCloserImpl{Writer: w}
}

type limitedWriter struct {
	io.WriteCloser
	N       int
	written int
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if w.written+len(p) > w.N {
		return 0, errors.New("writer full")
	}
	n, err := w.WriteCloser.Write(p)
	w.written += n
	return n, err
}

type entry struct {
	Time     time.Time
	Category string
	Name     string
	Event    map[string]interface{}
}

var _ = Describe("Tracer", func() {
	var (
		tracer Tracer
		buf    *bytes.Buffer
	)

	BeforeEach(func() {
		buf = &bytes.Buffer{}
		tracer = NewTracer(
			nopWriteCloser(buf),
			protocol.PerspectiveServer,
			protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef},
		)
	})

	It("exports a trace that has the right metadata", func() {
		Expect(tracer.Export()).To(Succeed())

		m := make(map[string]interface{})
		Expect(json.Unmarshal(buf.Bytes(), &m)).To(Succeed())
		Expect(m).To(HaveKeyWithValue("qlog_version", "draft-02-wip"))
		Expect(m).To(HaveKey("title"))
		Expect(m).To(HaveKey("traces"))
		traces := m["traces"].([]interface{})
		Expect(traces).To(HaveLen(1))
		trace := traces[0].(map[string]interface{})
		Expect(trace).To(HaveKey(("common_fields")))
		commonFields := trace["common_fields"].(map[string]interface{})
		Expect(commonFields).To(HaveKeyWithValue("ODCID", "deadbeef"))
		Expect(commonFields).To(HaveKeyWithValue("group_id", "deadbeef"))
		Expect(trace).To(HaveKey("event_fields"))
		for i, ef := range trace["event_fields"].([]interface{}) {
			Expect(ef.(string)).To(Equal(eventFields[i]))
		}
		Expect(trace).To(HaveKey("vantage_point"))
		vantagePoint := trace["vantage_point"].(map[string]interface{})
		Expect(vantagePoint).To(HaveKeyWithValue("type", "server"))
	})

	It("stops writing when encountering an error", func() {
		tracer = NewTracer(
			&limitedWriter{WriteCloser: nopWriteCloser(buf), N: 250},
			protocol.PerspectiveServer,
			protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef},
		)
		for i := uint32(0); i < 1000; i++ {
			tracer.UpdatedPTOCount(i)
		}
		Expect(tracer.Export()).To(MatchError("writer full"))
	})

	Context("Events", func() {
		exportAndParse := func() []entry {
			Expect(tracer.Export()).To(Succeed())

			m := make(map[string]interface{})
			Expect(json.Unmarshal(buf.Bytes(), &m)).To(Succeed())
			Expect(m).To(HaveKey("traces"))
			var entries []entry
			traces := m["traces"].([]interface{})
			Expect(traces).To(HaveLen(1))
			trace := traces[0].(map[string]interface{})
			Expect(trace).To(HaveKey("events"))
			for _, e := range trace["events"].([]interface{}) {
				ev := e.([]interface{})
				Expect(ev).To(HaveLen(4))
				entries = append(entries, entry{
					Time:     time.Unix(0, int64(1e6*ev[0].(float64))),
					Category: ev[1].(string),
					Name:     ev[2].(string),
					Event:    ev[3].(map[string]interface{}),
				})
			}
			return entries
		}

		exportAndParseSingle := func() entry {
			entries := exportAndParse()
			Expect(entries).To(HaveLen(1))
			return entries[0]
		}

		It("records connection starts", func() {
			tracer.StartedConnection(
				&net.UDPAddr{IP: net.IPv4(192, 168, 13, 37), Port: 42},
				&net.UDPAddr{IP: net.IPv4(192, 168, 12, 34), Port: 24},
				0xdeadbeef,
				protocol.ConnectionID{1, 2, 3, 4},
				protocol.ConnectionID{5, 6, 7, 8},
			)
			entry := exportAndParseSingle()
			Expect(entry.Time).To(BeTemporally("~", time.Now(), 10*time.Millisecond))
			Expect(entry.Category).To(Equal("transport"))
			Expect(entry.Name).To(Equal("connection_started"))
			ev := entry.Event
			Expect(ev).To(HaveKeyWithValue("ip_version", "ipv4"))
			Expect(ev).To(HaveKeyWithValue("src_ip", "192.168.13.37"))
			Expect(ev).To(HaveKeyWithValue("src_port", float64(42)))
			Expect(ev).To(HaveKeyWithValue("dst_ip", "192.168.12.34"))
			Expect(ev).To(HaveKeyWithValue("dst_port", float64(24)))
			Expect(ev).To(HaveKeyWithValue("quic_version", "deadbeef"))
			Expect(ev).To(HaveKeyWithValue("src_cid", "01020304"))
			Expect(ev).To(HaveKeyWithValue("dst_cid", "05060708"))
		})

		It("records sent transport parameters", func() {
			tracer.SentTransportParameters(&wire.TransportParameters{
				InitialMaxStreamDataBidiLocal:  1000,
				InitialMaxStreamDataBidiRemote: 2000,
				InitialMaxStreamDataUni:        3000,
				InitialMaxData:                 4000,
				MaxBidiStreamNum:               10,
				MaxUniStreamNum:                20,
				MaxAckDelay:                    123 * time.Millisecond,
				AckDelayExponent:               12,
				DisableActiveMigration:         true,
				MaxUDPPayloadSize:              1234,
				MaxIdleTimeout:                 321 * time.Millisecond,
				StatelessResetToken:            &[16]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00},
				OriginalConnectionID:           protocol.ConnectionID{0xde, 0xad, 0xc0, 0xde},
				ActiveConnectionIDLimit:        7,
			})
			entry := exportAndParseSingle()
			Expect(entry.Time).To(BeTemporally("~", time.Now(), 10*time.Millisecond))
			Expect(entry.Category).To(Equal("transport"))
			Expect(entry.Name).To(Equal("parameters_set"))
			ev := entry.Event
			Expect(ev).To(HaveKeyWithValue("owner", "local"))
			Expect(ev).To(HaveKeyWithValue("original_connection_id", "deadc0de"))
			Expect(ev).To(HaveKeyWithValue("stateless_reset_token", "112233445566778899aabbccddeeff00"))
			Expect(ev).To(HaveKeyWithValue("max_idle_timeout", float64(321)))
			Expect(ev).To(HaveKeyWithValue("max_udp_payload_size", float64(1234)))
			Expect(ev).To(HaveKeyWithValue("ack_delay_exponent", float64(12)))
			Expect(ev).To(HaveKeyWithValue("active_connection_id_limit", float64(7)))
			Expect(ev).To(HaveKeyWithValue("initial_max_data", float64(4000)))
			Expect(ev).To(HaveKeyWithValue("initial_max_stream_data_bidi_local", float64(1000)))
			Expect(ev).To(HaveKeyWithValue("initial_max_stream_data_bidi_remote", float64(2000)))
			Expect(ev).To(HaveKeyWithValue("initial_max_stream_data_uni", float64(3000)))
			Expect(ev).To(HaveKeyWithValue("initial_max_streams_bidi", float64(10)))
			Expect(ev).To(HaveKeyWithValue("initial_max_streams_uni", float64(20)))
		})

		It("records received transport parameters", func() {
			tracer.ReceivedTransportParameters(&wire.TransportParameters{})
			entry := exportAndParseSingle()
			Expect(entry.Time).To(BeTemporally("~", time.Now(), 10*time.Millisecond))
			Expect(entry.Category).To(Equal("transport"))
			Expect(entry.Name).To(Equal("parameters_set"))
			ev := entry.Event
			Expect(ev).To(HaveKeyWithValue("owner", "remote"))
		})

		It("records a sent packet, without an ACK", func() {
			tracer.SentPacket(
				&wire.ExtendedHeader{
					Header: wire.Header{
						IsLongHeader:     true,
						Type:             protocol.PacketTypeHandshake,
						DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
						SrcConnectionID:  protocol.ConnectionID{4, 3, 2, 1},
						Version:          protocol.VersionTLS,
					},
					PacketNumber: 1337,
				},
				987,
				nil,
				[]wire.Frame{
					&wire.MaxStreamDataFrame{StreamID: 42, ByteOffset: 987},
					&wire.StreamFrame{StreamID: 123, Offset: 1234, Data: []byte("foobar"), FinBit: true},
				},
			)
			entry := exportAndParseSingle()
			Expect(entry.Time).To(BeTemporally("~", time.Now(), 10*time.Millisecond))
			Expect(entry.Category).To(Equal("transport"))
			Expect(entry.Name).To(Equal("packet_sent"))
			ev := entry.Event
			Expect(ev).To(HaveKeyWithValue("packet_type", "handshake"))
			Expect(ev).To(HaveKey("header"))
			hdr := ev["header"].(map[string]interface{})
			Expect(hdr).To(HaveKeyWithValue("packet_size", float64(987)))
			Expect(hdr).To(HaveKeyWithValue("packet_number", float64(1337)))
			Expect(hdr).To(HaveKeyWithValue("scid", "04030201"))
			Expect(ev).To(HaveKey("frames"))
			frames := ev["frames"].([]interface{})
			Expect(frames).To(HaveLen(2))
			Expect(frames[0].(map[string]interface{})).To(HaveKeyWithValue("frame_type", "max_stream_data"))
			Expect(frames[1].(map[string]interface{})).To(HaveKeyWithValue("frame_type", "stream"))
		})

		It("records a sent packet, without an ACK", func() {
			tracer.SentPacket(
				&wire.ExtendedHeader{
					Header:       wire.Header{DestConnectionID: protocol.ConnectionID{1, 2, 3, 4}},
					PacketNumber: 1337,
				},
				123,
				&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 10}}},
				[]wire.Frame{&wire.MaxDataFrame{ByteOffset: 987}},
			)
			entry := exportAndParseSingle()
			ev := entry.Event
			Expect(ev).To(HaveKeyWithValue("packet_type", "1RTT"))
			Expect(ev).To(HaveKey("header"))
			Expect(ev).To(HaveKey("frames"))
			frames := ev["frames"].([]interface{})
			Expect(frames).To(HaveLen(2))
			Expect(frames[0].(map[string]interface{})).To(HaveKeyWithValue("frame_type", "ack"))
			Expect(frames[1].(map[string]interface{})).To(HaveKeyWithValue("frame_type", "max_data"))
		})

		It("records a received packet", func() {
			tracer.ReceivedPacket(
				&wire.ExtendedHeader{
					Header: wire.Header{
						IsLongHeader:     true,
						Type:             protocol.PacketTypeInitial,
						DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
						SrcConnectionID:  protocol.ConnectionID{4, 3, 2, 1},
						Version:          protocol.VersionTLS,
					},
					PacketNumber: 1337,
				},
				789,
				[]wire.Frame{
					&wire.MaxStreamDataFrame{StreamID: 42, ByteOffset: 987},
					&wire.StreamFrame{StreamID: 123, Offset: 1234, Data: []byte("foobar"), FinBit: true},
				},
			)
			entry := exportAndParseSingle()
			Expect(entry.Time).To(BeTemporally("~", time.Now(), 10*time.Millisecond))
			Expect(entry.Category).To(Equal("transport"))
			Expect(entry.Name).To(Equal("packet_received"))
			ev := entry.Event
			Expect(ev).To(HaveKeyWithValue("packet_type", "initial"))
			Expect(ev).To(HaveKey("header"))
			hdr := ev["header"].(map[string]interface{})
			Expect(hdr).To(HaveKeyWithValue("packet_size", float64(789)))
			Expect(hdr).To(HaveKeyWithValue("packet_number", float64(1337)))
			Expect(hdr).To(HaveKeyWithValue("scid", "04030201"))
			Expect(ev).To(HaveKey("frames"))
			Expect(ev["frames"].([]interface{})).To(HaveLen(2))
		})

		It("records a received Retry packet", func() {
			tracer.ReceivedRetry(
				&wire.Header{
					IsLongHeader:     true,
					Type:             protocol.PacketTypeRetry,
					DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
					SrcConnectionID:  protocol.ConnectionID{4, 3, 2, 1},
					Version:          protocol.VersionTLS,
				},
			)
			entry := exportAndParseSingle()
			Expect(entry.Time).To(BeTemporally("~", time.Now(), 10*time.Millisecond))
			Expect(entry.Category).To(Equal("transport"))
			Expect(entry.Name).To(Equal("packet_received"))
			ev := entry.Event
			Expect(ev).To(HaveKeyWithValue("packet_type", "retry"))
			Expect(ev).To(HaveKey("header"))
			Expect(ev).ToNot(HaveKey("frames"))
		})

		It("records buffered packets", func() {
			tracer.BufferedPacket(PacketTypeHandshake)
			entry := exportAndParseSingle()
			Expect(entry.Time).To(BeTemporally("~", time.Now(), 10*time.Millisecond))
			Expect(entry.Category).To(Equal("transport"))
			Expect(entry.Name).To(Equal("packet_buffered"))
			ev := entry.Event
			Expect(ev).To(HaveKeyWithValue("packet_type", "handshake"))
			Expect(ev).To(HaveKeyWithValue("trigger", "keys_unavailable"))
		})

		It("records dropped packets", func() {
			tracer.DroppedPacket(PacketTypeHandshake, 1337, PacketDropPayloadDecryptError)
			entry := exportAndParseSingle()
			Expect(entry.Time).To(BeTemporally("~", time.Now(), 10*time.Millisecond))
			Expect(entry.Category).To(Equal("transport"))
			Expect(entry.Name).To(Equal("packet_dropped"))
			ev := entry.Event
			Expect(ev).To(HaveKeyWithValue("packet_type", "handshake"))
			Expect(ev).To(HaveKeyWithValue("packet_size", float64(1337)))
			Expect(ev).To(HaveKeyWithValue("trigger", "payload_decrypt_error"))
		})

		It("records metrics updates", func() {
			now := time.Now()
			rttStats := congestion.NewRTTStats()
			rttStats.UpdateRTT(15*time.Millisecond, 0, now)
			rttStats.UpdateRTT(20*time.Millisecond, 0, now)
			rttStats.UpdateRTT(25*time.Millisecond, 0, now)
			Expect(rttStats.MinRTT()).To(Equal(15 * time.Millisecond))
			Expect(rttStats.SmoothedRTT()).To(And(
				BeNumerically(">", 15*time.Millisecond),
				BeNumerically("<", 25*time.Millisecond),
			))
			Expect(rttStats.LatestRTT()).To(Equal(25 * time.Millisecond))
			tracer.UpdatedMetrics(
				rttStats,
				4321,
				1234,
				42,
			)
			entry := exportAndParseSingle()
			Expect(entry.Time).To(BeTemporally("~", time.Now(), 10*time.Millisecond))
			Expect(entry.Category).To(Equal("recovery"))
			Expect(entry.Name).To(Equal("metrics_updated"))
			ev := entry.Event
			Expect(ev).To(HaveKeyWithValue("min_rtt", float64(15)))
			Expect(ev).To(HaveKeyWithValue("latest_rtt", float64(25)))
			Expect(ev).To(HaveKey("smoothed_rtt"))
			Expect(time.Duration(ev["smoothed_rtt"].(float64)) * time.Millisecond).To(BeNumerically("~", rttStats.SmoothedRTT(), time.Millisecond))
			Expect(ev).To(HaveKey("rtt_variance"))
			Expect(time.Duration(ev["rtt_variance"].(float64)) * time.Millisecond).To(BeNumerically("~", rttStats.MeanDeviation(), time.Millisecond))
			Expect(ev).To(HaveKeyWithValue("congestion_window", float64(4321)))
			Expect(ev).To(HaveKeyWithValue("bytes_in_flight", float64(1234)))
			Expect(ev).To(HaveKeyWithValue("packets_in_flight", float64(42)))
		})

		It("records lost packets", func() {
			tracer.LostPacket(protocol.EncryptionHandshake, 42, PacketLossReorderingThreshold)
			entry := exportAndParseSingle()
			Expect(entry.Time).To(BeTemporally("~", time.Now(), 10*time.Millisecond))
			Expect(entry.Category).To(Equal("recovery"))
			Expect(entry.Name).To(Equal("packet_lost"))
			ev := entry.Event
			Expect(ev).To(HaveKeyWithValue("packet_type", "handshake"))
			Expect(ev).To(HaveKeyWithValue("packet_number", float64(42)))
			Expect(ev).To(HaveKeyWithValue("trigger", "reordering_threshold"))
		})

		It("records PTO changes", func() {
			tracer.UpdatedPTOCount(42)
			entry := exportAndParseSingle()
			Expect(entry.Time).To(BeTemporally("~", time.Now(), 10*time.Millisecond))
			Expect(entry.Category).To(Equal("recovery"))
			Expect(entry.Name).To(Equal("metrics_updated"))
			Expect(entry.Event).To(HaveKeyWithValue("pto_count", float64(42)))
		})

		It("records TLS key updates", func() {
			tracer.UpdatedKeyFromTLS(protocol.EncryptionHandshake, protocol.PerspectiveClient)
			entry := exportAndParseSingle()
			Expect(entry.Time).To(BeTemporally("~", time.Now(), 10*time.Millisecond))
			Expect(entry.Category).To(Equal("security"))
			Expect(entry.Name).To(Equal("key_updated"))
			ev := entry.Event
			Expect(ev).To(HaveKeyWithValue("key_type", "client_handshake_secret"))
			Expect(ev).To(HaveKeyWithValue("trigger", "tls"))
			Expect(ev).ToNot(HaveKey("generation"))
			Expect(ev).ToNot(HaveKey("old"))
			Expect(ev).ToNot(HaveKey("new"))
		})

		It("records QUIC key updates", func() {
			tracer.UpdatedKey(1337, true)
			entries := exportAndParse()
			Expect(entries).To(HaveLen(2))
			var keyTypes []string
			for _, entry := range entries {
				Expect(entry.Time).To(BeTemporally("~", time.Now(), 10*time.Millisecond))
				Expect(entry.Category).To(Equal("security"))
				Expect(entry.Name).To(Equal("key_updated"))
				ev := entry.Event
				Expect(ev).To(HaveKeyWithValue("generation", float64(1337)))
				Expect(ev).To(HaveKeyWithValue("trigger", "remote_update"))
				Expect(ev).To(HaveKey("key_type"))
				keyTypes = append(keyTypes, ev["key_type"].(string))
			}
			Expect(keyTypes).To(ContainElement("server_1rtt_secret"))
			Expect(keyTypes).To(ContainElement("client_1rtt_secret"))
		})

		It("records dropped encryption levels", func() {
			tracer.DroppedEncryptionLevel(protocol.EncryptionInitial)
			entries := exportAndParse()
			Expect(entries).To(HaveLen(2))
			var keyTypes []string
			for _, entry := range entries {
				Expect(entry.Time).To(BeTemporally("~", time.Now(), 10*time.Millisecond))
				Expect(entry.Category).To(Equal("security"))
				Expect(entry.Name).To(Equal("key_retired"))
				ev := entry.Event
				Expect(ev).To(HaveKeyWithValue("trigger", "tls"))
				Expect(ev).To(HaveKey("key_type"))
				keyTypes = append(keyTypes, ev["key_type"].(string))
			}
			Expect(keyTypes).To(ContainElement("server_initial_secret"))
			Expect(keyTypes).To(ContainElement("client_initial_secret"))
		})
	})
})
