package ackhandler

import (
	"github.com/martenwallewein/quic-go/internal/congestion"
	"github.com/martenwallewein/quic-go/internal/protocol"
	"github.com/martenwallewein/quic-go/internal/utils"
	"github.com/martenwallewein/quic-go/qlog"
	"github.com/martenwallewein/quic-go/quictrace"
)

func NewAckHandler(
	initialPacketNumber protocol.PacketNumber,
	rttStats *congestion.RTTStats,
	pers protocol.Perspective,
	traceCallback func(quictrace.Event),
	qlogger qlog.Tracer,
	logger utils.Logger,
	version protocol.VersionNumber,
) (SentPacketHandler, ReceivedPacketHandler) {
	sph := newSentPacketHandler(initialPacketNumber, rttStats, pers, traceCallback, qlogger, logger)
	return sph, newReceivedPacketHandler(sph, rttStats, logger, version)
}
