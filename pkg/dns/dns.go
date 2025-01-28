package dns

import (
	"context"
	"encoding/binary"
	"net"
	"strings"

	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/outofforest/cloudless/pkg/host"
	"github.com/outofforest/cloudless/pkg/host/firewall"
	"github.com/outofforest/logger"
	"github.com/outofforest/parallel"
)

const (
	port         = 53
	bufferSize   = 4096
	maxMsgLength = 512
	headerSize   = 12
	ttl          = 60
	maxAnswers   = 10

	classInternet = 1

	typeA     = 1
	typeNS    = 2
	typeSOA   = 6
	typeCNAME = 5
	typeMX    = 15
	typeTXT   = 16

	rCodeOK             = 0
	rCodeFormatError    = 1
	rCodeServerFailure  = 2
	rCodeNameError      = 3
	rCodeNotImplemented = 4
	rCodeRefused        = 5
)

// Service returns DNS service.
func Service(configurators ...Configurator) host.Configurator {
	config := Config{
		Zones: map[string]ZoneConfig{},
	}
	for _, configurator := range configurators {
		configurator(&config)
	}

	return func(c *host.Configuration) error {
		c.AddFirewallRules(firewall.OpenV4UDPPort(port))
		c.StartServices(host.ServiceConfig{
			Name:   "dns",
			OnExit: parallel.Fail,
			TaskFn: func(ctx context.Context) error {
				for {
					if err := runServer(ctx, config); err != nil {
						if errors.Is(err, ctx.Err()) {
							return err
						}
						logger.Get(ctx).Error("DNS server failed", zap.Error(err))
					}
				}
			},
		})
		return nil
	}
}

func runServer(ctx context.Context, config Config) error {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: port,
	})
	if err != nil {
		return errors.WithStack(err)
	}

	return parallel.Run(ctx, func(ctx context.Context, spawn parallel.SpawnFn) error {
		spawn("watchdog", parallel.Fail, func(ctx context.Context) error {
			<-ctx.Done()
			_ = conn.Close()
			return errors.WithStack(ctx.Err())
		})
		spawn("server", parallel.Fail, func(ctx context.Context) error {
			rB := make([]byte, bufferSize)
			sB := make([]byte, bufferSize)

			var queryID uint64

			for {
				n, addr, err := conn.ReadFrom(rB)
				if err != nil {
					if ctx.Err() != nil {
						return errors.WithStack(ctx.Err())
					}
					return errors.WithStack(err)
				}

				rb := rB[:n]
				h, rb, ok := readHeader(rb)
				if !ok || h.QR || h.TC || h.QDCount == 0 || h.RCode != 0x00 || h.ANCount != 0 || h.NSCount != 0 {
					h.RCode = rCodeFormatError
					if err := sendError(h, addr, conn, sB); err != nil {
						return err
					}
					continue
				}
				if h.Opcode != 0x00 || h.QDCount > 1 {
					h.RCode = rCodeNotImplemented
					if err := sendError(h, addr, conn, sB); err != nil {
						return err
					}
					continue
				}

				h.QR = true
				h.AA = true
				h.RA = false
				h.QDCount = 0
				h.ANCount = 0
				h.NSCount = 0
				h.ARCount = 0

				q, ok := readQuery(rb)
				if !ok {
					continue
				}

				queryID++
				sb := resolve(q, config.Zones, sB[headerSize:headerSize], queryID, &h)

				putHeader(h, sB[:0])

				if h.RCode != rCodeOK {
					sb = nil
				}
				if _, err := conn.WriteTo(sB[:headerSize+len(sb)], addr); err != nil {
					return err
				}
			}
		})

		return nil
	})
}

func sendError(h header, addr net.Addr, conn *net.UDPConn, b []byte) error {
	h.QR = true
	h.AA = true
	h.TC = false
	h.RA = false
	h.QDCount = 0
	h.ANCount = 0
	h.NSCount = 0
	h.ARCount = 0

	putHeader(h, b[:0])
	_, err := conn.WriteTo(b[:headerSize], addr)
	return errors.WithStack(err)
}

//nolint:gocyclo
func resolve(q query, zones map[string]ZoneConfig, b []byte, queryID uint64, h *header) []byte {
	if q.QName == "" {
		h.RCode = rCodeFormatError
		return b
	}
	if q.QClass != classInternet {
		h.RCode = rCodeNotImplemented
		return b
	}

	zConfig, ok := zone(q.QName, zones)
	if !ok {
		h.RCode = rCodeRefused
		return b
	}

	switch q.QType {
	case typeSOA:
		if q.QName != zConfig.Domain {
			h.RCode = rCodeNameError
			return b
		}

		email := strings.Replace(zConfig.Email, "@", ".", 1)
		b = putRecord(rRecord{
			Name:     q.QName,
			Type:     typeSOA,
			Class:    classInternet,
			TTL:      ttl,
			RDLength: nameLen(zConfig.MainNameserver) + nameLen(email) + 20,
		}, b, h)
		if h.TC {
			return b
		}
		b = putName(zConfig.MainNameserver, b)
		b = putName(email, b)
		b = binary.BigEndian.AppendUint32(b, zConfig.SerialNumber)
		b = binary.BigEndian.AppendUint32(b, ttl)
		b = binary.BigEndian.AppendUint32(b, ttl)
		b = binary.BigEndian.AppendUint32(b, ttl)
		b = binary.BigEndian.AppendUint32(b, ttl)

		return b
	case typeNS:
		if q.QName != zConfig.Domain || len(zConfig.Nameservers) == 0 {
			h.RCode = rCodeNameError
			return b
		}

		for i := range uint64(len(zConfig.Nameservers)) {
			ns := zConfig.Nameservers[(queryID+i)%uint64(len(zConfig.Nameservers))]
			b = putRecord(rRecord{
				Name:     q.QName,
				Type:     typeNS,
				Class:    classInternet,
				TTL:      ttl,
				RDLength: nameLen(ns),
			}, b, h)
			if h.TC {
				return b
			}
			b = putName(ns, b)
		}

		return b
	case typeMX:
		if q.QName != zConfig.Domain || len(zConfig.MailExchanges) == 0 {
			h.RCode = rCodeNameError
			return b
		}

		for d, p := range zConfig.MailExchanges {
			b = putRecord(rRecord{
				Name:     q.QName,
				Type:     typeMX,
				Class:    classInternet,
				TTL:      ttl,
				RDLength: 2 + nameLen(d),
			}, b, h)
			if h.TC {
				return b
			}
			b = binary.BigEndian.AppendUint16(b, p)
			b = putName(d, b)
		}

		return b
	}

	for {
		alias := zConfig.Aliases[q.QName]
		if alias.Target == "" {
			break
		}

		// cycle protection
		if alias.QueryID == queryID {
			h.RCode = rCodeServerFailure
			return b
		}
		alias.QueryID = queryID
		zConfig.Aliases[q.QName] = alias

		b = putRecord(rRecord{
			Name:     q.QName,
			Type:     typeCNAME,
			Class:    classInternet,
			TTL:      ttl,
			RDLength: nameLen(alias.Target),
		}, b, h)
		if h.TC {
			return b
		}
		b = putName(alias.Target, b)

		if q.QType == typeCNAME {
			return b
		}

		q.QName = alias.Target
	}

	switch q.QType {
	case typeCNAME:
		h.RCode = rCodeNameError
		return b
	case typeA:
		ips := zConfig.Domains[q.QName]
		if len(ips) == 0 {
			h.RCode = rCodeNameError
			return b
		}
		for i := range uint64(len(ips)) {
			ip := ips[(queryID+i)%uint64(len(ips))]
			b = putRecord(rRecord{
				Name:     q.QName,
				Type:     typeA,
				Class:    classInternet,
				TTL:      ttl,
				RDLength: 4,
			}, b, h)
			if h.TC {
				return b
			}
			b = append(b, ip...)
		}
	case typeTXT:
		values := zConfig.Texts[q.QName]
		if len(values) == 0 {
			h.RCode = rCodeNameError
			return b
		}
		var length uint16
		for _, v := range values {
			length += uint16(len(v)) + 1
		}
		b = putRecord(rRecord{
			Name:     q.QName,
			Type:     typeTXT,
			Class:    classInternet,
			TTL:      ttl,
			RDLength: length,
		}, b, h)
		if h.TC {
			return b
		}
		for _, v := range values {
			b = append(b, uint8(len(v)))
			b = append(b, v...)
		}
	default:
		h.RCode = rCodeNotImplemented
		return b
	}

	return b
}

func zone(qName string, zones map[string]ZoneConfig) (ZoneConfig, bool) {
	for {
		if zone, ok := zones[qName]; ok {
			return zone, true
		}
		pos := strings.Index(qName, ".")
		if pos < 0 {
			return ZoneConfig{}, false
		}
		qName = qName[pos+1:]
	}
}

func readHeader(b []byte) (header, []byte, bool) {
	var h header

	if len(b) < 2 {
		return h, nil, false
	}

	h.ID = binary.BigEndian.Uint16(b)

	if len(b) < headerSize {
		return h, nil, false
	}

	h.QR = b[2]&0x80 != 0x00
	h.Opcode = (b[2] & 0x7f) >> 3
	h.AA = b[2]&0x04 != 0x00
	h.TC = b[2]&0x02 != 0x00
	h.RD = b[2]&0x01 != 0x00
	h.RA = b[3]&0x80 != 0x00
	h.RCode = b[3] & 0x0f
	h.QDCount = binary.BigEndian.Uint16(b[4:])

	return h, b[12:], true
}

func readQuery(b []byte) (query, bool) {
	var q query
	var ok bool

	q.QName, b, ok = readName(b)
	if !ok {
		return query{}, false
	}

	if len(b) < 4 {
		return query{}, false
	}

	q.QType = binary.BigEndian.Uint16(b)
	q.QClass = binary.BigEndian.Uint16(b[2:])

	return q, true
}

func readName(b []byte) (string, []byte, bool) {
	var name string

	for {
		if len(b) == 0 {
			return "", nil, false
		}

		l := int(b[0])
		if l == 0 {
			return name, b[1:], true
		}
		if len(b) < 1+l {
			return "", nil, false
		}

		if len(name) > 0 {
			name += "."
		}
		name += string(b[1 : 1+l])
		b = b[1+l:]
	}
}

func putHeader(h header, b []byte) {
	b = binary.BigEndian.AppendUint16(b, h.ID)
	b = append(b, h.Opcode<<3)
	if h.QR {
		b[2] |= 0x80
	}
	if h.AA {
		b[2] |= 0x04
	}
	if h.TC {
		b[2] |= 0x02
	}
	if h.RD {
		b[2] |= 0x01
	}
	b = append(b, h.RCode)
	if h.RA {
		b[3] |= 0x80
	}
	b = binary.BigEndian.AppendUint16(b, h.QDCount)
	b = binary.BigEndian.AppendUint16(b, h.ANCount)
	b = binary.BigEndian.AppendUint16(b, h.NSCount)
	binary.BigEndian.AppendUint16(b, h.ARCount)
}

func putRecord(r rRecord, b []byte, h *header) []byte {
	length := uint16(len(b)) + nameLen(r.Name) + 10 + r.RDLength + headerSize
	if length > maxMsgLength || h.ANCount >= maxAnswers {
		h.TC = true
		return nil
	}

	h.ANCount++
	b = putName(r.Name, b)
	b = binary.BigEndian.AppendUint16(b, r.Type)
	b = binary.BigEndian.AppendUint16(b, r.Class)
	b = binary.BigEndian.AppendUint32(b, r.TTL)
	return binary.BigEndian.AppendUint16(b, r.RDLength)
}

func putName(name string, b []byte) []byte {
	for _, part := range strings.Split(name, ".") {
		b = append(b, uint8(len(part)))
		b = append(b, part...)
	}
	return append(b, 0x00)
}

func nameLen(name string) uint16 {
	return uint16(len(name)) + 2
}

type header struct {
	ID      uint16
	QR      bool
	Opcode  uint8
	AA      bool
	TC      bool
	RD      bool
	RA      bool
	RCode   uint8
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

type query struct {
	QName  string
	QType  uint16
	QClass uint16
}

type rRecord struct {
	Name     string
	Type     uint16
	Class    uint16
	TTL      uint32
	RDLength uint16
}
