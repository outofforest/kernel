package dhcp6

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"golang.org/x/net/ipv6"
)

const (
	dhcpMulticastGroup = "ff02::1:2"
	dhcp6ServerPort    = 547
)

// Run runs DHCP IPv6 server giving random IP addresses required to send EFI payload later.
func Run(ctx context.Context) error {
	serverUUIDValue, err := uuid.NewUUID()
	if err != nil {
		return errors.WithStack(err)
	}
	serverUUID := make([]byte, 18)
	serverUUID[1] = 0x04
	copy(serverUUID[2:], serverUUIDValue[:])

	iface, err := net.InterfaceByName("enp9s0")
	if err != nil {
		return errors.WithStack(err)
	}

	conn, err := net.ListenPacket("udp6", ":"+strconv.Itoa(dhcp6ServerPort))
	if err != nil {
		return errors.WithStack(err)
	}
	defer conn.Close()

	p := ipv6.NewPacketConn(conn)
	if err := p.JoinGroup(iface, &net.UDPAddr{
		IP:   net.ParseIP(dhcpMulticastGroup),
		Port: dhcp6ServerPort,
	}); err != nil {
		return errors.WithStack(err)
	}

	b := make([]byte, 4096)

	fmt.Println("Waiting for solicit")

	n, addr, err := conn.ReadFrom(b)
	if err != nil {
		return errors.WithStack(err)
	}

	solicitMsg := parseMessage(b[:n])
	if solicitMsg.MessageType != MessageTypeSolicit {
		return errors.New("solicit message expected")
	}

	transactionID := solicitMsg.TransactionID

	fmt.Println("Solicit received")

	var clientUUID []byte
	for _, o := range solicitMsg.Options {
		switch o.OptionCode {
		case OptionCodeClientID:
			if clientUUID != nil {
				return errors.New("duplicated client ID")
			}
			clientUUID = make([]byte, len(o.OptionData))
			copy(clientUUID, o.OptionData)
		case OptionCodeServerID:
			return errors.New("unexpected server ID")
		}
	}
	if clientUUID == nil {
		return errors.New("client ID not present")
	}

	fmt.Println(len(clientUUID))

	fmt.Println("Sending advertise")

	if _, err := conn.WriteTo(serializeMessage(Message{
		MessageType:   MessageTypeAdvertise,
		TransactionID: transactionID,
		Options: []Option{
			{
				OptionCode: OptionCodeClientID,
				OptionData: clientUUID,
			},
			{
				OptionCode: OptionCodeServerID,
				OptionData: serverUUID,
			},
		},
	}, b), addr); err != nil {
		return errors.WithStack(err)
	}

	fmt.Println("Waiting for request")

	n, addr, err = conn.ReadFrom(b)
	if err != nil {
		return errors.WithStack(err)
	}

	requestMsg := parseMessage(b[:n])
	if requestMsg.MessageType != MessageTypeRequest {
		return errors.New("request message expected")
	}

	var receivedClientUUID, receivedServerUUID []byte
	for _, o := range requestMsg.Options {
		switch o.OptionCode {
		case OptionCodeClientID:
			if receivedClientUUID != nil {
				return errors.New("duplicated client ID")
			}
			receivedClientUUID = make([]byte, len(o.OptionData))
			copy(receivedClientUUID, o.OptionData)
		case OptionCodeServerID:
			if receivedServerUUID != nil {
				return errors.New("duplicated server ID")
			}
			receivedServerUUID = make([]byte, len(o.OptionData))
			copy(receivedServerUUID, o.OptionData)
		}
	}
	if receivedClientUUID == nil {
		return errors.New("client ID not present")
	}
	if receivedServerUUID == nil {
		return errors.New("server ID not present")
	}
	if !bytes.Equal(receivedServerUUID, serverUUID) {
		return errors.New("server ID does not match")
	}

	fmt.Println("Request received")

	n, addr, err = conn.ReadFrom(b)
	if err != nil {
		return errors.WithStack(err)
	}
	fmt.Println(addr.String())
	fmt.Printf("%#v\n", b[:n])

	return errors.New("test")
}

func parseMessage(b []byte) Message {
	m := Message{
		MessageType:   MessageType(b[0]),
		TransactionID: TransactionID(b[1:4]),
	}

	b = b[4:]
	for len(b) > 0 {
		optionLen := binary.BigEndian.Uint16(b[2:4])
		m.Options = append(m.Options, Option{
			OptionCode: OptionCode(binary.BigEndian.Uint16(b[:2])),
			OptionData: b[4 : 4+optionLen],
		})
		b = b[4+optionLen:]
	}

	return m
}

func serializeMessage(m Message, b []byte) []byte {
	b = b[:0]
	b = append(b, byte(m.MessageType))
	b = append(b, m.TransactionID[:]...)
	for _, o := range m.Options {
		b = binary.BigEndian.AppendUint16(b, uint16(o.OptionCode))
		b = binary.BigEndian.AppendUint16(b, uint16(len(o.OptionData)))
		b = append(b, o.OptionData...)
	}

	return b
}

type Message struct {
	MessageType   MessageType
	TransactionID TransactionID
	Options       []Option
}

type MessageType byte

const (
	MessageTypeSolicit   MessageType = 1
	MessageTypeAdvertise MessageType = 2
	MessageTypeRequest   MessageType = 3
)

type TransactionID [3]byte

type Option struct {
	OptionCode OptionCode
	OptionData []byte
}

type OptionCode uint16

const (
	OptionCodeClientID OptionCode = 1
	OptionCodeServerID OptionCode = 2
)
