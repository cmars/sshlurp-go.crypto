package ssh

import (
	"bytes"
	"crypto"
	"crypto/md5"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
)

func DialASlurp(network, addr string, config *ClientConfig) ([]byte, error) {
	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return Slurp(conn, config)
}

func Slurp(c net.Conn, config *ClientConfig) ([]byte, error) {
	conn := &ClientConn{
		transport:     newTransport(c, config.rand()),
		config:        config,
		globalRequest: globalRequest{response: make(chan interface{}, 1)},
	}
	defer conn.Close()
	return conn.slurpHostKey()
}

// SlurpHostKey acts like its going to handshake, but it just plays along long enough to get the host key.
func (c *ClientConn) slurpHostKey() ([]byte, error) {
	var magics handshakeMagics

	if _, err := c.Write(clientVersion); err != nil {
		return nil, err
	}
	if err := c.Flush(); err != nil {
		return nil, err
	}
	magics.clientVersion = clientVersion[:len(clientVersion)-2]

	// read remote server version
	version, err := readVersion(c)
	if err != nil {
		return nil, err
	}
	magics.serverVersion = version
	clientKexInit := kexInitMsg{
		KexAlgos:                supportedKexAlgos,
		ServerHostKeyAlgos:      supportedHostKeyAlgos,
		CiphersClientServer:     c.config.Crypto.ciphers(),
		CiphersServerClient:     c.config.Crypto.ciphers(),
		MACsClientServer:        c.config.Crypto.macs(),
		MACsServerClient:        c.config.Crypto.macs(),
		CompressionClientServer: supportedCompressions,
		CompressionServerClient: supportedCompressions,
	}
	kexInitPacket := marshal(msgKexInit, clientKexInit)
	magics.clientKexInit = kexInitPacket

	if err := c.writePacket(kexInitPacket); err != nil {
		return nil, err
	}
	packet, err := c.readPacket()
	if err != nil {
		return nil, err
	}

	magics.serverKexInit = packet

	var serverKexInit kexInitMsg
	if err = unmarshal(&serverKexInit, packet, msgKexInit); err != nil {
		return nil, err
	}

	kexAlgo, hostKeyAlgo, ok := findAgreedAlgorithms(c.transport, &clientKexInit, &serverKexInit)
	if !ok {
		return nil, errors.New("ssh: no common algorithms")
	}

	if serverKexInit.FirstKexFollows && kexAlgo != serverKexInit.KexAlgos[0] {
		// The server sent a Kex message for the wrong algorithm,
		// which we have to ignore.
		if _, err := c.readPacket(); err != nil {
			return nil, err
		}
	}

	var hostKey []byte
	var hashFunc crypto.Hash
	switch kexAlgo {
	case kexAlgoDH14SHA1:
		hashFunc = crypto.SHA1
		dhGroup14Once.Do(initDHGroup14)
		_, _, hostKey, err = c.kexDH(dhGroup14, hashFunc, &magics, hostKeyAlgo)
	case keyAlgoDH1SHA1:
		hashFunc = crypto.SHA1
		dhGroup1Once.Do(initDHGroup1)
		_, _, hostKey, err = c.kexDH(dhGroup1, hashFunc, &magics, hostKeyAlgo)
	default:
		err = fmt.Errorf("ssh: unexpected key exchange algorithm %v", kexAlgo)
	}
	if err != nil {
		return nil, err
	}

	return hostKey, err
}

type SlurpedHostKey struct {
	Key interface{}
}

var HostKeyParseErr error = errors.New("Parse error on host key")

func ParseHostKey(buf []byte) (*SlurpedHostKey, error) {
	key, _, ok := parsePubKey(buf)
	if !ok {
		return nil, HostKeyParseErr
	}
	return &SlurpedHostKey{key}, nil
}

func (pk *SlurpedHostKey) String() string {
	armor := base64.StdEncoding.EncodeToString(serializePublickey(pk.Key))
	return fmt.Sprintf("%s %s", algoName(pk.Key), armor)
}

func (pk *SlurpedHostKey) Fingerprint() string {
	h := md5.New()
	h.Write(serializePublickey(pk.Key))
	fp := h.Sum(nil)
	result := bytes.NewBuffer([]byte{})
	for i := 0; i < len(fp); i++ {
		if i > 0 {
			result.WriteByte(byte(':'))
		}
		io.WriteString(result, fmt.Sprintf("%02x", fp[i]))
	}
	return string(result.Bytes())
}
