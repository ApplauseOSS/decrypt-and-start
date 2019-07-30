package aws_encryption_sdk

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
)

const (
	CONTENT_TYPE_NON_FRAMED = 1
	CONTENT_TYPE_FRAMED     = 2
	SEQUENCE_NUMBER_END     = 0xFFFFFFFF
	STRING_ID_FRAME         = `AWSKMSEncryptionClient Frame`
	STRING_ID_FINAL_FRAME   = `AWSKMSEncryptionClient Final Frame`
	STRING_ID_NON_FRAMED    = `AWSKMSEncryptionClient Single Block`
)

// The following structs implements the AWS Encryption SDK Message Format
// https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html
type EncDataKey struct {
	ProviderId   string
	ProviderInfo string
	EncKeyData   []byte
}

type Frame struct {
	Final            bool
	SeqNumber        uint32
	IV               []byte
	EncContentLength uint32
	EncContent       []byte
	AuthTag          []byte
	AADContentString []byte
}

type Message struct {
	Version          uint8
	Type             uint8
	AlgorithmId      uint16
	Algorithm        *Algorithm
	MessageId        [16]byte
	EncContextLength uint16
	EncContext       map[string]string
	EncDataKeyCount  uint16
	EncDataKeys      []EncDataKey
	ContentType      uint8
	Reserved         uint32
	IVLength         uint8
	FrameLength      uint32
	HeaderAuth       struct {
		IV      []byte
		AuthTag []byte
	}
	Frames          []Frame
	SignatureLength uint16
	Signature       []byte
}

func NewMessage() *Message {
	m := &Message{}
	return m
}

func (m *Message) DecodeEncContext(r io.Reader) {
	m.EncContext = make(map[string]string)
	if m.EncContextLength > 0 {
		var dictSize uint16
		binary.Read(r, binary.BigEndian, &dictSize)
		var i uint16
		for i = 0; i < dictSize; i++ {
			var keyLength uint16
			var valueLength uint16
			binary.Read(r, binary.BigEndian, &keyLength)
			key := make([]byte, keyLength)
			r.Read(key)
			binary.Read(r, binary.BigEndian, &valueLength)
			value := make([]byte, valueLength)
			r.Read(value)
			m.EncContext[string(key)] = string(value)
		}
	}
}

func (m *Message) DecodeDataKeys(r io.Reader) {
	m.EncDataKeys = make([]EncDataKey, 0)
	if m.EncDataKeyCount > 0 {
		var i uint16
		for i = 0; i < m.EncDataKeyCount; i++ {
			var keyProviderIdLength uint16
			var keyProviderInfoLength uint16
			var encDataKeyLength uint16
			binary.Read(r, binary.BigEndian, &keyProviderIdLength)
			keyProviderId := make([]byte, keyProviderIdLength)
			r.Read(keyProviderId)
			binary.Read(r, binary.BigEndian, &keyProviderInfoLength)
			keyProviderInfo := make([]byte, keyProviderInfoLength)
			r.Read(keyProviderInfo)
			binary.Read(r, binary.BigEndian, &encDataKeyLength)
			encDataKey := make([]byte, encDataKeyLength)
			r.Read(encDataKey)
			m.EncDataKeys = append(m.EncDataKeys, EncDataKey{ProviderId: string(keyProviderId), ProviderInfo: string(keyProviderInfo), EncKeyData: encDataKey})
		}
	}
}

func (m *Message) DecodeBody(r io.Reader) {
	m.Frames = make([]Frame, 0)
	if m.ContentType == CONTENT_TYPE_NON_FRAMED {
		// TODO: implement me
	} else if m.ContentType == CONTENT_TYPE_FRAMED {
		for {
			var seqNumber uint32
			var f Frame
			f.IV = make([]byte, m.Algorithm.IVLength)
			f.AuthTag = make([]byte, m.Algorithm.AuthTagLength)
			binary.Read(r, binary.BigEndian, &seqNumber)
			if seqNumber == SEQUENCE_NUMBER_END {
				// Last frame
				f.Final = true
				binary.Read(r, binary.BigEndian, &f.SeqNumber)
				r.Read(f.IV)
				binary.Read(r, binary.BigEndian, &f.EncContentLength)
				f.AADContentString = []byte(STRING_ID_FINAL_FRAME)
			} else {
				f.SeqNumber = seqNumber
				r.Read(f.IV)
				f.EncContentLength = m.FrameLength
				f.AADContentString = []byte(STRING_ID_FRAME)
			}
			f.EncContent = make([]byte, f.EncContentLength)
			r.Read(f.EncContent)
			f.AuthTag = make([]byte, m.Algorithm.AuthTagLength)
			r.Read(f.AuthTag)
			m.Frames = append(m.Frames, f)
			if f.Final {
				break
			}
		}
	}
}

func (m *Message) Decode(r io.Reader) {
	binary.Read(r, binary.BigEndian, &m.Version)
	binary.Read(r, binary.BigEndian, &m.Type)
	binary.Read(r, binary.BigEndian, &m.AlgorithmId)
	binary.Read(r, binary.BigEndian, &m.MessageId)
	binary.Read(r, binary.BigEndian, &m.EncContextLength)
	m.DecodeEncContext(r)
	binary.Read(r, binary.BigEndian, &m.EncDataKeyCount)
	m.DecodeDataKeys(r)
	binary.Read(r, binary.BigEndian, &m.ContentType)
	binary.Read(r, binary.BigEndian, &m.Reserved)
	binary.Read(r, binary.BigEndian, &m.IVLength)
	binary.Read(r, binary.BigEndian, &m.FrameLength)
	m.Algorithm = lookupAlgorithm(m.AlgorithmId)
	if m.Algorithm == nil {
		log.Fatal(fmt.Sprintf("Unknown encryption algorithm with ID 0x%x", m.AlgorithmId))
	}
	m.HeaderAuth.IV = make([]byte, m.Algorithm.IVLength)
	m.HeaderAuth.AuthTag = make([]byte, m.Algorithm.AuthTagLength)
	r.Read(m.HeaderAuth.IV)
	r.Read(m.HeaderAuth.AuthTag)
	m.DecodeBody(r)
	// Footer
	binary.Read(r, binary.BigEndian, &m.SignatureLength)
	m.Signature = make([]byte, m.SignatureLength)
	r.Read(m.Signature)
}
