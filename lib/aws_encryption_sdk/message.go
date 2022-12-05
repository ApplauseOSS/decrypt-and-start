package aws_encryption_sdk

import (
	"encoding/binary"
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

func (m *Message) DecodeEncContext(r io.Reader) error {
	m.EncContext = make(map[string]string)
	if m.EncContextLength > 0 {
		var dictSize uint16
		if err := binary.Read(r, binary.BigEndian, &dictSize); err != nil {
			return err
		}
		var i uint16
		for i = 0; i < dictSize; i++ {
			var keyLength uint16
			var valueLength uint16
			if err := binary.Read(r, binary.BigEndian, &keyLength); err != nil {
				return err
			}
			key := make([]byte, keyLength)
			if _, err := r.Read(key); err != nil {
				return err
			}
			if err := binary.Read(r, binary.BigEndian, &valueLength); err != nil {
				return err
			}
			value := make([]byte, valueLength)
			if _, err := r.Read(value); err != nil {
				return err
			}
			m.EncContext[string(key)] = string(value)
		}
	}
	return nil
}

func (m *Message) DecodeDataKeys(r io.Reader) error {
	m.EncDataKeys = make([]EncDataKey, 0)
	if m.EncDataKeyCount > 0 {
		var i uint16
		for i = 0; i < m.EncDataKeyCount; i++ {
			var keyProviderIdLength uint16
			var keyProviderInfoLength uint16
			var encDataKeyLength uint16
			if err := binary.Read(r, binary.BigEndian, &keyProviderIdLength); err != nil {
				return err
			}
			keyProviderId := make([]byte, keyProviderIdLength)
			if _, err := r.Read(keyProviderId); err != nil {
				return err
			}
			if err := binary.Read(r, binary.BigEndian, &keyProviderInfoLength); err != nil {
				return err
			}
			keyProviderInfo := make([]byte, keyProviderInfoLength)
			if _, err := r.Read(keyProviderInfo); err != nil {
				return err
			}
			if err := binary.Read(r, binary.BigEndian, &encDataKeyLength); err != nil {
				return err
			}
			encDataKey := make([]byte, encDataKeyLength)
			if _, err := r.Read(encDataKey); err != nil {
				return err
			}
			m.EncDataKeys = append(m.EncDataKeys, EncDataKey{ProviderId: string(keyProviderId), ProviderInfo: string(keyProviderInfo), EncKeyData: encDataKey})
		}
	}
	return nil
}

func (m *Message) DecodeBody(r io.Reader) error {
	m.Frames = make([]Frame, 0)
	if m.ContentType == CONTENT_TYPE_NON_FRAMED {
		// TODO: implement me
	} else if m.ContentType == CONTENT_TYPE_FRAMED {
		for {
			var seqNumber uint32
			var f Frame
			f.IV = make([]byte, m.Algorithm.IVLength)
			f.AuthTag = make([]byte, m.Algorithm.AuthTagLength)
			if err := binary.Read(r, binary.BigEndian, &seqNumber); err != nil {
				return err
			}
			if seqNumber == SEQUENCE_NUMBER_END {
				// Last frame
				f.Final = true
				if err := binary.Read(r, binary.BigEndian, &f.SeqNumber); err != nil {
					return err
				}
				if _, err := r.Read(f.IV); err != nil {
					return err
				}
				if err := binary.Read(r, binary.BigEndian, &f.EncContentLength); err != nil {
					return err
				}
				f.AADContentString = []byte(STRING_ID_FINAL_FRAME)
			} else {
				f.SeqNumber = seqNumber
				if _, err := r.Read(f.IV); err != nil {
					return err
				}
				f.EncContentLength = m.FrameLength
				f.AADContentString = []byte(STRING_ID_FRAME)
			}
			f.EncContent = make([]byte, f.EncContentLength)
			if _, err := r.Read(f.EncContent); err != nil {
				return err
			}
			f.AuthTag = make([]byte, m.Algorithm.AuthTagLength)
			if _, err := r.Read(f.AuthTag); err != nil {
				return err
			}
			m.Frames = append(m.Frames, f)
			if f.Final {
				break
			}
		}
	}
	return nil
}

func (m *Message) Decode(r io.Reader) error {
	for _, varPtr := range []interface{}{&m.Version, &m.Type, &m.AlgorithmId, &m.MessageId, &m.EncContextLength} {
		if err := binary.Read(r, binary.BigEndian, varPtr); err != nil {
			return err
		}
	}
	if err := m.DecodeEncContext(r); err != nil {
		return err
	}
	if err := binary.Read(r, binary.BigEndian, &m.EncDataKeyCount); err != nil {
		return err
	}
	if err := m.DecodeDataKeys(r); err != nil {
		return err
	}
	for _, varPtr := range []interface{}{&m.ContentType, &m.Reserved, &m.IVLength, &m.FrameLength} {
		if err := binary.Read(r, binary.BigEndian, varPtr); err != nil {
			return err
		}
	}
	m.Algorithm = lookupAlgorithm(m.AlgorithmId)
	if m.Algorithm == nil {
		log.Fatalf("Unknown encryption algorithm with ID 0x%x", m.AlgorithmId)
	}
	m.HeaderAuth.IV = make([]byte, m.Algorithm.IVLength)
	m.HeaderAuth.AuthTag = make([]byte, m.Algorithm.AuthTagLength)
	if _, err := r.Read(m.HeaderAuth.IV); err != nil {
		return err
	}
	if _, err := r.Read(m.HeaderAuth.AuthTag); err != nil {
		return err
	}
	if err := m.DecodeBody(r); err != nil {
		return err
	}
	// Footer
	if err := binary.Read(r, binary.BigEndian, &m.SignatureLength); err != nil {
		return err
	}
	m.Signature = make([]byte, m.SignatureLength)
	if _, err := r.Read(m.Signature); err != nil {
		return err
	}
	return nil
}
