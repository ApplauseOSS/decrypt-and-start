package aws_encryption_sdk

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"golang.org/x/crypto/hkdf"
)

type KmsHelper struct {
	client *kms.Client
}

func NewKmsHelper(region string, assumedRole string) *KmsHelper {
	ctx := context.Background()
	var cfg aws.Config
	var err error
	if assumedRole != "" {
		// Load default config
		cfg, err = config.LoadDefaultConfig(ctx, config.WithRegion(region))
		if err != nil {
			panic(err)
		}
		// Assume role
		stsClient := sts.NewFromConfig(cfg)
		resp, err := stsClient.AssumeRole(ctx, &sts.AssumeRoleInput{
			RoleArn:         aws.String(assumedRole),
			RoleSessionName: aws.String("decrypt-and-start-session"),
		})
		if err != nil {
			panic(err)
		}

		// Get a new config with the assumed role credentials
		var optFns []func(*config.LoadOptions) error
		optFns = append(optFns, config.WithRegion(region))
		optFns = append(optFns, config.WithCredentialsProvider(
			aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
				return aws.Credentials{
					AccessKeyID:     *resp.Credentials.AccessKeyId,
					SecretAccessKey: *resp.Credentials.SecretAccessKey,
					SessionToken:    *resp.Credentials.SessionToken,
					CanExpire:       true,
					Expires:         *resp.Credentials.Expiration,
				}, nil
			}),
		))

		newCfg, err := config.LoadDefaultConfig(ctx, optFns...)
		if err != nil {
			panic(err)
		}
		cfg = newCfg
	} else {
		cfg, err = config.LoadDefaultConfig(ctx, config.WithRegion(region))
		if err != nil {
			panic(err)
		}
	}
	return &KmsHelper{client: kms.NewFromConfig(cfg)}
}

// Decrypt encrypted data keys
func (k *KmsHelper) decryptDataKeys(m *Message) ([][]byte, error) {
	ret := make([][]byte, 0)
	var i uint16
	for i = 0; i < m.EncDataKeyCount; i++ {
		data, err := k.kmsDecrypt(m.EncDataKeys[i].EncKeyData, m)
		if err != nil {
			return nil, err
		}
		ret = append(ret, data)
	}
	return ret, nil
}

// Generate derived encryption key
func (k *KmsHelper) getDerivedKey(key []byte, m *Message) ([]byte, error) {
	if m.Algorithm.HashFunc != nil {
		info := bytes.NewBuffer(nil)
		if err := binary.Write(info, binary.BigEndian, m.Algorithm.Id); err != nil {
			return nil, err
		}
		if _, err := info.Write(m.MessageId[:]); err != nil {
			return nil, err
		}
		tmp_hkdf := hkdf.New(m.Algorithm.HashFunc, key, nil, info.Bytes())
		ret := make([]byte, m.Algorithm.DataKeyLength)
		if _, err := tmp_hkdf.Read(ret); err != nil {
			return nil, err
		}
		return ret, nil
	} else {
		return key, nil
	}
}

// Build additional data string for use in decryption
func (k *KmsHelper) buildContentAAD(m *Message, f *Frame) ([]byte, error) {
	ret := bytes.NewBuffer(nil)
	if _, err := ret.Write(m.MessageId[:]); err != nil {
		return nil, err
	}
	if _, err := ret.Write(f.AADContentString); err != nil {
		return nil, err
	}
	if err := binary.Write(ret, binary.BigEndian, f.SeqNumber); err != nil {
		return nil, err
	}
	if err := binary.Write(ret, binary.BigEndian, uint64(f.EncContentLength)); err != nil {
		return nil, err
	}
	return ret.Bytes(), nil
}

// Decrypt using KMS
func (k *KmsHelper) kmsDecrypt(data []byte, m *Message) ([]byte, error) {
	ctx := context.Background()
	in := &kms.DecryptInput{
		CiphertextBlob: data,
	}
	if m != nil && len(m.EncContext) > 0 {
		in.EncryptionContext = m.EncContext
	}

	result, err := k.client.Decrypt(ctx, in)
	if err != nil {
		return nil, err
	}
	return result.Plaintext, nil
}

// Decryption entrypoint
func (k *KmsHelper) Decrypt(data []byte) ([]byte, error) {
	var err error
	var plaintext []byte
	var data_keys [][]byte

	// Try simple KMS decryption first
	if plaintext, err = k.kmsDecrypt(data, nil); err == nil {
		return plaintext, nil
	} else if strings.Contains(err.Error(), "InvalidCiphertextException") {
		// Do nothing for an InvalidCiphertextException error
	} else {
		// Unknown error
		return nil, err
	}

	r := bytes.NewReader(data)
	message := NewMessage()
	if err := message.Decode(r); err != nil {
		return nil, err
	}
	data_keys, err = k.decryptDataKeys(message)
	if err != nil {
		return nil, err
	}
	plaintext = make([]byte, 0)
	for _, frame := range message.Frames {
		// TODO: support multiple data keys
		tmp_key, err := k.getDerivedKey(data_keys[0], message)
		if err != nil {
			return nil, err
		}

		var c cipher.Block
		switch message.Algorithm.Type {
		case ALGORITHM_TYPE_AES:
			c, err = aes.NewCipher(tmp_key)
			if err != nil {
				return nil, err
			}
		default:
			return nil, errors.New("unknown encryption algorithm type")
		}

		var mode cipher.AEAD
		switch message.Algorithm.Mode {
		case ALGORITHM_MODE_GCM:
			mode, err = cipher.NewGCM(c)
			if err != nil {
				return nil, err
			}
		default:
			return nil, errors.New("unknown encryption algorithm mode")
		}

		ciphertext := frame.EncContent
		// The encryption functions expect the auth tag to be appended to the ciphertext
		ciphertext = append(ciphertext, frame.AuthTag...)
		nonce := frame.IV

		contentAAD, err := k.buildContentAAD(message, &frame)
		if err != nil {
			return nil, err
		}
		frame_plaintext, err := mode.Open(nil, nonce, ciphertext, contentAAD)
		if err != nil {
			return nil, err
		}

		// Append frame plaintext to overall plaintext
		plaintext = append(plaintext, frame_plaintext...)
	}

	return plaintext, nil
}
