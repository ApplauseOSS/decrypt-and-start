package aws_encryption_sdk

import (
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

const (
	ALGORITHM_TYPE_AES = 1
	ALGORITHM_MODE_GCM = 1
)

type Algorithm struct {
	Id            uint16
	Type          uint8
	DataKeyLength uint16
	Mode          uint8
	IVLength      uint8
	AuthTagLength uint8
	HashFunc      func() hash.Hash
}

// List of encryption algorithms for AWS Encryption SDK
// https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/algorithms-reference.html
var Algorithms = []Algorithm{
	{
		Id:            0x0378,
		Type:          ALGORITHM_TYPE_AES,
		DataKeyLength: 32,
		Mode:          ALGORITHM_MODE_GCM,
		IVLength:      12,
		AuthTagLength: 16,
		HashFunc:      sha512.New384,
	},
	{
		Id:            0x0346,
		Type:          ALGORITHM_TYPE_AES,
		DataKeyLength: 24,
		Mode:          ALGORITHM_MODE_GCM,
		IVLength:      12,
		AuthTagLength: 16,
		HashFunc:      sha512.New384,
	},
	{
		Id:            0x0214,
		Type:          ALGORITHM_TYPE_AES,
		DataKeyLength: 16,
		Mode:          ALGORITHM_MODE_GCM,
		IVLength:      12,
		AuthTagLength: 16,
		HashFunc:      sha256.New,
	},
	{
		Id:            0x0178,
		Type:          ALGORITHM_TYPE_AES,
		DataKeyLength: 32,
		Mode:          ALGORITHM_MODE_GCM,
		IVLength:      12,
		AuthTagLength: 16,
		HashFunc:      sha256.New,
	},
	{
		Id:            0x0146,
		Type:          ALGORITHM_TYPE_AES,
		DataKeyLength: 24,
		Mode:          ALGORITHM_MODE_GCM,
		IVLength:      12,
		AuthTagLength: 16,
		HashFunc:      sha256.New,
	},
	{
		Id:            0x0114,
		Type:          ALGORITHM_TYPE_AES,
		DataKeyLength: 16,
		Mode:          ALGORITHM_MODE_GCM,
		IVLength:      12,
		AuthTagLength: 16,
		HashFunc:      sha256.New,
	},
	{
		Id:            0x0078,
		Type:          ALGORITHM_TYPE_AES,
		DataKeyLength: 32,
		Mode:          ALGORITHM_MODE_GCM,
		IVLength:      12,
		AuthTagLength: 16,
		HashFunc:      nil,
	},
	{
		Id:            0x0046,
		Type:          ALGORITHM_TYPE_AES,
		DataKeyLength: 24,
		Mode:          ALGORITHM_MODE_GCM,
		IVLength:      12,
		AuthTagLength: 16,
		HashFunc:      nil,
	},
	{
		Id:            0x0014,
		Type:          ALGORITHM_TYPE_AES,
		DataKeyLength: 16,
		Mode:          ALGORITHM_MODE_GCM,
		IVLength:      12,
		AuthTagLength: 16,
		HashFunc:      nil,
	},
}

func lookupAlgorithm(id uint16) *Algorithm {
	for _, algo := range Algorithms {
		if id == algo.Id {
			return &algo
		}
	}
	return nil
}
