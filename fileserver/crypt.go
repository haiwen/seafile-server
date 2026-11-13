package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

type seafileCrypt struct {
	key     []byte
	iv      []byte
	version int
}

func (crypt *seafileCrypt) encrypt(input []byte) ([]byte, error) {
	key := crypt.key
	if crypt.version == 3 {
		key = to16Bytes(key)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	size := block.BlockSize()
	input = pkcs7Padding(input, size)
	out := make([]byte, len(input))

	if crypt.version == 3 {
		for bs, be := 0, size; bs < len(input); bs, be = bs+size, be+size {
			block.Encrypt(out[bs:be], input[bs:be])
		}
		return out, nil
	}

	blockMode := cipher.NewCBCEncrypter(block, crypt.iv)
	blockMode.CryptBlocks(out, input)

	return out, nil
}

func (crypt *seafileCrypt) decrypt(input []byte) ([]byte, error) {
	key := crypt.key
	if crypt.version == 3 {
		key = to16Bytes(key)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	size := block.BlockSize()
	if len(input) == 0 || len(input)%size != 0 {
		return nil, errors.New("invalid encrypted data size")
	}
	out := make([]byte, len(input))

	if crypt.version == 3 {
		// Encryption repo v3 uses AES_128_ecb mode to encrypt and decrypt, each block is encrypted and decrypted independently,
		// there is no relationship before and after, and iv is not required.
		for bs, be := 0, size; bs < len(input); bs, be = bs+size, be+size {
			block.Decrypt(out[bs:be], input[bs:be])
		}

		return pkcs7UnPadding(out, size)
	}

	blockMode := cipher.NewCBCDecrypter(block, crypt.iv)
	blockMode.CryptBlocks(out, input)

	return pkcs7UnPadding(out, size)
}

func pkcs7Padding(p []byte, blockSize int) []byte {
	padding := blockSize - len(p)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(p, padtext...)
}

func pkcs7UnPadding(p []byte, blockSize int) ([]byte, error) {
	length := len(p)
	if blockSize <= 0 || length == 0 || length%blockSize != 0 {
		return nil, errors.New("invalid data size")
	}

	paddLen := int(p[length-1])
	if paddLen == 0 || paddLen > blockSize || paddLen > length {
		return nil, errors.New("invalid padding size")
	}

	for _, b := range p[length-paddLen:] {
		if b != byte(paddLen) {
			return nil, errors.New("invalid padding bytes")
		}
	}

	return p[:length-paddLen], nil
}

func to16Bytes(input []byte) []byte {
	out := make([]byte, 16)
	copy(out, input)

	return out
}
