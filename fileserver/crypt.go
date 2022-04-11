package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
)

type seafileCrypt struct {
	key     []byte
	iv      []byte
	version int
}

func (crypt *seafileCrypt) encrypt(input []byte) ([]byte, error) {
	key := crypt.key
	if crypt.version == 3 {
		key = genKey(key)
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
		key = genKey(key)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(input))
	size := block.BlockSize()

	if crypt.version == 3 {
		for bs, be := 0, size; bs < len(input); bs, be = bs+size, be+size {
			block.Decrypt(out[bs:be], input[bs:be])
		}
		out = pkcs7UnPadding(out)
		return out, nil
	}

	blockMode := cipher.NewCBCDecrypter(block, crypt.iv)
	blockMode.CryptBlocks(out, input)
	out = pkcs7UnPadding(out)

	return out, nil
}

func pkcs7Padding(p []byte, blockSize int) []byte {
	padding := blockSize - len(p)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(p, padtext...)
}

func pkcs7UnPadding(p []byte) []byte {
	length := len(p)
	paddLen := int(p[length-1])
	return p[:(length - paddLen)]
}

func genKey(input []byte) []byte {
	out := make([]byte, 16)
	copy(out, input)

	return out
}
