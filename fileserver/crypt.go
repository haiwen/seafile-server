package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
)

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

func decrypt(input, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	out := make([]byte, len(input))
	blockMode := cipher.NewCBCDecrypter(block, iv)
	blockMode.CryptBlocks(out, input)
	out = pkcs7UnPadding(out)

	return out, nil
}

func encrypt(input, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	input = pkcs7Padding(input, block.BlockSize())
	out := make([]byte, len(input))
	blockMode := cipher.NewCBCEncrypter(block, iv)
	blockMode.CryptBlocks(out, input)

	return out, nil
}
