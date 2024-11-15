package rsa_alg

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"sync"
)

const paddingSize = 11

// generatePrime генерирует большое простое число заданной битности.
//
// bits - количество бит в генерируемом простом числе.
// Возвращает сгенерированное простое число.
func generatePrime(bits int) *big.Int {
	p, _ := rand.Prime(rand.Reader, bits)
	return p
}

// modInverse вычисляет обратный элемент a по модулю m с использованием алгоритма Евклида.
//
// a - число, для которого нужно найти обратный элемент.
// m - модуль, по которому вычисляется обратный элемент.
// Возвращает обратный элемент и ошибку, если она возникла.
func modInverse(a, m *big.Int) *big.Int {
	m0 := new(big.Int).Set(m)
	x0 := big.NewInt(0)
	x1 := big.NewInt(1)

	for a.Cmp(big.NewInt(1)) > 0 {
		q := new(big.Int).Div(a, m)
		t := new(big.Int).Set(m)

		m = new(big.Int).Mod(a, m)
		a = t

		t = new(big.Int).Set(x0)

		x0 = new(big.Int).Sub(x1, new(big.Int).Mul(q, x0))
		x1 = t
	}

	if x1.Cmp(big.NewInt(0)) < 0 {
		x1 = new(big.Int).Add(x1, m0)
	}

	return x1
}

// GenerateKeys генерирует пару ключей (открытый и закрытый) для алгоритма RSA.
//
// bits - общее количество бит в ключе.
// Возвращает модуль n, открытый экспонент e и закрытый экспонент d.
func GenerateKeys(bits int) (*big.Int, *big.Int, *big.Int) {
	p := generatePrime(bits / 2)
	q := generatePrime(bits / 2)
	n := new(big.Int).Mul(p, q)
	phi := new(big.Int).Mul(new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(q, big.NewInt(1)))

	e := big.NewInt(65537)
	d := modInverse(e, phi)

	return n, e, d
}

// encryptBlock шифрует один блок данных с использованием открытого ключа.
//
// block - байтовый массив, представляющий блок данных для шифрования.
// e - открытая экспонента.
// n - модуль.
// Возвращает зашифрованный блок в виде большого числа.
func encryptBlock(block []byte, e, n *big.Int) *big.Int {
	return new(big.Int).Exp(new(big.Int).SetBytes(block), e, n)
}

// decryptBlock расшифровывает зашифрованный блок с использованием закрытого ключа.
//
// ciphertext - зашифрованный блок в виде большого числа.
// d - закрытая экспонента.
// n - модуль.
// Возвращает расшифрованный блок в виде байтового массива.
func decryptBlock(ciphertext *big.Int, d, n *big.Int) []byte {
	return ciphertext.Exp(ciphertext, d, n).Bytes()
}

// Encrypt шифрует сообщение с использованием открытого ключа.
//
// message - строка, которую нужно зашифровать.
// e - открытая экспонента.
// n - модуль.
// Возвращает массив зашифрованных блоков и размер блока в байтах.
func Encrypt(message string, e, n *big.Int) ([]*big.Int, int) {
	var ciphertexts []*big.Int

	// Вычисление размера блока на основе размера ключа
	blockSize := n.BitLen()/8 - paddingSize // Размер блока в байтах
	fmt.Printf("Максимальный размер блока: %d байт\n", blockSize)

	for i := 0; i < len(message); i += blockSize {
		end := i + blockSize
		if end > len(message) {
			end = len(message)
		}
		block := []byte(message[i:end])
		ciphertext := encryptBlock(block, e, n)
		ciphertexts = append(ciphertexts, ciphertext)
	}

	return ciphertexts, blockSize
}

// Decrypt расшифровывает массив зашифрованных блоков с использованием закрытого ключа.
//
// ciphertexts - массив зашифрованных блоков в виде больших чисел.
// d - закрытая экспонента.
// n - модуль.
// Возвращает расшифрованное сообщение в виде строки.
func Decrypt(ciphertexts []*big.Int, d, n *big.Int) string {
	var wg sync.WaitGroup
	messageCh := make(chan struct {
		index int
		block []byte
	}, len(ciphertexts))

	for i, c := range ciphertexts {
		wg.Add(1)
		go func(index int, ciphertext *big.Int) {
			defer wg.Done()
			block := decryptBlock(ciphertext, d, n)
			messageCh <- struct {
				index int
				block []byte
			}{index, block}
		}(i, c)
	}

	wg.Wait()
	close(messageCh)

	// Сборка сообщения в правильном порядке
	message := make([][]byte, len(ciphertexts))
	for result := range messageCh {
		message[result.index] = result.block
	}

	return string(join(message))
}

// join объединяет массив байтовых массивов в один байтовый массив.
//
// parts - массив байтовых массивов, которые нужно объединить.
// Возвращает объединенный байтовый массив.
func join(parts [][]byte) []byte {
	var result []byte
	for _, part := range parts {
		result = append(result, part...)
	}
	return result
}
