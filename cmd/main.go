package main

import (
	"fmt"
	"os"
	"time"

	rsa "github.com/SanyaWarvar/rsa/pkg/rsa_alg"
)

func main() {

	n, e, d := rsa.GenerateKeys(64)

	// Сообщение для шифрования
	message, err := ReadTextFile("war_and_peace.ru.txt")
	if err != nil {
		fmt.Println(err)
	}

	//fmt.Printf("Исходное сообщение: %s\n", message)
	messageSize := len(message)
	symbolsNum := len([]rune(message))
	startTime := time.Now()
	fmt.Printf("Размер текста: %d байт (%.4f МБайт). Это %d символов.\n", messageSize, float64(messageSize)/1024/1024, symbolsNum)
	ciphertexts, _ := rsa.Encrypt(message, e, n)
	/*fmt.Printf("Зашифрованное сообщение: ")
	for _, c := range ciphertexts {
		fmt.Printf("%s ", c.String())
	}*/
	encryptTime := time.Now()

	decryptedMessage := rsa.Decrypt(ciphertexts, d, n)
	decryptTime := time.Now()
	//fmt.Printf("Расшифрованное сообщение: %s\n", decryptedMessage)
	endSize := len(decryptedMessage)
	if endSize == 0 {

	}
	fmt.Printf("Расшифрованное сообщение идентично начальному: %v\n", message == decryptedMessage)
	fmt.Printf("Время шифровки: %v. Время дешифровки: %v", encryptTime.Sub(startTime), decryptTime.Sub(encryptTime))
}

// ReadTextFile считывает содержимое текстового файла по указанному пути.
// Возвращает содержимое файла в виде строки или ошибку, если файл не найден или не может быть прочитан.
//
// Параметры:
//
//	path (string): путь к текстовому файлу
//
// Возвращает:
//
//	string: содержимое файла
//	error: ошибка, если файл не найден или не может быть прочитан
func ReadTextFile(path string) (string, error) {
	// Чтение файла
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
