package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strconv"
)

// Find the least common multiple for two big integers
func LCM(a *big.Int, b *big.Int) *big.Int {
	fmt.Println(a, b)
	// Create copies
	aCopy := new(big.Int).Set(a)
	bCopy := new(big.Int).Set(b)

	abMul := new(big.Int)
	resLCM := new(big.Int)

	resGCD := a.GCD(nil, nil, aCopy, bCopy)
	resLCM.Div(abMul.Mul(aCopy, bCopy), resGCD)
	return resLCM

}

// Convert message into bigInt followed by ASCII table
func convertMessage(m string) *big.Int {
	var i int
	var intStr string = ""
	messageArray := []rune(m)
	for i < len(messageArray) {
		intStr += (strconv.Itoa(int(messageArray[i])))
		i += 1
	}
	res, _ := big.NewInt(1).SetString(intStr, 0)
	return res
}

// Encryption of raw message (M) via public key (e,n)
func encryptMessage(m string, e *big.Int, n *big.Int) *big.Int {
	var encrypted big.Int
	convertedMessage := convertMessage(m)
	return encrypted.Exp(convertedMessage, e, n)
}

// Decryption of cipher (C) into readable message (M) via private key (d)
func decryptMessage(c *big.Int, d *big.Int, n *big.Int) *big.Int {
	var rawMessage = new(big.Int)
	rawMessage.Exp(c, d, n)
	return rawMessage
}

// Custom implementation of RSA cryptosystem
func main() {
	var keyLength int64 = 128
	var message string
	e := big.NewInt(65537)
	unit := big.NewInt(1)
	// Generating random p and q paramateres with approximate length of the key after multiplication
	qPrime, err1 := rand.Prime(rand.Reader, int(keyLength/2))
	if err1 != nil {
		fmt.Println("Error during number generation occured")

	}
	pPrime, err2 := rand.Prime(rand.Reader, int(keyLength/2))
	if err2 != nil {
		fmt.Println("Error during number generation occured")
	}
	n := big.NewInt(1).Mul(qPrime, pPrime)
	// Compute the Carmichael's totient function and validate result with e
	lambda := LCM(pPrime.Sub(pPrime, unit), qPrime.Sub(qPrime, unit))
	if big.NewInt(1).GCD(nil, nil, lambda, e).Cmp(unit) != 0 {
		panic("Randomization seed leaded to error")
	}
	d := big.NewInt(1).ModInverse(e, lambda)
	fmt.Println(lambda)
	fmt.Println(n)
	fmt.Println(d)
	fmt.Println("Enter the message:")
	fmt.Scanln(&message)
	c := encryptMessage(message, e, n)
	fmt.Println("Encrypted message is:\n", c)
	fmt.Println("Decrypted message is:\n", decryptMessage(c, d, n))
}
