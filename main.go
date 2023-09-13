package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"strings"
)

var EncryptedFlag string

func DecryptMessage(key []byte, message string) (string, error) {
	cipherText, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		return "", fmt.Errorf("could not base64 decode: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("could not create new cipher: %v", err)
	}

	if len(cipherText) < aes.BlockSize {
		return "", fmt.Errorf("invalid ciphertext block size")
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	return string(cipherText), nil
}

func main() {
	fmt.Print(`
              _-o#&&*''''?d:>b\_
          _o/"'''  '',, dMF9MMMMMHo_
       .o&#'        '"MbHMMMMMMMMMMMHo.
     .o"" '         vodM*$&&HMMMMMMMMMM?.
    ,'              $M&ood,~''(&##MMMMMMH\
   /               ,MMMMMMM#b?#bobMMMMHMMML
  &              ?MMMMMMMMMMMMMMMMM7MMM$R*Hk
 ?$.            :MMMMMMMMMMMMMMMMMMM/HMMM|'*L
|               |MMMMMMMMMMMMMMMMMMMMbMH'   T,
$H#:            '*MMMMMMMMMMMMMMMMMMMMb#}'  '?
]MMH#             ""*""""*#MMMMMMMMMMMMM'    -
MMMMMb_                   |MMMMMMMMMMMP'     :
HMMMMMMMHo                 'MMMMMMMMMT       .
?MMMMMMMMP                  9MMMMMMMM}       -
-?MMMMMMM                  |MMMMMMMMM?,d-    '
 :|MMMMMM-                 'MMMMMMMT .M|.   :
  .9MMM[                    &MMMMM*' ''    .
   :9MMk                    'MMM#"        -
     &M}                     '          .-
      '&.                             .
        '~,   .                     ./
            . _                  .-
              ''--._,dd###pp=""'
	`)

	var login string
	fmt.Println("World control v3.12.2")
	fmt.Print("Login> ")
	fmt.Scanln(&login)
	if login != "bra1nth3brain" {
		fmt.Println("Access Denied")
		return
	}

	var password string
	fmt.Print("Password> ")
	fmt.Scanln(&password)

	if len(password) != 16 {
		fmt.Println("Access Denied")
		return
	}

	decrypted, err := DecryptMessage([]byte(password), EncryptedFlag)
	if err != nil {
		fmt.Println("Access Denied")
		return
	}

	if !strings.HasPrefix(decrypted, "sutd") {
		fmt.Println("Access Denied")
		return
	}

	fmt.Println(decrypted)
	return
}
