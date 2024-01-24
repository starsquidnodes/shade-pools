package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/miscreant/miscreant.go"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"gopkg.in/yaml.v2"
)

type (
	ListAmmPairsResponse struct {
		ListAmmPairs ListAmmPairs `json:"list_a_m_m_pairs"`
	}

	ListAmmPairs struct {
		AmmPairs []AmmPair `json:"amm_pairs"`
	}

	AmmPair struct {
		Pair     [3]json.RawMessage `json:"Pair"`
		Address  string             `json:"address"`
		CodeHash string             `json:"code_hash"`
		Enabled  bool               `json:"enabled"`
	}

	Token struct {
		CustomToken CustomToken `json:"custom_token"`
	}

	CustomToken struct {
		ContractAddress string `json:"contract_addr"`
		TokenCodeHash   string `json:"token_code_hash"`
	}
)

func main() {
	bz, err := os.ReadFile("secret-tokens.yml")
	if err != nil {
		panic(err)
	}

	tokens := map[string]string{}

	err = yaml.Unmarshal(bz, &tokens)
	if err != nil {
		panic(err)
	}

	address := "secret1ja0hcwvy76grqkpgwznxukgd7t8a8anmmx05pp"

	var priv [32]byte
	rand.Read(priv[:]) //nolint:errcheck

	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &priv)

	nonce := make([]byte, 32)
	_, err = rand.Read(nonce)
	if err != nil {
		panic(err)
	}

	consensusPubString := "79++5YOHfm0SwhlpUDClv7cuCjq9xBZlWqSjDJWkRG8="

	consensusPubBytes, err := base64.StdEncoding.DecodeString(
		consensusPubString,
	)
	if err != nil {
		panic(err)
	}

	sharedSecret, err := curve25519.X25519(priv[:], consensusPubBytes)

	hkdfSalt := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x02, 0x4b, 0xea, 0xd8, 0xdf, 0x69, 0x99,
		0x08, 0x52, 0xc2, 0x02, 0xdb, 0x0e, 0x00, 0x97,
		0xc1, 0xa1, 0x2e, 0xa6, 0x37, 0xd7, 0xe9, 0x6d,
	}

	if err != nil {
		panic(err)
	}

	hkdfReader := hkdf.New(
		sha256.New,
		append(sharedSecret, nonce...),
		hkdfSalt,
		[]byte{},
	)

	encryptionKey := make([]byte, 32)
	_, err = io.ReadFull(hkdfReader, encryptionKey)
	if err != nil {
		panic(err)
	}

	cipher, err := miscreant.NewAESCMACSIV(encryptionKey)
	if err != nil {
		panic(err)
	}

	for i := 0; i < 10; i++ {

		codeHash := "2ad4ed2a4a45fd6de3daca9541ba82c26bb66c76d1c3540de39b509abd26538e"
		message := fmt.Sprintf(
			`{"list_a_m_m_pairs":{"pagination":{"start":%d,"limit":30}}}`, i*30,
		)

		plaintext := codeHash + message

		ciphertext, err := cipher.Seal(nil, []byte(plaintext), []byte{})
		if err != nil {
			panic(err)
		}
		encrypted := append(nonce, append(pub[:], ciphertext...)...)

		query := base64.StdEncoding.EncodeToString(encrypted)
		query = url.QueryEscape(query)

		url := fmt.Sprintf("%s/compute/v1beta1/query/%s?query=%s",
			"https://lcd.mainnet.secretsaturn.net",
			address,
			query,
		)
		res, err := http.Get(url)
		if err != nil {
			panic(err)
		}

		body, err := io.ReadAll(res.Body)
		if err != nil {
			panic(err)
		}

		var jsonData map[string]string
		err = json.Unmarshal(body, &jsonData)
		if err != nil {
			panic(err)
		}

		// Extract 'data' from the JSON.
		resultdata, ok := jsonData["data"]
		if !ok {
			panic(err)
		}

		resultdataBytes, err := base64.StdEncoding.DecodeString(resultdata)
		if err != nil {
			panic(err)
		}

		decryptedBytes, err := cipher.Open(nil, resultdataBytes, []byte{})
		if err != nil {
			panic(err)
		}

		// Decode base64 string to get the original byte slice.
		decodedBytes, err := base64.StdEncoding.DecodeString(string(decryptedBytes))
		if err != nil {
			panic(err)
		}

		var response ListAmmPairsResponse
		err = json.Unmarshal(decodedBytes, &response)
		if err != nil {
			panic(err)
		}

		for _, ammPair := range response.ListAmmPairs.AmmPairs {
			var token1, token2 Token

			err = json.Unmarshal(ammPair.Pair[0], &token1)
			if err != nil {
				panic(err)
			}

			err = json.Unmarshal(ammPair.Pair[1], &token2)
			if err != nil {
				panic(err)
			}

			symbol1, found1 := tokens[token1.CustomToken.ContractAddress]
			symbol2, found2 := tokens[token2.CustomToken.ContractAddress]

			if !found1 {
				symbol1 = token1.CustomToken.ContractAddress
			}

			if !found2 {
				symbol2 = token2.CustomToken.ContractAddress
			}

			fmt.Printf("%s: %s / %s\n", ammPair.Address, symbol1, symbol2)
		}

		if len(response.ListAmmPairs.AmmPairs) < 30 {
			break
		}
	}
}
