package magic

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ExpectedDIDTokenContentLength content
const ExpectedDIDTokenContentLength = 2

// DIDTokenNBFGracePeriod A grace period time in second applied to the nbf field for token validation.
const DIDTokenNBFGracePeriod = 300

// RequiredFields required fields
var RequiredFields = [7]string{
	"iat",
	"ext",
	"nbf",
	"iss",
	"sub",
	"aud",
	"tid",
}

// Token struct holding the didToken string, the proof and the claim (once decoded)
type Token struct {
	didToken string
	proof    string
	claim    map[string]interface{}
}

//New contructs a new token
func New(didToken string) (*Token, error) {
	token := &Token{didToken: didToken}
	var err error
	token.proof, token.claim, err = token.Decode()
	if err != nil {
		return nil, err
	}
	return token, nil
}

func checkRequiredFields(claim map[string]interface{}) error {
	var missingFields []string
	for _, field := range RequiredFields {
		if _, ok := claim[field]; !ok {
			missingFields = append(missingFields, field)
		}
	}

	if len(missingFields) > 0 {
		return fmt.Errorf("DID token is missing required field(s): {%s}", missingFields)
	}
	return nil
}

// Issuer Extracts the iss from the DID Token.
func (t *Token) Issuer() string {
	return t.claim["iss"].(string)
}

// PublicAddress public address of the issuer
func (t *Token) PublicAddress() (string, error) {
	iss := t.Issuer()
	siss := strings.Split(iss, ":")
	if siss == nil || len(siss) < 3 {
		return "", fmt.Errorf("Given issuer (%s) is malformed. Please make sure it follows the `did:method-name:method-specific-id` format", iss)
	}
	return strings.Split(iss, ":")[2], nil
}

//Decode decode the didToken
func (t *Token) Decode() (string, map[string]interface{}, error) {
	decodedDIDToken, err := base64.StdEncoding.DecodeString(t.didToken)
	if err != nil {
		return "", nil, errors.New("DID token is malformed. It has to be a based64 encoded JSON serialized string")
	}

	var jsonDIDToken []string
	if err = json.Unmarshal(decodedDIDToken, &jsonDIDToken); err != nil {
		return "", nil, errors.New("DID token is malformed. It has to be a based64 encoded JSON serialized string")
	}

	if len(jsonDIDToken) != ExpectedDIDTokenContentLength {
		return "", nil, errors.New("DID token is malformed. It has to have two parts [proof, claim]")
	}

	proof := jsonDIDToken[0]

	var claim map[string]interface{}
	if err = json.Unmarshal([]byte(jsonDIDToken[1]), &claim); err != nil {
		return "", nil, errors.New("DID token is malformed. Given claim should be a JSON serialized string")
	}
	err = checkRequiredFields(claim)
	if err != nil {
		return "", nil, err
	}

	return proof, claim, nil
}

// Validate validate
func (t *Token) Validate() error {
	_, err := json.Marshal(t.claim)
	if err != nil {
		return err
	}

	/*
		signature := t.proof[:len(t.proof)-1] // remove recovery id
		var recoveredAddress []byte
		_ = crypto.VerifySignature(recoveredAddress, msg, []byte(signature)) // Ignoring this until I figure out how to do it

		if false && (string(recoveredAddress) != t.PublicAddress()) {
			return fmt.Errorf"Signature mismatch between 'proof' and 'claim'. Please generate a new token with an intended issuer")
		}
	*/

	currentTime := time.Now().Unix()

	if currentTime > int64(t.claim["ext"].(float64)) {
		return fmt.Errorf("Given DID token has expired. Please generate a new one")
	}

	if currentTime < (int64(t.claim["nbf"].(float64)) - DIDTokenNBFGracePeriod) {
		return fmt.Errorf("Given DID token cannot be used at this time. Please check the 'nbf' field and regenerate a new token with a suitable value")
	}
	return nil
}
