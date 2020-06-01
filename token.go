package magic

import (
	"encoding/base64"
	"encoding/json"
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

// Token struct holding the DIDToken string
type Token struct {
	DIDToken string
}

//New contructs a new token
func New(DIDToken string) *Token {
	return &Token{DIDToken: DIDToken}
}

func checkRequiredFields(claim map[string]interface{}) {
	var missingFields []string
	for _, field := range RequiredFields {
		if _, ok := claim[field]; !ok {
			missingFields = append(missingFields, field)
		}
	}

	if len(missingFields) > 0 {
		panic(&DIDTokenError{
			Message: fmt.Sprintf("DID token is missing required field(s): {%s}.", missingFields),
			Err:     nil,
		})
	}
}

// Issuer Extracts the iss from the DID Token.
func (t *Token) Issuer() string {
	_, claim := t.Decode()
	return claim["iss"].(string)
}

// PublicAddress public
func (t *Token) PublicAddress() string {
	iss := t.Issuer()
	siss := strings.Split(iss, ":")
	if siss == nil || len(siss) < 3 {
		panic(&DIDTokenError{
			Message: fmt.Sprintf("Given issuer (%s) is malformed. Please make sure it follows the `did:method-name:method-specific-id` format.", iss),
			Err:     nil,
		})
	}
	return strings.Split(iss, ":")[2]
}

//Decode decode
func (t *Token) Decode() (string, map[string]interface{}) {
	decodedDIDToken, err := base64.StdEncoding.DecodeString(t.DIDToken)
	if err != nil {
		panic(&DIDTokenError{
			Message: "DID token is malformed. It has to be a based64 encoded JSON serialized string.",
			Err:     err,
		})
	}

	var jsonDIDToken []string
	if err = json.Unmarshal(decodedDIDToken, &jsonDIDToken); err != nil {
		panic(&DIDTokenError{
			Message: "DID token is malformed. It has to be a based64 encoded JSON serialized string.",
			Err:     err,
		})
	}

	if len(jsonDIDToken) != ExpectedDIDTokenContentLength {
		panic(&DIDTokenError{
			Message: "DID token is malformed. It has to have two parts [proof, claim].",
			Err:     nil,
		})
	}

	proof := jsonDIDToken[0]

	var claim map[string]interface{}
	if err = json.Unmarshal([]byte(jsonDIDToken[1]), &claim); err != nil {
		panic(&DIDTokenError{
			Message: "DID token is malformed. Given claim should be a JSON serialized string.",
			Err:     err,
		})
	}
	checkRequiredFields(claim)
	return proof, claim
}

// Validate validate
func (t *Token) Validate(DIDToken string) {
	proof, claim := t.Decode()
	msg, err := json.Marshal(claim)
	if err != nil {
		panic(&DIDTokenError{
			Message: "",
			Err:     err,
		})
	}

	/*
		signature := proof[:len(proof)-1] // remove recovery id

		var recoveredAddress []byte
		_ = crypto.VerifySignature(recoveredAddress, msg, []byte(signature)) // Ignoring this until I figure out how to do it

		if false && (string(recoveredAddress) != t.PublicAddress()) {
			panic(&DIDTokenError{
				Message: "Signature mismatch between 'proof' and 'claim'. Please generate a new token with an intended issuer.",
				Err:     nil,
			})
		}
	*/

	currentTime := time.Now().Unix()

	if currentTime > int64(claim["ext"].(float64)) {
		panic(&DIDTokenError{
			Message: "Given DID token has expired. Please generate a new one.",
			Err:     nil,
		})
	}

	if currentTime < (int64(claim["nbf"].(float64)) - DIDTokenNBFGracePeriod) {
		panic(&DIDTokenError{
			Message: "Given DID token cannot be used at this time. Please check the 'nbf' field and regenerate a new token with a suitable value",
			Err:     nil,
		})
	}
}
