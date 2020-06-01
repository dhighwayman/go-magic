package magic

import "fmt"

//DIDTokenError token error
type DIDTokenError struct {
	Message string
	Err     error
}

func (err *DIDTokenError) Error() string {
	return fmt.Sprintf("%s\n %v", err.Message, err.Err)
}
