package error

import "fmt"

type BPFError struct {
	Action string
	Reason string
}

func (e *BPFError) Error() string {
	return fmt.Sprintf("action: %s, Reason: %s", e.Action, e.Reason)
}
