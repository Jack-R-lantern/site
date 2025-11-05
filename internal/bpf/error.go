package bpf

import "fmt"

type BPFError struct {
	Action string
	Value  string
	Reason string
}

func (e *BPFError) Error() string {
	return fmt.Sprintf("action: %s, value: %s, Reason: %s", e.Action, e.Value, e.Reason)
}
