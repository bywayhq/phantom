package phantom

import (
	"encoding/json"
	"runtime"
	"sync/atomic"
)

// AttemptBudget is an atomic native allowance shared across requests and clients.
// Admissions include initial attempts and resends, and are never refunded.
type AttemptBudget struct{ id atomic.Uint64 }

// NewAttemptBudget creates a shared allowance, including an initially empty one.
func NewAttemptBudget(maximum uint64) (*AttemptBudget, error) {
	value, err := dispatch(map[string]any{"kind": "new_budget", "maximum": maximum}, nil)
	if err != nil {
		return nil, err
	}
	var result struct {
		ID uint64 `json:"id"`
	}
	if json.Unmarshal(value, &result) != nil {
		return nil, &Error{Kind: "native_abi"}
	}
	budget := &AttemptBudget{}
	budget.id.Store(result.ID)
	runtime.SetFinalizer(budget, func(owner *AttemptBudget) { _ = owner.Close() })
	return budget, nil
}

// Remaining reports the allowance left.
func (b *AttemptBudget) Remaining() (uint64, error) {
	value, err := dispatch(map[string]any{"kind": "budget_remaining", "budget": b.id.Load()}, nil)
	runtime.KeepAlive(b)
	if err != nil {
		return 0, err
	}
	var result struct {
		Remaining uint64 `json:"remaining"`
	}
	if json.Unmarshal(value, &result) != nil {
		return 0, &Error{Kind: "native_abi"}
	}
	return result.Remaining, nil
}

// TryAdmit charges work initiated outside Phantom; Do charges its own attempts.
func (b *AttemptBudget) TryAdmit() error {
	err := control("budget_admit", "budget", b.id.Load())
	runtime.KeepAlive(b)
	return err
}

// Close releases this handle. Requests already admitted retain their allowance.
func (b *AttemptBudget) Close() error {
	id := b.id.Swap(0)
	if id == 0 {
		return nil
	}
	runtime.SetFinalizer(b, nil)
	return control("release_budget", "budget", id)
}
