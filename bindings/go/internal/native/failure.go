package native

// Failure carries native categories without including sensitive values in text.
// Cause retains loader and transport errors for the public adapter to unwrap.
type Failure struct {
	Kind         string `json:"kind"`
	Protocol     string `json:"protocol"`
	TimeoutPhase string `json:"timeout_phase"`
	Field        string `json:"field"`
	Cause        error  `json:"-"`
}

func (failure *Failure) Error() string { return "phantom: " + failure.Kind }
func (failure *Failure) Unwrap() error { return failure.Cause }
