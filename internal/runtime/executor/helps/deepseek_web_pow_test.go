package helps

import "testing"

func TestSolveDeepSeekWebPoWCapturedChallenge(t *testing.T) {
	nonce, err := SolveDeepSeekWebPoW(
		"DeepSeekHashV1",
		"ea74b2a42974e90c46295a2fbd0b6942bb686efc1b71e5aa70abeda64869ade4",
		"09fd35c1f240633d7545",
		144000,
		1787756464033,
	)
	if err != nil {
		t.Fatalf("SolveDeepSeekWebPoW() error = %v", err)
	}
	if nonce != 75656 {
		t.Fatalf("SolveDeepSeekWebPoW() nonce = %d, want 75656", nonce)
	}
}

func TestSolveDeepSeekWebPoWRejectsUnknownAlgorithm(t *testing.T) {
	if _, err := SolveDeepSeekWebPoW("unknown", "", "", 1, 0); err == nil {
		t.Fatal("SolveDeepSeekWebPoW() expected error")
	}
}
