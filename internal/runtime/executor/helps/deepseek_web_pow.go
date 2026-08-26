package helps

import (
	"encoding/hex"
	"fmt"
	"math/bits"
	"strconv"
)

const deepSeekWebRate = 136

var deepSeekWebRoundConstants = [24]uint64{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
	0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
	0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
	0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
	0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
	0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
	0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
	0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
}

var deepSeekWebRotationOffsets = [25]int{
	0, 1, 62, 28, 27,
	36, 44, 6, 55, 20,
	3, 10, 43, 25, 39,
	41, 45, 15, 21, 8,
	18, 2, 61, 56, 14,
}

// SolveDeepSeekWebPoW solves DeepSeekHashV1 challenges. DeepSeek's web
// implementation intentionally applies rounds 1..23 of Keccak-f[1600] (round
// zero is skipped), with rate=136 and SHA-3 domain separator 0x06.
func SolveDeepSeekWebPoW(algorithm, challenge, salt string, difficulty int, expireAt int64) (int, error) {
	if algorithm != "DeepSeekHashV1" {
		return -1, fmt.Errorf("unsupported DeepSeek PoW algorithm %q", algorithm)
	}
	if difficulty <= 0 {
		return -1, fmt.Errorf("invalid DeepSeek PoW difficulty %d", difficulty)
	}
	want, errDecode := hex.DecodeString(challenge)
	if errDecode != nil || len(want) != 32 {
		return -1, fmt.Errorf("invalid DeepSeek PoW challenge")
	}
	prefix := []byte(salt + "_" + strconv.FormatInt(expireAt, 10) + "_")
	candidate := make([]byte, len(prefix), len(prefix)+20)
	copy(candidate, prefix)
	for nonce := 0; nonce < difficulty; nonce++ {
		candidate = candidate[:len(prefix)]
		candidate = strconv.AppendInt(candidate, int64(nonce), 10)
		digest := deepSeekWebDigest(candidate)
		if string(digest[:]) == string(want) {
			return nonce, nil
		}
	}
	return -1, fmt.Errorf("DeepSeek PoW solution not found")
}

func deepSeekWebDigest(message []byte) [32]byte {
	var state [25]uint64
	for len(message) >= deepSeekWebRate {
		deepSeekWebXORBlock(&state, message[:deepSeekWebRate])
		deepSeekWebKeccakF1600(&state)
		message = message[deepSeekWebRate:]
	}
	var block [deepSeekWebRate]byte
	copy(block[:], message)
	block[len(message)] ^= 0x06
	block[deepSeekWebRate-1] ^= 0x80
	deepSeekWebXORBlock(&state, block[:])
	deepSeekWebKeccakF1600(&state)
	var out [32]byte
	for i := range out {
		out[i] = byte(state[i/8] >> (8 * (i % 8)))
	}
	return out
}

func deepSeekWebXORBlock(state *[25]uint64, block []byte) {
	for i, value := range block {
		state[i/8] ^= uint64(value) << (8 * (i % 8))
	}
}

func deepSeekWebKeccakF1600(state *[25]uint64) {
	// Match DeepSeek's browser solver: the loop starts at round 1.
	for _, roundConstant := range deepSeekWebRoundConstants[1:] {
		var columns [5]uint64
		for x := 0; x < 5; x++ {
			columns[x] = state[x] ^ state[x+5] ^ state[x+10] ^ state[x+15] ^ state[x+20]
		}
		for x := 0; x < 5; x++ {
			delta := columns[(x+4)%5] ^ bits.RotateLeft64(columns[(x+1)%5], 1)
			for y := 0; y < 5; y++ {
				state[x+5*y] ^= delta
			}
		}
		var rotated [25]uint64
		for x := 0; x < 5; x++ {
			for y := 0; y < 5; y++ {
				source := x + 5*y
				destination := y + 5*((2*x+3*y)%5)
				rotated[destination] = bits.RotateLeft64(state[source], deepSeekWebRotationOffsets[source])
			}
		}
		for x := 0; x < 5; x++ {
			for y := 0; y < 5; y++ {
				index := x + 5*y
				state[index] = rotated[index] ^ (^rotated[(x+1)%5+5*y] & rotated[(x+2)%5+5*y])
			}
		}
		state[0] ^= roundConstant
	}
}
