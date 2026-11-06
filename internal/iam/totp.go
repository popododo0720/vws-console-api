package iam

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 6238 TOTP is defined over HMAC-SHA1.
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"time"
)

// totpPeriod is the RFC 6238 time step of an AWS virtual MFA device.
const totpPeriod = 30 * time.Second

// TOTPCode is the six-digit RFC 6238 code of seed at time t. It is exported
// for tests that act as the device.
func TOTPCode(seed []byte, t time.Time) string {
	return totpAt(seed, t.Unix()/int64(totpPeriod/time.Second))
}

func totpAt(seed []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step)) //nolint:gosec // steps since 1970 are positive.
	mac := hmac.New(sha1.New, seed)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1_000_000)
}

// totpSequence reports whether code1 is the code of the current or previous
// step and code2 the code of the step after code1, and returns code2's step.
// A device without a seed matches nothing. Codes compare in constant time.
func totpSequence(seed []byte, code1, code2 string, now time.Time) (int64, bool) {
	if len(seed) == 0 {
		return 0, false
	}
	cur := now.Unix() / int64(totpPeriod/time.Second)
	for first := cur - 1; first <= cur; first++ {
		if equalCode(totpAt(seed, first), code1) && equalCode(totpAt(seed, first+1), code2) {
			return first + 1, true
		}
	}
	return 0, false
}

// totpStep reports whether code is the code of the current or previous step
// and returns that step. A device without a seed matches nothing.
func totpStep(seed []byte, code string, now time.Time) (int64, bool) {
	if len(seed) == 0 {
		return 0, false
	}
	cur := now.Unix() / int64(totpPeriod/time.Second)
	for step := cur; step >= cur-1; step-- {
		if equalCode(totpAt(seed, step), code) {
			return step, true
		}
	}
	return 0, false
}

func equalCode(want, got string) bool {
	return subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1
}
