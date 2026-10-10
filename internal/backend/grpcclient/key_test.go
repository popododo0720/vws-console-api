package grpcclient

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestKeySeedIsNotThePublishedID(t *testing.T) {
	const mutation = "mutation-key"
	if _, _, _, err := derivedKey(mutation, "key-seed"); err != nil {
		t.Fatal(err)
	}
	sum := hashParts(mutation, "key-seed")
	seed := hex.EncodeToString(sum[:])
	published := strings.TrimPrefix(derivedID("key-", mutation, "key"), "key-")
	if strings.HasPrefix(seed, published) {
		t.Fatal("key id is a prefix of the private-key seed")
	}
	requestID := strings.ReplaceAll(requestUUID(mutation, "key"), "-", "")
	if strings.HasPrefix(seed, requestID[:12]) {
		t.Fatal("request id shares the private-key seed")
	}
}
