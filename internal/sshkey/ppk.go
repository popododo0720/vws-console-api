package sshkey

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // PPK v2 MACs are HMAC-SHA-1
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

// PPK returns the key as an unencrypted PuTTY-User-Key-File-2, the format
// EC2 returns for KeyFormat=ppk.
func (p Pair) PPK(comment string) string {
	var out strings.Builder
	out.WriteString("PuTTY-User-Key-File-2: " + p.algo + "\n")
	out.WriteString("Encryption: none\n")
	out.WriteString("Comment: " + comment + "\n")
	writeLines(&out, "Public-Lines", p.blob)
	writeLines(&out, "Private-Lines", p.ppkPrivate)
	out.WriteString("Private-MAC: " + ppkMAC(p.algo, "none", comment, p.blob, p.ppkPrivate) + "\n")
	return out.String()
}

func writeLines(out *strings.Builder, header, data string) {
	b64 := base64.StdEncoding.EncodeToString([]byte(data))
	var lines []string
	for len(b64) > 64 {
		lines = append(lines, b64[:64])
		b64 = b64[64:]
	}
	lines = append(lines, b64)
	out.WriteString(header + ": " + strconv.Itoa(len(lines)) + "\n" + strings.Join(lines, "\n") + "\n")
}

func ppkMAC(algo, enc, comment, public, private string) string {
	key := sha1.Sum([]byte("putty-private-key-file-mac-key")) //nolint:gosec // PPK v2
	m := hmac.New(sha1.New, key[:])
	m.Write([]byte(sshString(algo) + sshString(enc) + sshString(comment) + sshString(public) + sshString(private)))
	return hex.EncodeToString(m.Sum(nil))
}

// VerifyPPK checks the MAC of an unencrypted PPK v2 file.
func VerifyPPK(text string) error {
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	val := func(i int, key string) (string, error) {
		if i >= len(lines) || !strings.HasPrefix(lines[i], key+": ") {
			return "", errors.New("ppk: want " + key)
		}
		return strings.TrimPrefix(lines[i], key+": "), nil
	}
	block := func(i int, key string) (string, int, error) {
		v, err := val(i, key)
		if err != nil {
			return "", 0, err
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || i+1+n > len(lines) {
			return "", 0, errors.New("ppk: bad " + key)
		}
		b, err := base64.StdEncoding.DecodeString(strings.Join(lines[i+1:i+1+n], ""))
		if err != nil {
			return "", 0, errors.New("ppk: bad base64 in " + key)
		}
		return string(b), i + 1 + n, nil
	}
	algo, err := val(0, "PuTTY-User-Key-File-2")
	if err != nil {
		return err
	}
	enc, err := val(1, "Encryption")
	if err != nil || enc != "none" {
		return errors.New("ppk: want Encryption: none")
	}
	comment, err := val(2, "Comment")
	if err != nil {
		return err
	}
	pub, next, err := block(3, "Public-Lines")
	if err != nil {
		return err
	}
	priv, next, err := block(next, "Private-Lines")
	if err != nil {
		return err
	}
	mac, err := val(next, "Private-MAC")
	if err != nil {
		return err
	}
	if !hmac.Equal([]byte(mac), []byte(ppkMAC(algo, enc, comment, pub, priv))) {
		return errors.New("ppk: MAC mismatch")
	}
	return nil
}
