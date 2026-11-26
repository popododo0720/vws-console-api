package pveclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// UploadWait bounds one imgcopy task.
const UploadWait = 60 * time.Second

// UploadISO stores content as <storage>:iso/<filename> on node and returns
// the import task. PVE overwrites a file of the same name.
//
// The request is POST /nodes/{node}/storage/{storage}/upload, a multipart
// form with the text fields first and the file last, because pveproxy reads
// the fields before it streams the file: content=iso,
// checksum-algorithm=sha256, checksum=<hex of content>, then the file part
// named "filename". The task checks the checksum.
//
// The body is replayed only when no connection was obtained, as for every
// write; after that the caller uploads again on its next pass, under the same
// name, so a repeat is harmless.
//
// PVE does not proxy this call: the task runs on the node that answered and
// copies the file to node itself. Task.Node is therefore the node of the
// UPID, not the node argument.
//
// filename must match [A-Za-z0-9_.-]+\.iso and be at most 255 bytes; PVE
// would rewrite any other name.
func (c *Client) UploadISO(ctx context.Context, node, storage, filename string, content []byte) (Task, error) {
	n, err := segment("node", node)
	if err != nil {
		return Task{}, err
	}
	s, err := segment("storage", storage)
	if err != nil {
		return Task{}, err
	}
	if len(filename) > 255 || !regexp.MustCompile(`^[A-Za-z0-9_.-]+\.iso$`).MatchString(filename) {
		return Task{}, fmt.Errorf("pveclient: invalid ISO file name %q", filename)
	}
	if len(content) == 0 {
		return Task{}, errors.New("pveclient: empty ISO")
	}
	sum := sha256.Sum256(content)
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	for _, field := range [][2]string{
		{"content", "iso"}, {"checksum-algorithm", "sha256"}, {"checksum", hex.EncodeToString(sum[:])},
	} {
		if err := form.WriteField(field[0], field[1]); err != nil {
			return Task{}, fmt.Errorf("pveclient: upload form: %w", err)
		}
	}
	file, err := form.CreateFormFile("filename", filename)
	if err == nil {
		_, err = file.Write(content)
	}
	if err == nil {
		err = form.Close()
	}
	if err != nil {
		return Task{}, fmt.Errorf("pveclient: upload form: %w", err)
	}
	var upid string
	path := "/nodes" + n + "/storage" + s + "/upload"
	err = c.write(ctx, http.MethodPost, path, form.FormDataContentType(), bytes.NewReader(body.Bytes()), &upid)
	if err != nil {
		return Task{}, err
	}
	parts := strings.Split(upid, ":")
	if len(parts) < 3 || parts[0] != "UPID" || parts[1] == "" {
		return Task{}, fmt.Errorf("pveclient: invalid upload UPID %q", upid)
	}
	return Task{Node: parts[1], UPID: upid}, nil
}
