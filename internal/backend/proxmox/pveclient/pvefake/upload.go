package pvefake

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"
)

// maxUpload bounds one uploaded file; a seed image is far smaller.
const maxUpload = 16 << 20

// Uploaded returns the bytes of the last successful upload of filename to
// storage on node, or nil. A shared storage keeps an upload under the node
// it was sent to.
func (f *Fake) Uploaded(node, storage, filename string) []byte {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return slices.Clone(f.uploads[node+"/"+storage+"/"+filename])
}

// upload is POST /nodes/{node}/storage/{storage}/upload for content=iso, as
// PVE serves it: Datastore.AllocateTemplate on the storage, the text fields
// before the file part, the name rewritten to [-\w.] characters, and an
// imgcopy task on the node that answered, the first node, that checks the
// checksum and then replaces the file.
func (f *Fake) upload(t *Token, r *http.Request) (any, *failure) {
	node, fail := f.node(r)
	if fail != nil {
		return nil, fail
	}
	name := r.PathValue("storage")
	if fail := f.need(t, "/storage/"+name, "Datastore.AllocateTemplate"); fail != nil {
		return nil, fail
	}
	fields, filename, data, fail := uploadForm(r)
	if fail != nil {
		return nil, fail
	}
	if fields["content"] != "iso" {
		return nil, parameter("content", "only iso uploads are modeled")
	}
	algorithm, checksum := fields["checksum-algorithm"], fields["checksum"]
	if (algorithm == "") != (checksum == "") || algorithm != "" && algorithm != "sha256" {
		return nil, parameter("checksum-algorithm", "only sha256 is modeled, with a checksum")
	}
	filename = regexp.MustCompile(`[^-\w.]`).ReplaceAllString(filename, "_")
	if !regexp.MustCompile(`(?i)^[^/]+\.(iso|img)$`).MatchString(filename) {
		return nil, parameter("filename", "wrong file extension")
	}
	storage := f.storage(node, name)
	if storage == nil {
		return nil, &failure{http.StatusInternalServerError, fmt.Sprintf("storage '%s' does not exist", name)}
	}
	if !slices.Contains(strings.Split(storage.Types, ","), "iso") {
		return nil, &failure{
			http.StatusBadRequest, fmt.Sprintf("storage '%s' does not support 'iso' content", name),
		}
	}
	volid := name + ":iso/" + filename
	key := node + "/" + name + "/" + filename
	return f.submit(t, f.s.Nodes[0].Name, "imgcopy", "", func() string {
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); checksum != "" && got != strings.ToLower(checksum) {
			return fmt.Sprintf("checksum mismatch: got '%s' != expect '%s'", got, checksum)
		}
		storage := f.storage(node, name)
		if storage == nil {
			return "storage does not exist"
		}
		storage.Content = slices.DeleteFunc(storage.Content, func(c StorageContent) bool { return c.VolID == volid })
		storage.Content = append(storage.Content, StorageContent{
			VolID: volid, Content: "iso", Format: "iso", Size: int64(len(data)),
		})
		f.uploads[key] = data
		return "OK"
	}), nil
}

// uploadForm reads the multipart body: each of content, checksum and
// checksum-algorithm at most once and before the one file part, "filename".
func uploadForm(r *http.Request) (map[string]string, string, []byte, *failure) {
	reader, err := r.MultipartReader()
	if err != nil {
		return nil, "", nil, parameter("body", "expected multipart/form-data")
	}
	fields := map[string]string{}
	for {
		part, err := reader.NextPart()
		if errors.Is(err, io.EOF) {
			return nil, "", nil, parameter("filename", "property is missing and it is not optional")
		}
		if err != nil {
			return nil, "", nil, parameter("body", "unable to parse multipart form")
		}
		key := part.FormName()
		if key == "filename" {
			data, err := io.ReadAll(io.LimitReader(part, maxUpload+1))
			if err != nil || len(data) > maxUpload || part.FileName() == "" {
				return nil, "", nil, parameter("filename", "unreadable, oversized or unnamed file")
			}
			if next, err := reader.NextPart(); !errors.Is(err, io.EOF) || next != nil {
				return nil, "", nil, parameter("body", "the file must be the last part")
			}
			return fields, part.FileName(), data, nil
		}
		value, err := io.ReadAll(io.LimitReader(part, 1024))
		if _, seen := fields[key]; seen || err != nil ||
			!slices.Contains([]string{"content", "checksum", "checksum-algorithm"}, key) {
			return nil, "", nil, parameter(key, "unknown or repeated parameter")
		}
		fields[key] = string(value)
	}
}
