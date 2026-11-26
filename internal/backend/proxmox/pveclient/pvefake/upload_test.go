package pvefake_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
)

const (
	uploader     = "vws@pve!uploader"
	uploaderKey  = "00000000-0000-4000-8000-0000000000a1"
	spaceOnly    = "vws@pve!space"
	spaceOnlyKey = "00000000-0000-4000-8000-0000000000a2"
)

// uploadWorld has the storage seed (iso) on both nodes and images (no iso)
// on pve1; the uploader token may allocate templates on both.
func uploadWorld(t *testing.T) (*pvefake.Fake, *httptest.Server) {
	t.Helper()
	s := scenario(t)
	s.Roles = append(s.Roles,
		pvefake.Role{ID: "SeedUploader", Privs: []string{"Datastore.AllocateTemplate", "Datastore.Audit"}},
		pvefake.Role{ID: "SpaceOnly", Privs: []string{"Datastore.AllocateSpace", "Datastore.Audit"}},
	)
	s.Storages = append(s.Storages,
		pvefake.Storage{Node: "pve1", Name: "seed", Types: "iso,vztmpl"},
		pvefake.Storage{Node: "pve2", Name: "seed", Types: "iso,vztmpl"},
		pvefake.Storage{Node: "pve1", Name: "images", Types: "images,rootdir"},
	)
	s.Tokens = append(s.Tokens,
		pvefake.Token{ID: uploader, Secret: uploaderKey, ACL: []pvefake.ACE{
			{Path: "/storage/seed", Role: "SeedUploader"}, {Path: "/storage/images", Role: "SeedUploader"},
		}},
		pvefake.Token{ID: spaceOnly, Secret: spaceOnlyKey, ACL: []pvefake.ACE{{Path: "/storage", Role: "SpaceOnly"}}},
	)
	return start(t, s)
}

// UploadISO sends the bytes, PVE's task stores exactly those bytes on the
// node named, and the task belongs to the node that answered.
func TestUploadISOStoresTheExactBytes(t *testing.T) {
	f, srv := uploadWorld(t)
	c := client(t, srv, uploader, uploaderKey)
	iso := bytes.Repeat([]byte("CD001\x00seed"), 4096)
	task, err := c.UploadISO(t.Context(), "pve2", "seed", "vws-seed-3f9a1c0b7d2e-105.iso", iso)
	if err != nil {
		t.Fatal(err)
	}
	if task.Node != "pve1" || !strings.HasPrefix(task.UPID, "UPID:pve1:") || !strings.Contains(task.UPID, ":imgcopy:") {
		t.Fatalf("task = %+v, want the imgcopy task of the node that answered", task)
	}
	if err := c.WaitTask(t.Context(), task, pveclient.UploadWait); err != nil {
		t.Fatal(err)
	}
	if got := f.Uploaded("pve2", "seed", "vws-seed-3f9a1c0b7d2e-105.iso"); !bytes.Equal(got, iso) {
		t.Fatalf("stored %d bytes, want the %d sent", len(got), len(iso))
	}
	if f.Uploaded("pve1", "seed", "vws-seed-3f9a1c0b7d2e-105.iso") != nil {
		t.Fatal("the upload landed on the node that answered")
	}

	// A second upload of the name replaces the file.
	again := []byte("second image")
	task, err = c.UploadISO(t.Context(), "pve2", "seed", "vws-seed-3f9a1c0b7d2e-105.iso", again)
	if err == nil {
		err = c.WaitTask(t.Context(), task, pveclient.UploadWait)
	}
	if err != nil || !bytes.Equal(f.Uploaded("pve2", "seed", "vws-seed-3f9a1c0b7d2e-105.iso"), again) {
		t.Fatalf("replacing upload: %v", err)
	}
	content, err := c.StorageContent(t.Context(), "pve2", "seed")
	if err != nil || len(content) != 1 || content[0].VolID != "seed:iso/vws-seed-3f9a1c0b7d2e-105.iso" ||
		content[0].Size != int64(len(again)) {
		t.Fatalf("storage content = %+v %v", content, err)
	}
	rows, err := c.ClusterResources(t.Context(), pveclient.ResourceStorage)
	if err != nil || len(rows) == 0 {
		t.Fatal(rows, err)
	}
	for _, row := range rows {
		if row.Storage == "seed" && row.Content != "iso,vztmpl" {
			t.Fatalf("cluster resources content = %q", row.Content)
		}
	}
}

// The fake refuses what PVE refuses, and a failed upload stores nothing.
func TestUploadRefusals(t *testing.T) {
	f, srv := uploadWorld(t)
	c := client(t, srv, uploader, uploaderKey)
	if _, err := client(t, srv, spaceOnly, spaceOnlyKey).UploadISO(
		t.Context(), "pve1", "seed", "a.iso", []byte("x")); status(err) != http.StatusForbidden {
		t.Fatalf("without Datastore.AllocateTemplate: %v", err)
	}
	if _, err := c.UploadISO(t.Context(), "pve1", "images", "a.iso", []byte("x")); status(err) != http.StatusBadRequest {
		t.Fatalf("storage without iso content: %v", err)
	}

	raw := func(parts [][3]string) (int, string) {
		t.Helper()
		var body bytes.Buffer
		form := multipart.NewWriter(&body)
		for _, p := range parts {
			var w interface{ Write([]byte) (int, error) }
			var err error
			if p[0] == "filename" {
				w, err = form.CreateFormFile("filename", p[1])
			} else {
				w, err = form.CreateFormField(p[0])
			}
			if err == nil {
				_, err = w.Write([]byte(p[2]))
			}
			if err != nil {
				t.Fatal(err)
			}
		}
		if err := form.Close(); err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
			srv.URL+"/api2/json/nodes/pve1/storage/seed/upload", &body)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", form.FormDataContentType())
		req.Header.Set("Authorization", "PVEAPIToken="+uploader+"="+uploaderKey)
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var env struct{ Data string }
		if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, env.Data
	}
	const zeros = "0000000000000000000000000000000000000000000000000000000000000000"
	code, upid := raw([][3]string{
		{"content", "", "iso"},
		{"checksum-algorithm", "", "sha256"},
		{"checksum", "", zeros},
		{"filename", "bad.iso", "data"},
	})
	if code != http.StatusOK {
		t.Fatal(code)
	}
	var exit *pveclient.TaskError
	err := c.WaitTask(t.Context(), pveclient.Task{Node: "pve1", UPID: upid}, pveclient.UploadWait)
	if !errors.As(err, &exit) || !strings.HasPrefix(exit.ExitStatus, "checksum mismatch") ||
		f.Uploaded("pve1", "seed", "bad.iso") != nil {
		t.Fatalf("a wrong checksum: %v", err)
	}
	if code, _ := raw([][3]string{{"filename", "late.iso", "data"}, {"content", "", "iso"}}); code != 400 {
		t.Fatalf("a field after the file: %d", code)
	}
	if code, _ := raw([][3]string{{"content", "", "iso"}, {"filename", "image.qcow2", "data"}}); code != 400 {
		t.Fatalf("a name PVE refuses: %d", code)
	}
	// PVE rewrites a character outside [-\w.] to an underscore.
	code, upid = raw([][3]string{{"content", "", "iso"}, {"filename", "a b.iso", "data"}})
	err = c.WaitTask(t.Context(), pveclient.Task{Node: "pve1", UPID: upid}, pveclient.UploadWait)
	if code != http.StatusOK || err != nil || string(f.Uploaded("pve1", "seed", "a_b.iso")) != "data" {
		t.Fatalf("a rewritten name: %d %v", code, err)
	}

	// The client refuses a name PVE would rewrite and an empty image, and
	// sends nothing for them.
	before := len(f.Requests())
	for _, name := range []string{"", "a b.iso", "../a.iso", "a.img", "a.ISO", strings.Repeat("a", 252) + ".iso"} {
		if _, err := c.UploadISO(t.Context(), "pve1", "seed", name, []byte("x")); err == nil {
			t.Errorf("name %q was accepted", name)
		}
	}
	if _, err := c.UploadISO(t.Context(), "pve1", "seed", "empty.iso", nil); err == nil {
		t.Error("an empty image was accepted")
	}
	if _, err := c.UploadISO(t.Context(), "pve1", "../seed", "a.iso", []byte("x")); err == nil {
		t.Error("a storage outside one path segment was accepted")
	}
	if len(f.Requests()) != before {
		t.Fatalf("refused uploads reached PVE: %v", f.Requests()[before:])
	}
}
