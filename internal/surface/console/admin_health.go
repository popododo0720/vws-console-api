package console

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"regexp"
	"syscall"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// RegionMTLSConfigError keeps credential-loading details off the health response.
type RegionMTLSConfigError struct{ Err error }

func (*RegionMTLSConfigError) Error() string { return "region mTLS configuration failed" }

// Unwrap preserves the cause for safe server-side classification.
func (e *RegionMTLSConfigError) Unwrap() error { return e.Err }

func (h *handler) adminHealth(w http.ResponseWriter, r *http.Request) {
	if !h.adminReady(w, r) {
		return
	}
	name := r.PathValue("name")
	if !regexp.MustCompile(`^pve-[a-z0-9]+(-[a-z0-9]+)*-[0-9]+$`).MatchString(name) || len(name) > 63 {
		writeErr(w, r, resource.Invalid("name", "invalid Proxmox region name"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	region, err := h.registry.Regions().Get(ctx, name)
	if err != nil {
		adminError(w, r, err)
		return
	}
	if h.regionStatus == nil {
		writeErr(w, r, &resource.Error{Code: resource.CodeUnavailable, Message: "region status transport unavailable"})
		return
	}
	status, err := h.regionStatus(ctx, region.RegionEndpoint)
	state := "ok"
	if err != nil {
		state = "unreachable"
		message := h.regionFailure(r.Context(), err)
		status = resource.RegionStatus{
			Nodes:     []resource.RegionNode{},
			LastError: &resource.RegionStatusError{Time: h.now().UTC(), Message: message},
		}
	}
	writeJSON(w, http.StatusOK, struct {
		resource.RegionStatus
		Status    string    `json:"status"`
		CheckedAt time.Time `json:"checkedAt"`
	}{RegionStatus: status, Status: state, CheckedAt: h.now().UTC()})
}

func (h *handler) regionFailure(ctx context.Context, err error) string {
	message := "region transport failed"
	var config *RegionMTLSConfigError
	var network *net.OpError
	var errno syscall.Errno
	var certificate *tls.CertificateVerificationError
	var record tls.RecordHeaderError
	regional := resource.RegionFailureMessage(err)
	switch {
	case regional != "":
		message = regional
	case errors.As(err, &config):
		message = config.Error()
		reason := "invalid certificate or CA"
		if errors.Is(err, os.ErrNotExist) {
			reason = "credential file missing"
		} else if errors.Is(err, os.ErrPermission) {
			reason = "credential file permission denied"
		}
		h.log.WarnContext(ctx, "region mTLS configuration failed", slog.String("reason", reason))
	case errors.Is(err, context.DeadlineExceeded):
		message += ": deadline exceeded"
	case errors.Is(err, context.Canceled):
		message += ": request canceled"
	case errors.As(err, &certificate), errors.As(err, &record):
		message += ": TLS handshake failed"
	case errors.As(err, &network):
		switch network.Op {
		case "dial", "read", "write":
			message += ": " + network.Op
			if errors.As(network.Err, &errno) {
				message += ": " + errno.Error()
			}
		case "remote error":
			message += ": TLS handshake failed"
		}
	}
	return message
}
