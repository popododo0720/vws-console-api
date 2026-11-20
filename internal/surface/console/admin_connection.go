package console

import (
	"context"
	"encoding/json"
	"mime"
	"net/http"
	"regexp"
	"time"

	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func (h *handler) adminTestAWSAccount(w http.ResponseWriter, r *http.Request) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		unsupportedMedia(w)
		return
	}
	if !h.adminReady(w, r) {
		return
	}
	if h.adminKey == nil || h.accountConnection == nil {
		writeErr(w, r, &resource.Error{Code: resource.CodeUnavailable, Message: "AWS connection test requires KEK and proxy"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	var v store.AWSAccount
	var external string
	id := r.PathValue("id")
	if id != "" {
		if !regexp.MustCompile(`^[0-9]{12}$`).MatchString(id) {
			writeErr(w, r, resource.Invalid("awsAccountId", "must be 12 digits"))
			return
		}
		var empty *struct{}
		if err := decode(w, r, &empty); err != nil || empty == nil {
			writeErr(w, r, resource.Invalid("body", "saved tests require an empty JSON object"))
			return
		}
		var err error
		v, err = h.registry.AWSAccounts().Get(ctx, id)
		if err != nil {
			adminError(w, r, err)
			return
		}
		plain, err := h.adminKey.Open(v.SealedExternalID, id)
		if err != nil {
			unusableSavedAccount(w)
			return
		}
		defer clear(plain)
		external = string(plain)
	} else {
		var in *accountInput
		if err := decode(w, r, &in); err != nil {
			if resource.CodeOf(err) != resource.CodePayloadTooLarge {
				err = resource.Invalid("body", "invalid AWS connection test body")
			}
			writeErr(w, r, err)
			return
		}
		if in == nil || in.ID == nil || in.RoleARN == nil || in.ExternalID == nil || in.AllowedRegions == nil {
			writeErr(w, r, resource.Invalid("body", "all AWS account fields are required"))
			return
		}
		v = store.AWSAccount{ID: *in.ID, RoleARN: *in.RoleARN, AllowedRegions: *in.AllowedRegions}
		external = *in.ExternalID
	}
	if err := validateAccount(v, &external, true); err != nil {
		if id != "" {
			unusableSavedAccount(w)
			return
		}
		writeErr(w, r, err)
		return
	}
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	steps := h.accountConnection(ctx, resource.AWSConnectionRequest{
		AccountID: v.ID, RoleARN: v.RoleARN, ExternalID: external,
	}, c.Principal)
	writeJSON(w, http.StatusOK, struct {
		Steps []resource.ConnectionStep `json:"steps"`
	}{steps})
}

func unusableSavedAccount(w http.ResponseWriter) {
	steps := resource.AWSConnectionSteps(false, false)
	steps[0].Message = "saved registration cannot be used; save it again"
	writeJSON(w, http.StatusOK, struct {
		Steps []resource.ConnectionStep `json:"steps"`
	}{steps})
}

func (h *handler) adminTestRegion(w http.ResponseWriter, r *http.Request) {
	if !h.adminReady(w, r) {
		return
	}
	if h.adminKey == nil {
		writeErr(w, r, &resource.Error{Code: resource.CodeUnavailable, Message: "admin tests require credentials.kek_file"})
		return
	}
	var v store.Region
	name := r.PathValue("name")
	if name != "" {
		if !validRegionName(name) {
			writeErr(w, r, resource.Invalid("name", "invalid Proxmox region name"))
			return
		}
		var err error
		v, err = h.registry.Regions().Get(r.Context(), name)
		if err != nil {
			adminError(w, r, err)
			return
		}
	}
	var in *regionInput
	if err := decode(w, r, &in); err != nil {
		writeErr(w, r, err)
		return
	}
	if in == nil {
		writeErr(w, r, resource.Invalid("body", "expected one JSON object"))
		return
	}
	if name != "" {
		if in.Name != nil || in.ClusterName != nil || in.PVEAPIURLs != nil || in.CAPEM != nil ||
			in.TokenID != nil || in.RegionEndpoint != nil || in.Zones != nil {
			writeErr(w, r, resource.Invalid("name", "saved tests accept only tokenSecret; use the unsaved test for edits"))
			return
		}
	} else {
		for _, field := range []struct{ from, to *string }{
			{in.Name, &v.Name},
			{in.ClusterName, &v.ClusterName},
			{in.CAPEM, &v.CAPEM},
			{in.TokenID, &v.TokenID},
			{in.RegionEndpoint, &v.RegionEndpoint},
		} {
			if field.from != nil {
				*field.to = *field.from
			}
		}
		if in.PVEAPIURLs != nil {
			v.PVEAPIURLs = *in.PVEAPIURLs
		}
		if in.Zones != nil {
			v.Zones = *in.Zones
		}
	}
	if err := validateRegion(v, in.TokenSecret, name == ""); err != nil {
		writeErr(w, r, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	steps := make([]resource.ConnectionStep, 0, 5)
	if in.TokenSecret == nil {
		for _, step := range []string{"tls", "version", "cluster_name", "privileges"} {
			steps = append(steps, resource.ConnectionStep{
				Name: step, Result: resource.ConnectionSkipped, Message: "tokenSecret is needed; only the region daemon stores it",
			})
		}
	} else {
		if h.regionConnection == nil {
			writeErr(w, r, &resource.Error{Code: resource.CodeUnavailable, Message: "PVE connection test unavailable"})
			return
		}
		steps = h.testPVE(ctx, v, *in.TokenSecret)
	}
	last := resource.ConnectionStep{Name: "regionapi", Result: resource.ConnectionSkipped, Message: "previous step failed"}
	failed := false
	for _, step := range steps {
		failed = failed || step.Result == resource.ConnectionFail
	}
	if !failed {
		last.Result, last.Message = resource.ConnectionFail, "region status transport unavailable"
		if h.regionStatus != nil {
			if _, err := h.regionStatus(ctx, v.RegionEndpoint); err != nil {
				last.Message = h.regionFailure(ctx, err)
			} else {
				last.Result, last.Message = resource.ConnectionPass, "regionapi mTLS status read succeeded"
			}
		}
	}
	writeJSON(w, http.StatusOK, struct {
		Steps []resource.ConnectionStep `json:"steps"`
	}{Steps: append(steps, last)})
}

// testPVE has the region daemon run the PVE checks. console-api opens no
// connection to a PVE address; it sends the candidate registration, the token
// and the managed pools of the region over the authenticated regionapi channel.
// A daemon that cannot be reached or answers badly fails the first step with a
// fixed diagnostic, since no PVE check ran.
func (h *handler) testPVE(ctx context.Context, v store.Region, token string) []resource.ConnectionStep {
	failed := func(name, message string) []resource.ConnectionStep {
		steps := make([]resource.ConnectionStep, 0, len(resource.PVEConnectionStepNames()))
		for _, step := range resource.PVEConnectionStepNames() {
			result, text := resource.ConnectionSkipped, "previous step failed"
			if step == name {
				result, text = resource.ConnectionFail, message
			}
			steps = append(steps, resource.ConnectionStep{Name: step, Result: result, Message: text})
		}
		return steps
	}
	projects, skipped, err := h.registry.Projects().List(ctx)
	if err != nil || len(skipped) != 0 {
		steps := failed("privileges", "managed project pools could not be read")
		for i := range steps[:3] {
			steps[i].Message = "managed project pools could not be read"
		}
		return steps
	}
	pools := []string{}
	for _, project := range projects {
		for _, binding := range project.Pools {
			if binding.Region == v.Name {
				pools = append(pools, binding.Pool)
			}
		}
	}
	data, err := json.Marshal(struct {
		Region string `json:"region"`
		//nolint:tagliatelle // The daemon protocol names cluster_name.
		ClusterName string   `json:"cluster_name"`
		PVEAPIURLs  []string `json:"pveApiUrls"`
		CAPEM       string   `json:"caPem"`
		TokenID     string   `json:"tokenId"`
		Token       string   `json:"token"`
		Pools       []string `json:"pools"`
	}{v.Name, v.ClusterName, v.PVEAPIURLs, v.CAPEM, v.TokenID, token, pools})
	if err != nil {
		return failed("tls", "region daemon request could not be built")
	}
	steps, err := h.regionConnection(ctx, v.RegionEndpoint, data)
	if err != nil {
		if e := resource.AsError(err); e.Code == resource.CodeInvalidArgument {
			return failed("tls", "region daemon refused the test request")
		}
		return failed("tls", "PVE checks run in the region daemon, which did not answer: "+h.regionFailure(ctx, err))
	}
	return steps
}
