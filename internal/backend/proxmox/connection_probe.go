package proxmox

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"regexp"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// maxProbePools bounds the managed pools one connection test reads.
const maxProbePools = 256

var probePool = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// probeRequest is the candidate registration an operator wants checked. It
// carries the same fields and passes the same validation as a registration;
// pools are the managed pools of this region.
type probeRequest struct {
	Region string `json:"region"`
	//nolint:tagliatelle // The registration protocol names cluster_name.
	ClusterName string   `json:"cluster_name"`
	PVEAPIURLs  []string `json:"pveApiUrls"`
	CAPEM       string   `json:"caPem"`
	TokenID     string   `json:"tokenId"`
	Token       string   `json:"token"`
	Pools       []string `json:"pools"`
}

func decodeProbe(data []byte, region string) (probeRequest, error) {
	var r probeRequest
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return r, resource.Invalid("connection test", "invalid JSON")
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return r, resource.Invalid("connection test", "expected one JSON document")
	}
	if r.Region != region {
		return r, resource.Invalid("region", "connection test is for another region than this instance")
	}
	if !registrationCluster.MatchString(r.ClusterName) || !registrationTokenID.MatchString(r.TokenID) {
		return r, resource.Invalid("connection test", "invalid cluster_name or tokenId")
	}
	if !registrationSecret.MatchString(r.Token) {
		return r, resource.Invalid("token", "expected 1-512 token characters")
	}
	if err := resource.CheckPVEAPIURLs(r.PVEAPIURLs); err != nil {
		return r, err
	}
	if !x509.NewCertPool().AppendCertsFromPEM([]byte(r.CAPEM)) {
		return r, resource.Invalid("caPem", "expected the PEM certificates that sign the PVE nodes")
	}
	if len(r.Pools) > maxProbePools {
		return r, resource.Invalid("pools", "too many pools")
	}
	for _, pool := range r.Pools {
		if !probePool.MatchString(pool) {
			return r, resource.Invalid("pools", "invalid pool id")
		}
	}
	return r, nil
}

// TestConnection runs the four PVE checks for a candidate registration. It
// reads and writes no state, takes no registration lock and never touches
// the live registration or the quorum gate; the token lives only in this call.
// It dials nothing but the addresses in the request, which passed the
// registration checks (HTTPS origins only) and answer only to the request's CA.
func (c *Connection) TestConnection(ctx context.Context, data json.RawMessage) ([]resource.ConnectionStep, error) {
	r, err := decodeProbe(data, c.region)
	if err != nil {
		return nil, err
	}
	return TestConnection(ctx, ConnectionConfig{
		URLs: r.PVEAPIURLs, CAPEM: r.CAPEM, ClusterName: r.ClusterName, TokenID: r.TokenID,
		TokenSecret: r.Token, Pools: r.Pools, dial: c.dialPVE,
	}), nil
}
