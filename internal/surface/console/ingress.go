package console

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func readIngressBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return nil, resource.TooLarge("body exceeds the limit")
		}
		return nil, resource.Invalid("body", "malformed json")
	}
	return body, nil
}

func expandIngressPermissions(body []byte) ([]resource.IngressChange, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var raw ingressBody
	if err := dec.Decode(&raw); err != nil {
		return nil, resource.MalformedPermission("body", "malformed json")
	}
	if len(raw.Permissions) == 0 {
		return nil, resource.MalformedPermission("ipPermissions", "required")
	}
	var out []resource.IngressChange
	for i, perm := range raw.Permissions {
		base := fmt.Sprintf("ipPermissions[%d]", i)
		if len(perm.Prefixes) > 0 {
			if !prefixListsWellFormed(perm.Prefixes) {
				return nil, resource.MalformedPrefixList(base + ".prefixListIds")
			}
			return nil, resource.UnsupportedIngress(base + ".prefixListIds")
		}
		if len(perm.IPv6) > 0 {
			return nil, resource.UnsupportedIngress(base + ".ipv6Ranges")
		}
		if len(perm.Pairs) > 0 {
			return nil, resource.UnsupportedIngress(base + ".userIdGroupPairs")
		}
		if len(perm.Ranges) == 0 {
			return nil, resource.MalformedPermission(base+".ipRanges", "required")
		}
		from, to, missing := perm.ports()
		if missing != "" {
			return nil, resource.MissingIngressPorts(base + "." + missing)
		}
		for j, rg := range perm.Ranges {
			path := fmt.Sprintf("%s.ipRanges[%d]", base, j)
			if rg.Description != "" {
				return nil, resource.RejectedDescription(path + ".description")
			}
			out = append(out, resource.IngressChange{
				IngressRule: resource.IngressRule{
					Protocol: perm.Protocol, FromPort: from, ToPort: to, Cidr: rg.Cidr,
				},
				Path: path,
				Perm: base,
			})
		}
	}
	return out, nil
}

type ingressBody struct {
	Permissions []ingressPermission `json:"ipPermissions"`
}

type ingressPermission struct {
	Protocol string         `json:"ipProtocol"`
	FromPort *int           `json:"fromPort"`
	ToPort   *int           `json:"toPort"`
	Ranges   []ingressRange `json:"ipRanges"`
	IPv6     []ipv6Range    `json:"ipv6Ranges"`
	Pairs    []groupPair    `json:"userIdGroupPairs"`
	Prefixes []prefixRef    `json:"prefixListIds"`
}

func (p ingressPermission) ports() (from, to int, missing string) {
	if !tcpOrUDP(p.Protocol) {
		if p.FromPort != nil {
			from = *p.FromPort
		}
		if p.ToPort != nil {
			to = *p.ToPort
		}
		return from, to, ""
	}
	if p.FromPort == nil {
		return 0, 0, "fromPort"
	}
	if p.ToPort == nil {
		return 0, 0, "toPort"
	}
	return *p.FromPort, *p.ToPort, ""
}

func tcpOrUDP(protocol string) bool {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "tcp", "6", "udp", "17":
		return true
	default:
		return false
	}
}

func prefixListsWellFormed(refs []prefixRef) bool {
	for _, ref := range refs {
		hexID, ok := strings.CutPrefix(ref.ID, "pl-")
		if !ok || len(hexID) < 8 || len(hexID) > 17 {
			return false
		}
		for _, c := range hexID {
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return false
			}
		}
	}
	return true
}

type ingressRange struct {
	Cidr        string `json:"cidrIp"`
	Description string `json:"description,omitempty"`
}

type ipv6Range struct {
	Cidr        string `json:"cidrIpv6"`
	Description string `json:"description,omitempty"`
}

type groupPair struct {
	GroupID       string `json:"groupId,omitempty"`
	GroupName     string `json:"groupName,omitempty"`
	UserID        string `json:"userId,omitempty"`
	Description   string `json:"description,omitempty"`
	VpcID         string `json:"vpcId,omitempty"`
	PeeringID     string `json:"vpcPeeringConnectionId,omitempty"`
	PeeringStatus string `json:"peeringStatus,omitempty"`
}

type prefixRef struct {
	ID          string `json:"prefixListId"`
	Description string `json:"description,omitempty"`
}
