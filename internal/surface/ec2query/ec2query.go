// Package ec2query serves a small EC2 Query entry point.
// Actions parse into the resource model and render EC2-shaped XML.
// The listener is dedicated to this protocol so the path does not have to be sniffed.
package ec2query

import (
	"encoding/xml"
	"net/http"
	"strconv"
	"strings"

	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

// Version is the query version this entry point accepts.
const Version = "2016-11-15"

// Config wires the query surface.
type Config struct {
	Service  *cloud.Service
	Verifier *sigv4.Verifier
}

// New returns the query handler.
func New(cfg Config) http.Handler {
	h := &handler{svc: cfg.Service, verifier: cfg.Verifier}
	return http.HandlerFunc(h.serve)
}

type handler struct {
	svc      *cloud.Service
	verifier *sigv4.Verifier
}

func (h *handler) serve(w http.ResponseWriter, r *http.Request) {
	if h.verifier == nil {
		writeErr(w, r, resource.Unauthenticated("missing signature"))
		return
	}
	caller, err := h.verifier.Verify(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	if err := r.ParseForm(); err != nil {
		writeErr(w, r, resource.Invalid("body", "malformed form"))
		return
	}
	if r.Form.Get("Version") != Version {
		writeErr(w, r, resource.Invalid("Version", "unsupported"))
		return
	}
	action := r.Form.Get("Action")
	if err := rejectUnknown(r, action); err != nil {
		writeErr(w, r, err)
		return
	}
	switch action {
	case resource.ActionRunInstances.String():
		h.runInstances(w, r, caller)
	case resource.ActionStopInstances.String():
		h.stopInstances(w, r, caller)
	case resource.ActionCreateSubnet.String():
		h.createSubnet(w, r, caller)
	case "DescribeInstances":
		h.describeInstances(w, r, caller)
	case "DescribeSubnets":
		h.describeSubnets(w, r, caller)
	default:
		writeErr(w, r, resource.Unimplemented(action))
	}
}

func (h *handler) runInstances(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	token, err := clientToken(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	img, err := resource.Parse[resource.ImageID](r.Form.Get("ImageId"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	sub, err := resource.Parse[resource.SubnetID](r.Form.Get("SubnetId"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	count, err := exactCount(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	tags, err := tags(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	acc, err := h.svc.RunInstances(r.Context(), c, token, resource.RunInstancesRequest{
		ImageID: img, InstanceType: r.Form.Get("InstanceType"), SubnetID: sub, Count: count, Tags: tags,
	})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeXML(w, runInstancesXML{
		RequestID: requestID(r), ReservationID: acc.Items[0].ReservationID.String(),
		Instances: instanceItems(acc.Items),
	})
}

func (h *handler) stopInstances(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	token, err := clientToken(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	ids, err := indexedIDs[resource.InstanceID](r, "InstanceId")
	if err != nil {
		writeErr(w, r, err)
		return
	}
	acc, err := h.svc.StopInstances(r.Context(), c, token, resource.StopInstancesRequest{IDs: ids})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	var items []stateItem
	for _, ch := range acc.Items {
		items = append(items, stateItem{
			InstanceID:    ch.ID.String(),
			CurrentState:  stateXMLOf(ch.Current),
			PreviousState: stateXMLOf(ch.Previous),
		})
	}
	writeXML(w, stopInstancesXML{RequestID: requestID(r), Instances: struct {
		Items []stateItem `xml:"item"`
	}{Items: items}})
}

func (h *handler) createSubnet(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	token, err := clientToken(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	acc, err := h.svc.CreateSubnet(r.Context(), c, token, resource.CreateSubnetRequest{Cidr: r.Form.Get("CidrBlock")})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	sub := acc.Items[0]
	writeXML(w, createSubnetXML{RequestID: requestID(r), Subnet: subnetXML(sub)})
}

func (h *handler) describeInstances(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	q, err := instanceQuery(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	page, err := h.svc.DescribeInstances(r.Context(), c, q)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	groups := map[string][]resource.Instance{}
	var order []string
	for _, inst := range page.Items {
		key := inst.ReservationID.String()
		if _, ok := groups[key]; !ok {
			order = append(order, key)
		}
		groups[key] = append(groups[key], inst)
	}
	var items []reservationItem
	for _, key := range order {
		items = append(items, reservationItem{ReservationID: key, Instances: instanceItems(groups[key])})
	}
	writeXML(w, describeInstancesXML{RequestID: requestID(r), NextToken: page.NextToken, Reservations: struct {
		Items []reservationItem `xml:"item"`
	}{Items: items}})
}

func (h *handler) describeSubnets(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	ids, err := indexedIDs[resource.SubnetID](r, "SubnetId")
	if err != nil {
		writeErr(w, r, err)
		return
	}
	pageReq, err := pageForm(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	page, err := h.svc.DescribeSubnets(r.Context(), c, resource.SubnetQuery{IDs: ids, Page: pageReq})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	var items []subnetItem
	for _, sub := range page.Items {
		items = append(items, subnetXML(sub))
	}
	writeXML(w, describeSubnetsXML{RequestID: requestID(r), NextToken: page.NextToken, Subnets: struct {
		Items []subnetItem `xml:"item"`
	}{Items: items}})
}

func clientToken(r *http.Request) (resource.ClientToken, error) {
	raw := r.Form.Get("ClientToken")
	if raw == "" {
		return resource.ClientToken{}, resource.Invalid("ClientToken", "ClientToken is required")
	}
	return resource.Parse[resource.ClientToken](raw)
}

func exactCount(r *http.Request) (int, error) {
	minRaw, maxRaw := r.Form.Get("MinCount"), r.Form.Get("MaxCount")
	if minRaw == "" && maxRaw == "" {
		return 1, nil
	}
	minC, err1 := strconv.Atoi(minRaw)
	maxC, err2 := strconv.Atoi(maxRaw)
	if err1 != nil || err2 != nil || minC != maxC || minC < 1 {
		return 0, resource.Invalid("MinCount", "MinCount and MaxCount must be equal")
	}
	return minC, nil
}

func tags(r *http.Request) (map[string]string, error) {
	out := map[string]string{}
	for i := 1; i <= 20; i++ {
		n := strconv.Itoa(i)
		k, v := r.Form.Get("Tag."+n+".Key"), r.Form.Get("Tag."+n+".Value")
		if k == "" && v == "" {
			continue
		}
		if k == "" {
			return nil, resource.Invalid("Tag."+n+".Key", "required")
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func instanceQuery(r *http.Request) (resource.InstanceQuery, error) {
	ids, err := indexedIDs[resource.InstanceID](r, "InstanceId")
	if err != nil {
		return resource.InstanceQuery{}, err
	}
	var states []resource.InstanceState
	for i := 1; i <= 20; i++ {
		name := r.Form.Get("Filter." + strconv.Itoa(i) + ".Name")
		if name == "" {
			continue
		}
		value := r.Form.Get("Filter." + strconv.Itoa(i) + ".Value.1")
		switch name {
		case "instance-id":
			id, err := resource.Parse[resource.InstanceID](value)
			if err != nil {
				return resource.InstanceQuery{}, err
			}
			ids = append(ids, id)
		case "instance-state-name":
			st, ok := resource.ParseInstanceState(value)
			if !ok {
				return resource.InstanceQuery{}, resource.Invalid("Filter", "unknown state")
			}
			states = append(states, st)
		default:
			return resource.InstanceQuery{}, resource.Invalid("Filter", "unsupported")
		}
	}
	page, err := pageForm(r)
	if err != nil {
		return resource.InstanceQuery{}, err
	}
	return resource.InstanceQuery{IDs: ids, States: states, Page: page}, nil
}

func pageForm(r *http.Request) (resource.PageRequest, error) {
	var p resource.PageRequest
	if raw := r.Form.Get("MaxResults"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			return p, resource.Invalid("MaxResults", "malformed")
		}
		p.Size = n
	}
	p.Token = r.Form.Get("NextToken")
	return p, nil
}

func indexedIDs[T any, PT interface {
	*T
	encodingText
}](r *http.Request, prefix string) ([]T, error) {
	var out []T
	for i := 1; i <= 100; i++ {
		raw := r.Form.Get(prefix + "." + strconv.Itoa(i))
		if raw == "" {
			continue
		}
		id, err := resource.Parse[T, PT](raw)
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, nil
}

type encodingText interface {
	UnmarshalText([]byte) error
}

func rejectUnknown(r *http.Request, action string) error {
	var allow func(string) bool
	switch action {
	case resource.ActionRunInstances.String():
		allow = allowRun
	case resource.ActionStopInstances.String():
		allow = allowStop
	case resource.ActionCreateSubnet.String():
		allow = allowSubnet
	case "DescribeInstances":
		allow = allowDescribeInstances
	case "DescribeSubnets":
		allow = allowDescribeSubnets
	default:
		allow = allowCommon
	}
	for key := range r.Form {
		if !allow(key) {
			return resource.Invalid(key, "unsupported")
		}
	}
	return nil
}

func allowCommon(key string) bool {
	return key == "Action" || key == "Version"
}

func allowRun(key string) bool {
	switch key {
	case "Action", "Version", "ImageId", "InstanceType", "SubnetId", "MinCount", "MaxCount", "ClientToken":
		return true
	default:
		return tagField(key)
	}
}

func allowStop(key string) bool {
	return key == "Action" || key == "Version" || key == "ClientToken" || indexed(key, "InstanceId", 100)
}

func allowSubnet(key string) bool {
	return key == "Action" || key == "Version" || key == "ClientToken" || key == "CidrBlock"
}

func allowDescribeInstances(key string) bool {
	return key == "Action" || key == "Version" || key == "MaxResults" || key == "NextToken" || indexed(key, "InstanceId", 100) || filterField(key)
}

func allowDescribeSubnets(key string) bool {
	return key == "Action" || key == "Version" || key == "MaxResults" || key == "NextToken" || indexed(key, "SubnetId", 100)
}

func tagField(key string) bool {
	rest, ok := strings.CutPrefix(key, "Tag.")
	if !ok {
		return false
	}
	n, field, ok := strings.Cut(rest, ".")
	if !ok || (field != "Key" && field != "Value") {
		return false
	}
	return inRange(n, 20)
}

func filterField(key string) bool {
	rest, ok := strings.CutPrefix(key, "Filter.")
	if !ok {
		return false
	}
	n, field, ok := strings.Cut(rest, ".")
	if !ok || !inRange(n, 20) {
		return false
	}
	return field == "Name" || field == "Value.1"
}

func indexed(key, prefix string, max int) bool {
	rest, ok := strings.CutPrefix(key, prefix+".")
	if !ok || strings.Contains(rest, ".") {
		return false
	}
	return inRange(rest, max)
}

func inRange(raw string, max int) bool {
	n, err := strconv.Atoi(raw)
	return err == nil && n >= 1 && n <= max
}

func requestID(r *http.Request) string { return r.Header.Get("X-Request-Id") }

func writeXML(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(xml.Header))
	enc := xml.NewEncoder(w)
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, r *http.Request, err error) {
	e := resource.AsError(err)
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.WriteHeader(statusOf(e.Code))
	_, _ = w.Write([]byte(xml.Header))
	_ = xml.NewEncoder(w).Encode(errorXML{
		Code: ec2Code(e), Message: e.Message, RequestID: requestID(r),
	})
}

func statusOf(c resource.Code) int {
	switch c {
	case resource.CodeUnauthenticated:
		return http.StatusUnauthorized
	case resource.CodePermissionDenied:
		return http.StatusForbidden
	case resource.CodeUnimplemented:
		return http.StatusNotImplemented
	case resource.CodeUnavailable:
		return http.StatusServiceUnavailable
	case resource.CodeInternal, resource.CodeUnspecified:
		return http.StatusInternalServerError
	case resource.CodeInvalidArgument, resource.CodeNotFound, resource.CodeAlreadyExists,
		resource.CodeConflict, resource.CodeIdempotencyMismatch, resource.CodeResourceExhausted,
		resource.CodePayloadTooLarge:
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}

func ec2Code(e *resource.Error) string {
	switch e.Code {
	case resource.CodeNotFound:
		return notFoundCode(e.Kind)
	case resource.CodeInvalidArgument:
		return "InvalidParameterValue"
	case resource.CodeAlreadyExists:
		return "InvalidParameterValue"
	case resource.CodeConflict:
		return "IncorrectInstanceState"
	case resource.CodeIdempotencyMismatch:
		return "IdempotentParameterMismatch"
	case resource.CodeUnauthenticated:
		return "AuthFailure"
	case resource.CodePermissionDenied:
		return "UnauthorizedOperation"
	case resource.CodeResourceExhausted:
		return "RequestLimitExceeded"
	case resource.CodePayloadTooLarge:
		return "InvalidParameterValue"
	case resource.CodeUnavailable:
		return "Unavailable"
	case resource.CodeUnimplemented:
		return "InvalidAction"
	case resource.CodeInternal, resource.CodeUnspecified:
		return "InternalError"
	default:
		return "InternalError"
	}
}

func notFoundCode(k resource.Kind) string {
	switch k {
	case resource.KindInstance:
		return "InvalidInstanceID.NotFound"
	case resource.KindSubnet:
		return "InvalidSubnetID.NotFound"
	case resource.KindImage:
		return "InvalidAMIID.NotFound"
	case resource.KindReservation, resource.KindBucket, resource.KindObject, resource.KindOperation, resource.KindUnspecified:
		return "InvalidParameterValue"
	default:
		return "InvalidParameterValue"
	}
}
