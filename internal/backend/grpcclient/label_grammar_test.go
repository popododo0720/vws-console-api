package grpcclient

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"
)

// labelGrammar is the envelope label rule in vws/common/v1/resource.proto:
// at most 64 entries, keys [a-z][a-z0-9_-]{0,62}, values 0 to 63 bytes of
// UTF-8 with no ASCII control characters.
var labelGrammar = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)

// enforceLabelGrammar refuses a request that carries a label the resource API
// would refuse, so the loopback cannot accept what vws-compute drops (#93).
func enforceLabelGrammar(
	ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
) (any, error) {
	if msg, ok := req.(proto.Message); ok {
		if err := labelsBreakGrammar(msg.ProtoReflect()); err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
	}
	return handler(ctx, req)
}

func labelsBreakGrammar(m protoreflect.Message) error {
	var bad error
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch {
		case fd.IsMap() && fd.Name() == "labels":
			if v.Map().Len() > 64 {
				bad = fmt.Errorf("%d labels, at most 64", v.Map().Len())
				return false
			}
			v.Map().Range(func(k protoreflect.MapKey, val protoreflect.Value) bool {
				bad = labelBreaksGrammar(k.String(), val.String())
				return bad == nil
			})
		case fd.IsList() && fd.Message() != nil:
			for i := 0; i < v.List().Len() && bad == nil; i++ {
				bad = labelsBreakGrammar(v.List().Get(i).Message())
			}
		case fd.IsMap() && fd.MapValue().Message() != nil:
			v.Map().Range(func(_ protoreflect.MapKey, val protoreflect.Value) bool {
				bad = labelsBreakGrammar(val.Message())
				return bad == nil
			})
		case !fd.IsMap() && !fd.IsList() && fd.Message() != nil:
			bad = labelsBreakGrammar(v.Message())
		}
		return bad == nil
	})
	return bad
}

func labelBreaksGrammar(key, value string) error {
	if !labelGrammar.MatchString(key) {
		return fmt.Errorf("label key %q breaks the resource API grammar", key)
	}
	if len(value) > 63 || !utf8.ValidString(value) ||
		strings.ContainsFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return fmt.Errorf("label %s value %q breaks the resource API grammar", key, value)
	}
	return nil
}

func TestLabelGrammarRefusesWhatComputeRefuses(t *testing.T) {
	for _, labels := range []map[string]string{
		{"Name": "web-1"},
		{"owner team": "x"},
		{"env": strings.Repeat("v", 64)},
		{"env": "a\tb"},
	} {
		req := &computev1.CreateInstanceRequest{Instance: &computev1.Instance{Labels: labels}}
		if err := labelsBreakGrammar(req.ProtoReflect()); err == nil {
			t.Errorf("labels %q pass the grammar check", labels)
		}
	}
	ok := &computev1.CreateInstanceRequest{Instance: &computev1.Instance{Labels: map[string]string{
		"env": "dev", "vws-tags-00": `{"Name":"web-1"}`, "empty": "",
	}}}
	if err := labelsBreakGrammar(ok.ProtoReflect()); err != nil {
		t.Fatal(err)
	}
}
