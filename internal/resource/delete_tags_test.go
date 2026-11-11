package resource

import (
	"maps"
	"strconv"
	"strings"
	"testing"
)

func TestRemoveTags(t *testing.T) {
	base := map[string]string{"Name": "web", "env": "dev", "blank": "", "aws:cloudformation:stack-name": "s"}
	dev, empty, prod := "dev", "", "prod"
	for name, tc := range map[string]struct {
		sel  []TagSelector
		want map[string]string
	}{
		"key only": {
			[]TagSelector{{Key: "Name"}},
			map[string]string{"env": "dev", "blank": "", "aws:cloudformation:stack-name": "s"},
		},
		"matching value": {
			[]TagSelector{{Key: "env", Value: &dev}},
			map[string]string{"Name": "web", "blank": "", "aws:cloudformation:stack-name": "s"},
		},
		"other value": {[]TagSelector{{Key: "env", Value: &prod}}, base},
		"empty value": {
			[]TagSelector{{Key: "blank", Value: &empty}, {Key: "Name", Value: &empty}},
			map[string]string{"Name": "web", "env": "dev", "aws:cloudformation:stack-name": "s"},
		},
		"absent key":       {[]TagSelector{{Key: "nope"}}, base},
		"all but aws tags": {nil, map[string]string{"aws:cloudformation:stack-name": "s"}},
	} {
		t.Run(name, func(t *testing.T) {
			before := maps.Clone(base)
			if got := RemoveTags(base, tc.sel); !maps.Equal(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			if !maps.Equal(base, before) {
				t.Fatalf("RemoveTags changed its input to %v", base)
			}
		})
	}
}

func TestDeleteTagsRequestNormalize(t *testing.T) {
	id, err := Parse[VpcID]("vpc-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("v", 257)
	selectors := func(n int) []TagSelector {
		out := make([]TagSelector, n)
		for i := range out {
			out[i] = TagSelector{Key: "k" + strconv.Itoa(i)}
		}
		return out
	}
	for name, tc := range map[string]struct {
		req  UntagVpcsRequest
		want string
	}{
		"no ids":    {UntagVpcsRequest{}, "must list from 1 to 20 ids"},
		"duplicate": {UntagVpcsRequest{IDs: []VpcID{id, id}}, "duplicate"},
		"empty key": {UntagVpcsRequest{IDs: []VpcID{id}, Tags: []TagSelector{{Key: ""}}}, "Tag key must not be empty"},
		"long key": {
			UntagVpcsRequest{IDs: []VpcID{id}, Tags: []TagSelector{{Key: strings.Repeat("k", 129)}}},
			"Tag key exceeds the maximum length of 128 characters",
		},
		"long value": {
			UntagVpcsRequest{IDs: []VpcID{id}, Tags: []TagSelector{{Key: "k", Value: &long}}},
			"Tag value exceeds the maximum length of 256 characters",
		},
		"aws: prefix": {UntagVpcsRequest{IDs: []VpcID{id}, Tags: []TagSelector{{Key: "aws:x"}}}, "reserved"},
		"ok, all":     {UntagVpcsRequest{IDs: []VpcID{id}}, ""},
		"51 selectors": {
			UntagVpcsRequest{IDs: []VpcID{id}, Tags: selectors(MaxTags + 1)}, "too many",
		},
		"50 selectors": {
			UntagVpcsRequest{IDs: []VpcID{id}, Tags: selectors(MaxTags)}, "",
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := tc.req.Normalize()
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v, want %q", err, tc.want)
			}
		})
	}
	if (DeleteTagsRequest{}).Action() != ActionDeleteTags || (UntagSubnetsRequest{}).Action() != ActionDeleteTags {
		t.Fatal("DeleteTags requests must name the DeleteTags action")
	}
}

func TestUntagVolumesRequestNormalize(t *testing.T) {
	id, err := Parse[VolumeID]("vol-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		req  UntagVolumesRequest
		want string
	}{
		"no ids":    {UntagVolumesRequest{}, "must list from 1 to 20 ids"},
		"duplicate": {UntagVolumesRequest{IDs: []VolumeID{id, id}}, "duplicate"},
		"empty key": {UntagVolumesRequest{IDs: []VolumeID{id}, Tags: []TagSelector{{Key: ""}}}, "Tag key must not be empty"},
		"reserved":  {UntagVolumesRequest{IDs: []VolumeID{id}, Tags: []TagSelector{{Key: "aws:stack"}}}, "reserved"},
		"all":       {UntagVolumesRequest{IDs: []VolumeID{id}}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := tc.req.Normalize()
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v, want %q", err, tc.want)
			}
			if tc.req.Action() != ActionDeleteTags {
				t.Fatal("volume untag must name DeleteTags")
			}
		})
	}
}
