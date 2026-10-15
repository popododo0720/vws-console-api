package resource

import (
	"errors"
	"math"
	"testing"
)

func TestInstanceTypeMapsToNearestVWSType(t *testing.T) {
	type size struct {
		vcpus  float64
		memGiB float64
	}
	vws := []struct {
		name string
		size size
	}{
		{"vws.small", size{1, 1}},
		{"vws.medium", size{2, 4}},
		{"vws.large", size{4, 8}},
		{"vws.xlarge", size{8, 16}},
	}
	t3 := []size{{2, 0.5}, {2, 1}, {2, 2}, {2, 4}, {2, 8}, {4, 16}, {8, 32}}
	steps := []string{"nano", "micro", "small", "medium", "large", "xlarge", "2xlarge"}
	ec2 := map[string]size{}
	for i, s := range steps {
		ec2["t3."+s], ec2["t3a."+s] = t3[i], t3[i]
	}
	t2 := []size{{1, 0.5}, {1, 1}, {1, 2}, {2, 4}, {2, 8}, {4, 16}, {8, 32}}
	for i, s := range steps {
		ec2["t2."+s] = t2[i]
	}
	for _, s := range []struct {
		n string
		m size
		c size
	}{{"large", size{2, 8}, size{2, 4}}, {"xlarge", size{4, 16}, size{4, 8}}, {"2xlarge", size{8, 32}, size{8, 16}}} {
		ec2["m5."+s.n], ec2["c5."+s.n] = s.m, s.c
	}
	for name, sz := range ec2 {
		best, bestD := "", math.Inf(1)
		for _, v := range vws {
			d := math.Abs(math.Log2(sz.vcpus/v.size.vcpus)) + math.Abs(math.Log2(sz.memGiB/v.size.memGiB))
			if d < bestD {
				best, bestD = v.name, d
			}
		}
		got, ok := vwsInstanceType(name)
		if !ok || got != best {
			t.Errorf("%s: got %q, %v; want %q", name, got, ok, best)
		}
	}
	for _, v := range vws {
		if got, ok := vwsInstanceType(v.name); !ok || got != v.name {
			t.Errorf("%s: got %q, %v", v.name, got, ok)
		}
	}
}

func TestRunInstancesMapsInstanceType(t *testing.T) {
	img, _ := Parse[ImageID]("ami-0123456789abcdef0")
	sub, _ := Parse[SubnetID]("subnet-0123456789abcdef0")
	norm, err := RunInstancesRequest{ImageID: img, InstanceType: "t3.micro", SubnetID: sub}.Normalize()
	if err != nil || norm.InstanceType != "vws.small" {
		t.Fatalf("got %q, %v", norm.InstanceType, err)
	}
	for _, typ := range []string{"p4d.24xlarge", "t3.nano2", "vws.huge", ""} {
		_, err := RunInstancesRequest{ImageID: img, InstanceType: typ, SubnetID: sub}.Normalize()
		var e *Error
		if !errors.As(err, &e) || e.Code != CodeInvalidArgument || e.Field != "instanceType" {
			t.Errorf("%q: %v", typ, err)
		}
	}
}
