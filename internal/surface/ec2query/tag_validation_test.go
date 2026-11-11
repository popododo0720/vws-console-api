package ec2query

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestTagValidationUsesAWSMessages(t *testing.T) {
	h, cred, now := harness(t)
	for _, action := range []string{"CreateTags", "DeleteTags"} {
		for _, kind := range []string{"i", "vol", "vpc", "subnet"} {
			for _, parameter := range []string{"key", "value"} {
				t.Run(action+"/"+kind+"/"+parameter, func(t *testing.T) {
					key, value := "k", "v"
					reason := "Tag key exceeds the maximum length of 128 characters"
					if parameter == "key" {
						key = strings.Repeat("k", 129)
					} else {
						value = strings.Repeat("v", 257)
						reason = "Tag value exceeds the maximum length of 256 characters"
					}
					invalid := key
					if parameter == "value" {
						invalid = value
					}
					form := url.Values{
						"Action": {action}, "Version": {Version},
						"ResourceId.1": {kind + "-0123456789abcdef0"},
						"Tag.1.Key":    {key}, "Tag.1.Value": {value},
					}
					for range 2 {
						res := signed(t, h, cred, now, form.Encode())
						body := res.Body.String()
						want := "Value (" + invalid + ") for parameter " + parameter + " is invalid. " + reason
						if res.Code != http.StatusBadRequest ||
							xmlText(t, body, "Code") != "InvalidParameterValue" || xmlText(t, body, "Message") != want {
							t.Fatalf("got %d %s, want 400 InvalidParameterValue %q", res.Code, body, want)
						}
					}
				})
			}
		}
	}
}

func TestTagSpecificationValidationUsesAWSMessages(t *testing.T) {
	h, cred, now := harness(t)
	for _, action := range []string{"CreateVolume", "RunInstances"} {
		for _, parameter := range []string{"key", "value"} {
			t.Run(action+"/"+parameter, func(t *testing.T) {
				form := url.Values{"Action": {action}, "Version": {Version}}
				kind := "volume"
				if action == "CreateVolume" {
					form.Set("Size", "8")
					form.Set("AvailabilityZone", "vws-1a")
				} else {
					kind = "instance"
					form.Set("ClientToken", "invalid-tag-"+parameter)
					form.Set("ImageId", "ami-0123456789abcdef0")
					form.Set("InstanceType", "vws.small")
					form.Set("SubnetId", "subnet-0123456789abcdef0")
					form.Set("MinCount", "1")
					form.Set("MaxCount", "1")
				}
				key, value := strings.Repeat("k", 129), "v"
				reason := "Tag key exceeds the maximum length of 128 characters"
				invalid := key
				if parameter == "value" {
					key, value = "k", strings.Repeat("v", 257)
					invalid = value
					reason = "Tag value exceeds the maximum length of 256 characters"
				}
				form.Set("TagSpecification.1.ResourceType", kind)
				form.Set("TagSpecification.1.Tag.1.Key", key)
				form.Set("TagSpecification.1.Tag.1.Value", value)
				res := signed(t, h, cred, now, form.Encode())
				body := res.Body.String()
				want := "Value (" + invalid + ") for parameter " + parameter + " is invalid. " + reason
				if res.Code != http.StatusBadRequest ||
					xmlText(t, body, "Code") != "InvalidParameterValue" || xmlText(t, body, "Message") != want {
					t.Fatalf("got %d %s, want 400 InvalidParameterValue %q", res.Code, body, want)
				}
			})
		}
	}
}
