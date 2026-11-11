package resource

import (
	"strings"
	"testing"
)

func TestInvalidTagMessages(t *testing.T) {
	for _, tc := range []struct {
		name, key, value, want string
	}{
		{
			"long key", strings.Repeat("k", 129), "v",
			"Value (" + strings.Repeat("k", 129) +
				") for parameter key is invalid. Tag key exceeds the maximum length of 128 characters",
		},
		{
			"long value", "k", strings.Repeat("v", 257),
			"Value (" + strings.Repeat("v", 257) +
				") for parameter value is invalid. Tag value exceeds the maximum length of 256 characters",
		},
		{"empty key", "", "v", "Value () for parameter key is invalid. Tag key must not be empty"},
		{
			"control key", "a\nb", "v",
			`Value ("a\nb") for parameter key is invalid. Tag key must not contain control characters`,
		},
		{
			"control value", "k", "a\x00b",
			`Value ("a\x00b") for parameter value is invalid. Tag value must not contain control characters`,
		},
		{
			"invalid UTF-8 key", "\xff", "v",
			`Value ("\xff") for parameter key is invalid. Tag key must be valid UTF-8`,
		},
		{
			"invalid UTF-8 value", "k", "\xff",
			`Value ("\xff") for parameter value is invalid. Tag value must be valid UTF-8`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, err := range []error{
				validTags(map[string]string{tc.key: tc.value}),
				ValidateTagSelectors([]TagSelector{{Key: tc.key, Value: &tc.value}}),
			} {
				if err == nil {
					t.Fatal("invalid tag accepted")
				}
				got := AsError(err)
				if got.Code != CodeInvalidArgument || got.Field != "tags" || got.Message != tc.want {
					t.Fatalf("got %+v, want InvalidArgument tags %q", got, tc.want)
				}
			}
		})
	}
}
