package iam_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/iam"
)

// #358: every Admin call that answers one named user, group or role, other
// than the Create call that makes it, takes the AuthorizedPrincipal the caller was
// authorized on. The pre-authorization lookup is Resolver, which answers an
// identity (ARN and unique ID) and never the entity's data.
func TestAdminEntityReadsAreBound(t *testing.T) {
	admin := reflect.TypeFor[iam.Admin]()
	entity := map[reflect.Type]bool{
		reflect.TypeFor[iam.User](): true, reflect.TypeFor[iam.Group](): true, reflect.TypeFor[iam.Role](): true,
	}
	bound := reflect.TypeFor[iam.AuthorizedPrincipal]()
	for i := range admin.NumMethod() {
		m := admin.Method(i)
		if strings.HasPrefix(m.Name, "Create") || m.Type.NumOut() == 0 || !entity[m.Type.Out(0)] {
			continue
		}
		takes := false
		for j := range m.Type.NumIn() {
			takes = takes || m.Type.In(j) == bound
		}
		if !takes {
			t.Errorf("iam.Admin.%s answers a %s without an AuthorizedPrincipal", m.Name, m.Type.Out(0).Name())
		}
	}
	resolver := reflect.TypeFor[iam.Resolver]()
	for i := range resolver.NumMethod() {
		m := resolver.Method(i)
		if m.Type.NumOut() != 2 || m.Type.Out(0) != reflect.TypeFor[iam.Ref]() {
			t.Errorf("iam.Resolver.%s answers %v, want (iam.Ref, error)", m.Name, m.Type)
		}
	}
}
