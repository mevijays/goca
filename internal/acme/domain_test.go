package acme

import "testing"

func TestDomainAllowed(t *testing.T) {
	cases := []struct {
		patterns []string
		name     string
		want     bool
	}{
		{nil, "anything.internal", true},
		{[]string{}, "anything.internal", true},
		{[]string{"*.svc.cluster-a.internal"}, "app.svc.cluster-a.internal", true},
		{[]string{"*.svc.cluster-a.internal"}, "a.b.svc.cluster-a.internal", true},
		{[]string{"*.svc.cluster-a.internal"}, "svc.cluster-a.internal", false},
		{[]string{"*.svc.cluster-a.internal"}, "app.svc.cluster-b.internal", false},
		{[]string{"app.internal.lab"}, "app.internal.lab", true},
		{[]string{"app.internal.lab"}, "other.internal.lab", false},
		{[]string{"*.a.internal", "*.b.internal"}, "x.b.internal", true},
		{[]string{"*.internal.lab"}, "*.internal.lab", true},                       // a wildcard identifier itself
		{[]string{"*.SVC.Cluster-A.Internal"}, "app.svc.cluster-a.internal", true}, // case-insensitive
		{[]string{"*.svc.cluster-a.internal"}, "APP.SVC.CLUSTER-A.INTERNAL", true},
	}
	for _, c := range cases {
		got := domainAllowed(c.patterns, c.name)
		if got != c.want {
			t.Errorf("domainAllowed(%v, %q) = %v, want %v", c.patterns, c.name, got, c.want)
		}
	}
}
