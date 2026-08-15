package oidcauth

import (
	"reflect"
	"testing"
)

func TestMatchesAny(t *testing.T) {
	cases := []struct {
		name       string
		have, want []string
		match      bool
	}{
		{"exact", []string{"ca-admins"}, []string{"ca-admins"}, true},
		{"case-insensitive", []string{"CA-Admins"}, []string{"ca-admins"}, true},
		{"whitespace", []string{" ca-admins "}, []string{"ca-admins"}, true},
		{"no overlap", []string{"engineering"}, []string{"ca-admins"}, false},
		{"empty have", nil, []string{"ca-admins"}, false},
		{"empty want", []string{"ca-admins"}, nil, false},
		{"one of many", []string{"a", "b", "ca-admins"}, []string{"x", "ca-admins"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := matchesAny(c.have, c.want); got != c.match {
				t.Errorf("matchesAny(%v, %v) = %v, want %v", c.have, c.want, got, c.match)
			}
		})
	}
}

func TestStringClaim(t *testing.T) {
	claims := map[string]any{"email": "a@example.com", "num": 5}
	if got := stringClaim(claims, "email"); got != "a@example.com" {
		t.Errorf("stringClaim(email) = %q", got)
	}
	if got := stringClaim(claims, "missing"); got != "" {
		t.Errorf("stringClaim(missing) = %q, want empty", got)
	}
	if got := stringClaim(claims, "num"); got != "" {
		t.Errorf("stringClaim(num) = %q, want empty (wrong type)", got)
	}
	if got := stringClaim(claims, ""); got != "" {
		t.Errorf("stringClaim(\"\") = %q, want empty", got)
	}
}

func TestStringSliceClaim(t *testing.T) {
	cases := []struct {
		name  string
		value any
		want  []string
	}{
		{"json array", []any{"a", "b"}, []string{"a", "b"}},
		{"mixed array drops non-strings", []any{"a", 1, "b"}, []string{"a", "b"}},
		{"bare string", "solo-group", []string{"solo-group"}},
		{"go string slice", []string{"a", "b"}, []string{"a", "b"}},
		{"missing", nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			claims := map[string]any{}
			if c.value != nil {
				claims["groups"] = c.value
			}
			got := stringSliceClaim(claims, "groups")
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("stringSliceClaim = %#v, want %#v", got, c.want)
			}
		})
	}
	if got := stringSliceClaim(map[string]any{"groups": []any{"a"}}, ""); got != nil {
		t.Errorf("stringSliceClaim with empty key = %#v, want nil", got)
	}
}

func TestFirstNonEmptyClaim(t *testing.T) {
	claims := map[string]any{"email": "a@example.com", "sub": "abc123"}
	if got := firstNonEmptyClaim(claims, "preferred_username", "email", "sub"); got != "a@example.com" {
		t.Errorf("got %q, want email fallback", got)
	}
	if got := firstNonEmptyClaim(claims, "preferred_username", "sub"); got != "abc123" {
		t.Errorf("got %q, want sub fallback", got)
	}
	if got := firstNonEmptyClaim(claims, "nope"); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestScopesOrDefault(t *testing.T) {
	if got := scopesOrDefault(nil); !reflect.DeepEqual(got, []string{"openid", "profile", "email"}) {
		t.Errorf("default scopes = %v", got)
	}
	if got := scopesOrDefault([]string{"openid", "groups"}); !reflect.DeepEqual(got, []string{"openid", "groups"}) {
		t.Errorf("explicit openid scopes changed: %v", got)
	}
	if got := scopesOrDefault([]string{"groups"}); !reflect.DeepEqual(got, []string{"openid", "groups"}) {
		t.Errorf("missing openid was not added: %v", got)
	}
}

// TestExchangeMapsAdminAndAllowedGroups exercises the claim-to-Identity
// mapping and group-based role/access logic directly (the part a live IdP
// like Dex's static-password connector, used for the end-to-end test, cannot
// exercise since it does not emit a groups claim).
func TestExchangeMapsAdminAndAllowedGroups(t *testing.T) {
	cfg := struct {
		AdminGroups, AllowedGroups []string
	}{
		AdminGroups:   []string{"ca-admins"},
		AllowedGroups: []string{"ca-admins", "ca-users"},
	}

	admin := &Identity{Username: "alice", Groups: []string{"ca-admins", "engineering"}}
	admin.IsAdmin = matchesAny(admin.Groups, cfg.AdminGroups)
	if !admin.IsAdmin {
		t.Error("a member of ca-admins should be admin")
	}

	member := &Identity{Username: "bob", Groups: []string{"ca-users"}}
	member.IsAdmin = matchesAny(member.Groups, cfg.AdminGroups)
	if member.IsAdmin {
		t.Error("a non-admin group member should not be admin")
	}
	if !matchesAny(member.Groups, cfg.AllowedGroups) {
		t.Error("a ca-users member should be an allowed login")
	}

	outsider := &Identity{Username: "eve", Groups: []string{"engineering"}}
	if matchesAny(outsider.Groups, cfg.AllowedGroups) {
		t.Error("a user with no matching group should not be allowed")
	}
}
