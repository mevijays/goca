package web

import (
	"net/http/httptest"
	"testing"

	"github.com/mevijays/goca/internal/gocaclient"
)

// TestCreateRequestsRoundTripThroughRealMarshalling is what
// internal/gocaclient's drift test cannot be: it calls the actual client
// methods, over real HTTP, against a real server. The drift test compares
// json tag *names* between the client's request structs and each service
// layer's own input type, but CsiAuthMethod and Webhook are also each
// client's *response* shape, decoded straight off GET/list endpoints with a
// server-set id/created_at/updated_at - there is no service-layer input type
// to diff those two structs against, only the web package's own unexported
// decode target (csiAuthMethodInput, webhookInput), which the drift test
// cannot see across package boundaries. A CsiAuthMethod or Webhook value
// marshalled with those response-only fields still present (they were
// missing `omitempty`, once - see the fix on the same commit as this test)
// is a hard 400 from decodeJSON's DisallowUnknownFields, not a silently
// ignored field - so this exercises Create for both by round-tripping a real
// client through a real httptest server, the same way a CLI invocation
// would.
func TestCreateRequestsRoundTripThroughRealMarshalling(t *testing.T) {
	h := newHarness(t)
	srv := httptest.NewServer(h.handler)
	defer srv.Close()

	c, err := gocaclient.New(gocaclient.Options{Server: srv.URL, Token: h.token("admin")})
	if err != nil {
		t.Fatalf("gocaclient.New: %v", err)
	}
	ctx := h.t.Context()

	t.Run("CsiAuthMethod", func(t *testing.T) {
		created, err := c.CreateCsiAuthMethod(ctx, gocaclient.CsiAuthMethod{
			Name: "smoke-test", Audience: "goca-csi", APIServerURL: "https://10.0.0.1:6443",
			ReviewerToken: "dummy-token",
		})
		if err != nil {
			t.Fatalf("CreateCsiAuthMethod: %v", err)
		}
		if created.Value.Name != "smoke-test" {
			t.Fatalf("created name = %q, want smoke-test", created.Value.Name)
		}

		// Update, built as a fresh request from the fetched fields - the
		// pattern internal/rcli/csi_auth_cmd.go actually uses, deliberately
		// never copying ID/CreatedBy/CreatedAt/UpdatedAt into an outgoing
		// request (see CsiAuthMethod's doc comment for why those must never
		// be set on a request, not just left at their zero value).
		in := gocaclient.CsiAuthMethod{
			Name: created.Value.Name, Audience: "goca-csi-v2",
			APIServerURL: created.Value.APIServerURL,
		}
		if _, err := c.UpdateCsiAuthMethod(ctx, created.Value.ID, in); err != nil {
			t.Fatalf("UpdateCsiAuthMethod: %v", err)
		}
	})

	t.Run("Webhook", func(t *testing.T) {
		created, err := c.CreateWebhook(ctx, gocaclient.Webhook{
			Name: "smoke-test", URL: "https://hooks.example.com/goca", Events: "*",
		})
		if err != nil {
			t.Fatalf("CreateWebhook: %v", err)
		}
		if created.Value.Name != "smoke-test" {
			t.Fatalf("created name = %q, want smoke-test", created.Value.Name)
		}

		in := gocaclient.Webhook{Name: created.Value.Name, URL: created.Value.URL, Events: "cert.issue"}
		if _, err := c.UpdateWebhook(ctx, created.Value.ID, in); err != nil {
			t.Fatalf("UpdateWebhook: %v", err)
		}
	})
}
