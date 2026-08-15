package acme

import "fmt"

// Problem is an RFC 8555 §6.7 / RFC 7807 problem document. It is both the
// value marshalled as an "application/problem+json" response and the Go error
// type used internally to carry that response back through the call stack.
type Problem struct {
	Type   string `json:"type"`
	Detail string `json:"detail,omitempty"`
	Status int    `json:"status,omitempty"`
}

func (p *Problem) Error() string { return p.Detail }

const errNS = "urn:ietf:params:acme:error:"

func problem(kind string, status int, format string, a ...any) *Problem {
	return &Problem{Type: errNS + kind, Status: status, Detail: fmt.Sprintf(format, a...)}
}

// The standard ACME error types (RFC 8555 §6.7), constructed with the HTTP
// status the spec associates with each.
func BadNonce(detail string) *Problem       { return problem("badNonce", 400, "%s", detail) }
func Malformed(f string, a ...any) *Problem { return problem("malformed", 400, f, a...) }
func Unauthorized(f string, a ...any) *Problem {
	return problem("unauthorized", 401, f, a...)
}
func AccountDoesNotExist(detail string) *Problem {
	return problem("accountDoesNotExist", 400, "%s", detail)
}
func RejectedIdentifier(f string, a ...any) *Problem {
	return problem("rejectedIdentifier", 400, f, a...)
}
func UnsupportedIdentifier(f string, a ...any) *Problem {
	return problem("unsupportedIdentifier", 400, f, a...)
}
func OrderNotReady(detail string) *Problem { return problem("orderNotReady", 403, "%s", detail) }
func BadCSR(f string, a ...any) *Problem   { return problem("badCSR", 400, f, a...) }
func BadRevocationReason(detail string) *Problem {
	return problem("badRevocationReason", 400, "%s", detail)
}
func AlreadyRevoked(detail string) *Problem { return problem("alreadyRevoked", 400, "%s", detail) }
func ExternalAccountRequired(detail string) *Problem {
	return problem("externalAccountRequired", 400, "%s", detail)
}
func ServerInternal(f string, a ...any) *Problem { return problem("serverInternal", 500, f, a...) }
func NotFound(detail string) *Problem            { return problem("malformed", 404, "%s", detail) }
