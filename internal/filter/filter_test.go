package filter

import (
	"strings"
	"testing"
)

func TestRedactKinds(t *testing.T) {
	cases := map[string]string{
		"aws_access_key": "key AKIAIOSFODNN7EXAMPLE here",
		"github_token":   "token ghp_0123456789abcdefghijABCDEFGHIJ012345 end",
		"openai_key":     `{"k":"sk-proj-abcdefghijklmnopqrstuvwxyz0123"}`,
		"anthropic_key":  "sk-ant-api03-abcdefghijklmnopqrstuvwxyz",
		"stripe_key":     "sk_live_0123456789abcdefABCD",
		"slack_token":    "xoxb-1234567890-abcdefghij",
		"google_api_key": "AIzaSyA0123456789abcdefghijklmnopqrstuv",
		"jwt":            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
		"url_password":   "postgres://admin:hunter2pass@db:5432/x",
		"bearer_token":   "Authorization: Bearer abcdefghijklmnop0123",
		"secret_field":   `{"user":"bob","password":"correct-horse"}`,
		"private_key":    "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----",
	}
	for kind, in := range cases {
		r := Redact(in)
		if r.Kinds[kind] == 0 {
			t.Errorf("%s not found in %q: %+v", kind, in, r)
		}
	}
}

func TestRedactKeepsOrdinaryText(t *testing.T) {
	for _, in := range []string{
		`{"symbol":"ACME","price":12.50,"quantity":10}`,
		"The password policy requires 12 characters.",
		"token count: 1234",
		"order o-17 cancelled",
		"see https://example.com/docs?page=2",
	} {
		if r := Redact(in); r.Redactions != 0 || r.Text != in {
			t.Errorf("changed %q -> %q", in, r.Text)
		}
	}
}

func TestRedactFieldValueOnly(t *testing.T) {
	r := Redact(`{"user":"bob","api_key":"abc123secret","note":"hi"}`)
	if r.Text != `{"user":"bob","api_key":"[REDACTED:secret_field]","note":"hi"}` {
		t.Fatal(r.Text)
	}
	r = Redact("DB_PASSWORD=s3cretvalue\nPORT=5432")
	if !strings.Contains(r.Text, "DB_PASSWORD=[REDACTED:secret_field]") || !strings.Contains(r.Text, "PORT=5432") {
		t.Fatal(r.Text)
	}
}

func TestRedactLiteral(t *testing.T) {
	r := Redact("served with key zz-app-key-zz twice zz-app-key-zz", "zz-app-key-zz")
	if strings.Contains(r.Text, "zz-app-key-zz") || r.Kinds["credential"] != 2 {
		t.Fatalf("%+v", r)
	}
}
