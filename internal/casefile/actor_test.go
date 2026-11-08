package casefile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
)

// All data is synthetic: example.com, RFC 5737 addresses, invented user agents.
const validActor = `apiVersion: jb.actor/v1
id: actor-a
label: Example actor A
confidence: medium
indicators:
  - kind: user_agent
    value: ExampleBrowser/9.1 (Plan9; Win64; x64) InventedKit/537.36 (like Gecko) Chrome/9.1.0.0 Safari/537.36
    first_seen: 2026-11-01
    note: full string; a shorter form also matches customers on the same build
  - kind: ip
    value: 198.51.100.200
    note: CDN edge address shared by many clients; an observation, not attribution
  - kind: asn
    value: 64496
  - kind: domain
    value: attacker.example.com
  - kind: fingerprint
    type: jarm
    method: probe-by-hostname
    probe_target: portal.example.com:443
    value: 00000000000000000000000000000000000000000000000000000000000000
detection:
  noise_paths: ["/wp-", "/xmlrpc.php"]
  bare_root_4xx_is_noise: true
  grant_paths: ["/protocol/openid-connect/token"]
`

func TestParseActorValid(t *testing.T) {
	a, err := ParseActor([]byte(validActor))
	if err != nil {
		t.Fatal(err)
	}
	if a.ID != "actor-a" || a.Confidence != "medium" || len(a.Indicators) != 5 {
		t.Fatalf("%+v", a)
	}
	if got := a.UserAgents(); len(got) != 1 || !strings.HasPrefix(got[0], "ExampleBrowser/9.1 (Plan9;") || !strings.HasSuffix(got[0], "Safari/537.36") {
		t.Errorf("user agents %q: the value must be kept byte for byte", got)
	}
	// An unquoted run of digits is a number to YAML. The value must still be the text as written.
	fp := a.Indicators[4]
	if string(fp.Value) != strings.Repeat("0", 62) {
		t.Errorf("fingerprint value %q was rewritten by YAML", fp.Value)
	}
	if !a.BareRoot4xxIsNoise() {
		t.Error("bare_root_4xx_is_noise: true lost")
	}
}

func TestBareRootDefaultsToNoise(t *testing.T) {
	a, err := ParseActor([]byte(minimalActor))
	if err != nil {
		t.Fatal(err)
	}
	if !a.BareRoot4xxIsNoise() {
		t.Error("the default must be the safe one learned from real false results: a 4xx on / is noise")
	}
	off, err := ParseActor([]byte(minimalActor + "detection:\n  bare_root_4xx_is_noise: false\n"))
	if err != nil {
		t.Fatal(err)
	}
	if off.BareRoot4xxIsNoise() {
		t.Error("explicit false ignored")
	}
}

const minimalActor = `apiVersion: jb.actor/v1
id: actor-b
label: Minimal
confidence: low
indicators:
  - kind: user_agent
    value: InventedAgent/1.0
`

func TestParseActorInvalid(t *testing.T) {
	long := strings.Repeat("a", 1100)
	for name, tc := range map[string]struct{ doc, want string }{
		"empty":                 {"", "empty"},
		"wrong version":         {strings.Replace(minimalActor, "jb.actor/v1", "jb.actor/v2", 1), "unsupported apiVersion"},
		"no version":            {strings.Replace(minimalActor, "apiVersion: jb.actor/v1\n", "", 1), "apiVersion is required"},
		"unknown key":           {minimalActor + "surprise: 1\n", "unknown key"},
		"unknown nested key":    {minimalActor + "detection:\n  noise_path: [\"/wp-\"]\n", "unknown key"},
		"unknown indicator key": {minimalActor + "  - kind: ip\n    value: 192.0.2.1\n    extra: 1\n", "unknown key"},
		"two documents":         {minimalActor + "---\nid: x\n", "more than one"},
		"missing label":         {strings.Replace(minimalActor, "label: Minimal\n", "", 1), `missing required key "label"`},
		"no indicators":         {"apiVersion: jb.actor/v1\nid: a\nlabel: l\nconfidence: low\nindicators: []\n", "indicators"},
		"bad id":                {strings.Replace(minimalActor, "actor-b", "Actor B", 1), "id"},
		"bad confidence":        {strings.Replace(minimalActor, "low", "certain", 1), "confidence"},
		"bad kind":              {strings.Replace(minimalActor, "kind: user_agent", "kind: cookie", 1), "kind"},
		"ip not an ip":          {minimalActor + "  - kind: ip\n    value: 192.0.2.999\n", "indicators[1]"},
		"ip with zone":          {minimalActor + "  - kind: ip\n    value: \"fe80::1%eth0\"\n", "indicators[1]"},
		"cidr as ip":            {minimalActor + "  - kind: ip\n    value: 192.0.2.0/24\n", "indicators[1]"},
		"asn zero":              {minimalActor + "  - kind: asn\n    value: 0\n", "indicators[1]"},
		"asn not a number":      {minimalActor + "  - kind: asn\n    value: AS64496\n", "indicators[1]"},
		"asn too big":           {minimalActor + "  - kind: asn\n    value: 4294967296\n", "indicators[1]"},
		"domain upper case":     {minimalActor + "  - kind: domain\n    value: Attacker.Example.com\n", "indicators[1]"},
		"empty ua":              {strings.Replace(minimalActor, "InventedAgent/1.0", "\"\"", 1), "indicators[0]"},
		"ua padded":             {strings.Replace(minimalActor, "InventedAgent/1.0", "\" InventedAgent/1.0\"", 1), "indicators[0]"},
		"ua control char":       {strings.Replace(minimalActor, "InventedAgent/1.0", "\"Invented\\tAgent\"", 1), "indicators[0]"},
		"ua too long":           {strings.Replace(minimalActor, "InventedAgent/1.0", long, 1), "indicators[0]"},
		"ua duplicated":         {minimalActor + "  - kind: user_agent\n    value: InventedAgent/1.0\n", "repeats"},
		"fingerprint no method": {minimalActor + "  - kind: fingerprint\n    type: jarm\n    value: abc123\n", "method"},
		"fingerprint no type":   {minimalActor + "  - kind: fingerprint\n    method: by-host\n    value: abc123\n", "type"},
		"method on an ip":       {minimalActor + "  - kind: ip\n    value: 192.0.2.1\n    method: by-host\n", "method"},
		"bad first_seen":        {minimalActor + "  - kind: ip\n    value: 192.0.2.1\n    first_seen: yesterday\n", "first_seen"},
		"multiline note":        {minimalActor + "  - kind: ip\n    value: 192.0.2.1\n    note: \"a\\nb\"\n", "note"},
		"noise marker short":    {minimalActor + "detection:\n  noise_paths: [\"/\"]\n", "noise_paths[0]"},
		"noise marker empty":    {minimalActor + "detection:\n  noise_paths: [\"\"]\n", "noise_paths[0]"},
		"grant relative":        {minimalActor + "detection:\n  grant_paths: [token]\n", "grant_paths[0]"},
		"grant with query":      {minimalActor + "detection:\n  grant_paths: [\"/token?x=1\"]\n", "grant_paths[0]"},
		"credential in note":    {minimalActor + "  - kind: ip\n    value: 192.0.2.1\n    note: " + strings.Repeat("0123456789abcdef", 3) + "\n", "credential-shaped"},
		"not a mapping":         {"- a\n- b\n", ""},
	} {
		t.Run(name, func(t *testing.T) {
			a, err := ParseActor([]byte(tc.doc))
			if err == nil {
				t.Fatalf("accepted: %+v", a)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

func TestActorCredentialErrorNeverEchoesValue(t *testing.T) {
	secret := "Zk3Qm9Xr2Lt7" + "Vb5Nc8Wd4Hs6Jp1Gy0Fa" // synthetic
	_, err := ParseActor([]byte(minimalActor + "  - kind: ip\n    value: 192.0.2.1\n    note: " + secret + "\n"))
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("want a refusal that omits the value, got %v", err)
	}
}

// A TLS fingerprint legitimately looks like a secret (62 hex characters), so its value
// is the one string exempt from the credential scan. Everything else is still scanned.
func TestFingerprintValueIsExemptFromCredentialScan(t *testing.T) {
	doc := strings.Replace(validActor, strings.Repeat("0", 62), "07d14d16d21d21d00042d43d000000aa99ce74e2c6d013c745aa52b5629e53", 1)
	if _, err := ParseActor([]byte(doc)); err != nil {
		t.Fatal(err)
	}
}

func writeActor(t *testing.T, dir, name, body string) {
	t.Helper()
	p := filepath.Join(dir, "actors", name)
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
}

func newCase(t *testing.T) *Case {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "case.yaml"),
		[]byte("apiVersion: jb.case/v1\nid: t\ntitle: t\nstatus: open\nopened: 2026-11-01\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	c, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestLoadActorFile(t *testing.T) {
	c := newCase(t)
	writeActor(t, c.Dir, "a.yaml", validActor)
	a, err := LoadActorFile(c, "a.yaml")
	if err != nil || a.ID != "actor-a" {
		t.Fatalf("%v %+v", err, a)
	}
}

func TestLoadActorFileConfinement(t *testing.T) {
	c := newCase(t)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "x.yaml"), []byte(validActor), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(c.Dir, "actors"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(c.Dir, "evidence"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.Dir, "evidence", "e.yaml"), []byte(validActor), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "x.yaml"), filepath.Join(c.Dir, "actors", "link.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(c.Dir, "evidence", "e.yaml"), filepath.Join(c.Dir, "actors", "inside.yaml")); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]string{
		"dotdot":               "../evidence/e.yaml",
		"absolute":             filepath.Join(outside, "x.yaml"),
		"symlink outside case": "link.yaml",
		"symlink to evidence":  "inside.yaml", // inside the case, but not in the actors directory
		"empty":                "",
		"not yaml":             "a.txt",
		"backslash":            `sub\a.yaml`,
		"missing":              "nope.yaml",
	} {
		t.Run(name, func(t *testing.T) {
			if a, err := LoadActorFile(c, p); err == nil {
				t.Fatalf("accepted %q: %+v", p, a)
			}
		})
	}
}

func TestLoadActorFileSizeCap(t *testing.T) {
	c := newCase(t)
	writeActor(t, c.Dir, "big.yaml", minimalActor+"# "+strings.Repeat("x", maxFileSize)+"\n")
	if _, err := LoadActorFile(c, "big.yaml"); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("got %v", err)
	}
}

func TestLoadActorFileNotRegular(t *testing.T) {
	c := newCase(t)
	if err := os.MkdirAll(filepath.Join(c.Dir, "actors", "dir.yaml"), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadActorFile(c, "dir.yaml"); err == nil {
		t.Fatal("a directory is not an actor file")
	}
}

func TestLoadActors(t *testing.T) {
	c := newCase(t)
	if as, err := LoadActors(c); err != nil || len(as) != 0 {
		t.Fatalf("no actors directory is not an error: %v %v", as, err)
	}
	writeActor(t, c.Dir, "a.yaml", validActor)
	writeActor(t, c.Dir, "b.yml", minimalActor)
	writeActor(t, c.Dir, "README.md", "not an actor file")
	as, err := LoadActors(c)
	if err != nil || len(as) != 2 || as[0].ID != "actor-a" || as[1].ID != "actor-b" {
		t.Fatalf("%v %+v", err, as)
	}
	writeActor(t, c.Dir, "c.yaml", strings.Replace(minimalActor, "Minimal", "Dup", 1)) // id actor-b again
	if _, err := LoadActors(c); err == nil || !strings.Contains(err.Error(), "actor-b") {
		t.Fatalf("a duplicate id across files must be refused: %v", err)
	}
}

func TestLoadActorsReportsEveryBrokenFile(t *testing.T) {
	c := newCase(t)
	writeActor(t, c.Dir, "good.yaml", validActor)
	writeActor(t, c.Dir, "bad1.yaml", "apiVersion: jb.actor/v1\nid: x\n")
	writeActor(t, c.Dir, "bad2.yaml", minimalActor+"surprise: 1\n")
	_, err := LoadActors(c)
	if err == nil || !strings.Contains(err.Error(), "bad1.yaml") || !strings.Contains(err.Error(), "bad2.yaml") {
		t.Fatalf("got %v", err)
	}
}

// The shipped example must parse as a real actor file.
func TestExampleActor(t *testing.T) {
	c, err := Load(filepath.Join("..", "..", "examples", "case"))
	if err != nil {
		t.Fatal(err)
	}
	as, err := LoadActors(c)
	if err != nil || len(as) == 0 {
		t.Fatalf("%v %v", as, err)
	}
	for _, a := range as {
		if len(a.UserAgents()) == 0 {
			t.Errorf("%s: the example should show a user_agent indicator", a.ID)
		}
	}
}

// ---- schema/loader equality, as for case.schema.json ----

func loadActorSchema(t *testing.T) schemaNode {
	t.Helper()
	b, err := os.ReadFile("../../docs/schemas/actor.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var s schemaNode
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestActorSchemaMatchesStruct(t *testing.T) {
	s := loadActorSchema(t)
	var fromSchema, fromGo []string
	schemaNames(t, s, "", &fromSchema)
	goNames(reflect.TypeOf(Actor{}), "", &fromGo)
	sort.Strings(fromSchema)
	sort.Strings(fromGo)
	if !slices.Equal(fromSchema, fromGo) {
		t.Errorf("schema properties %v\nGo fields         %v", fromSchema, fromGo)
	}
}

func TestActorSchemaMatchesLoaderRules(t *testing.T) {
	s := loadActorSchema(t)
	if !slices.Equal(sorted(s.Required), sorted(ActorRequiredKeys)) {
		t.Errorf("required: schema %v, loader %v", s.Required, ActorRequiredKeys)
	}
	if s.Properties["apiVersion"].Const != ActorAPIVersion {
		t.Errorf("apiVersion const: schema %v, loader %s", s.Properties["apiVersion"].Const, ActorAPIVersion)
	}
	if got := asStrings(t, s.Properties["confidence"].Enum); !slices.Equal(sorted(got), sorted(Confidences)) {
		t.Errorf("confidence enum: schema %v, loader %v", got, Confidences)
	}
	ind := s.Properties["indicators"].Items
	if got := asStrings(t, ind.Properties["kind"].Enum); !slices.Equal(sorted(got), sorted(IndicatorKinds)) {
		t.Errorf("kind enum: schema %v, loader %v", got, IndicatorKinds)
	}
	if !slices.Equal(sorted(ind.Required), sorted(IndicatorRequiredKeys)) {
		t.Errorf("indicator required: schema %v, loader %v", ind.Required, IndicatorRequiredKeys)
	}
}
