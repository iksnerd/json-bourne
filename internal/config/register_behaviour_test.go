package config

import (
	"strings"
	"testing"
)

const behaviourOK = `  - type: behaviour
    key_field: client_ip
    path_field: path
    method_field: method
    status_field: status
    user_agent_field: user_agent
    ignore_keys: [192.0.2.1]
    ignore_user_agents: [gateway-http]
    actions:
      - name: device-code
        class: rare
        path: /oauth/device/code
        methods: [POST]
      - name: token
        class: common
        path_pattern: /oauth/(token|introspect)
        fail_statuses: [400, 401]
`

func TestBehaviourParseAndBuild(t *testing.T) {
	f, err := Parse([]byte(kibanaHead + behaviourOK))
	if err != nil {
		t.Fatal(err)
	}
	rt, err := f.Build(envOf(map[string]string{"JB_KIBANA_API_KEY": secret}))
	if err != nil {
		t.Fatal(err)
	}
	if len(rt.Detectors) != 1 || rt.Detectors[0].Name() != "behaviour" {
		t.Fatalf("detectors %v", rt.Detectors)
	}
}

func TestBehaviourRejectsBadInputAtLoad(t *testing.T) {
	cases := map[string]string{
		"unknown key":        strings.Replace(behaviourOK, "key_field: client_ip", "key_field: client_ip\n    key_feild: x", 1),
		"unknown action key": strings.Replace(behaviourOK, "class: rare", "class: rare\n        paths: [/x]", 1),
		"bad class":          strings.Replace(behaviourOK, "class: rare", "class: sometimes", 1),
		"no actions":         strings.Split(behaviourOK, "    actions:")[0],
		"bad pattern":        strings.Replace(behaviourOK, "/oauth/(token|introspect)", "/oauth/(", 1),
		"bad status":         strings.Replace(behaviourOK, "[400, 401]", "[4]", 1),
	}
	for name, body := range cases {
		if _, err := Parse([]byte(kibanaHead + body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
