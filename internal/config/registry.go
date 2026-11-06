package config

import "gopkg.in/yaml.v3"

// The registries map a `type:` to the function that decodes and validates its
// options. One function per adapter, each in its own file, keeps adding an adapter
// to a single new file plus one line here.

func sourceTypes() map[string]func(*yaml.Node) (sourceSpec, error) {
	m := map[string]func(*yaml.Node) (sourceSpec, error){}
	registerKibana(m)
	return m
}

func detectorTypes() map[string]func(*yaml.Node) (detectorSpec, error) {
	m := map[string]func(*yaml.Node) (detectorSpec, error){}
	registerAuthspike(m)
	registerFingerprint(m)
	registerSignup(m)
	registerNewkey(m)
	registerBehaviour(m)
	registerSignature(m)
	return m
}

func feedTypes() map[string]func(*yaml.Node) (feedSpec, error) {
	m := map[string]func(*yaml.Node) (feedSpec, error){}
	registerGreyNoise(m)
	registerSansISC(m)
	registerDNSBL(m)
	return m
}
