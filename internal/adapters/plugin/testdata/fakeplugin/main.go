// Command fakeplugin is a deliberately misbehaving mapper plugin for the host's tests.
// Its behaviour is chosen by the contents of a file named "mode" in its working
// directory (the host starts a plugin there), because the host hands a child no
// environment and no arguments. Not a real plugin; do not copy it.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

func appendLine(name, line string) {
	f, err := os.OpenFile(name, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err == nil {
		fmt.Fprintln(f, line)
		f.Close()
	}
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "sleeper" {
		_ = os.WriteFile("child.pid", []byte(fmt.Sprint(os.Getpid())), 0o644)
		time.Sleep(time.Minute)
		return
	}
	b, _ := os.ReadFile("mode")
	mode := strings.TrimSpace(string(b))
	appendLine("launches", mode)
	_ = os.WriteFile("pid", []byte(fmt.Sprint(os.Getpid())), 0o644)
	out := bufio.NewWriter(os.Stdout)
	flush := func() { out.Flush() }

	switch mode {
	case "nohandshake":
		return
	case "slowhandshake":
		time.Sleep(time.Minute)
	case "badrole":
		fmt.Fprintln(out, `{"v":1,"role":"sink","name":"fake"}`)
		flush()
		time.Sleep(time.Minute)
	case "badversion":
		fmt.Fprintln(out, `{"v":2,"role":"mapper","name":"fake"}`)
		flush()
		time.Sleep(time.Minute)
	case "slow":
		// Start a grandchild before the handshake and wait until it is running, so the
		// test can prove the deadline kill reaches it without racing its start-up.
		c := exec.Command(os.Args[0], "sleeper")
		_ = c.Start()
		for i := 0; i < 300; i++ {
			if _, err := os.Stat("child.pid"); err == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		fmt.Fprintln(out, `{"v":1,"role":"mapper","name":"fake"}`)
	case "extra":
		fmt.Fprintln(out, `{"v":1,"role":"mapper","name":"fake","version":"1.0","future":{"a":1},"config_schema":"anything"}`)
	case "crashonce":
		fmt.Fprintln(out, `{"v":1,"role":"mapper","name":"fake"}`)
		if _, err := os.Stat("crashed"); err != nil {
			_ = os.WriteFile("crashed", nil, 0o644)
			flush()
			os.Exit(1)
		}
	default:
		fmt.Fprintln(out, `{"v":1,"role":"mapper","name":"fake"}`)
	}
	flush()

	in := bufio.NewReaderSize(os.Stdin, 1<<20)
	reqs := 0
	for {
		line, err := in.ReadBytes('\n')
		if err != nil {
			if mode == "ignoreeof" {
				time.Sleep(time.Minute) // a plugin that does not leave when asked politely
			}
			return
		}
		reqs++
		if mode == "logrequest" {
			appendLine("requests", strings.TrimRight(string(line), "\n"))
		}
		var req struct {
			ID     int64             `json:"id"`
			Config map[string]any    `json:"config"`
			Docs   []json.RawMessage `json:"docs"`
		}
		_ = json.Unmarshal(line, &req)
		n := len(req.Docs)

		events := make([]any, n)
		var unp []int
		for i, d := range req.Docs {
			var doc map[string]any
			_ = json.Unmarshal(d, &doc)
			if doc["bad"] == true {
				events[i] = nil
				unp = append(unp, i)
				continue
			}
			events[i] = map[string]any{"ts": "2026-01-02T03:04:05Z", "fields": map[string]any{"i": i, "req": reqs, "status": 401, "x": doc["x"], "cfg": req.Config["k"]}}
		}
		resp := map[string]any{"id": req.ID, "events": events, "unparsable": unp}

		switch mode {
		case "slow":
			time.Sleep(time.Minute)
		case "huge":
			fmt.Fprintf(out, `{"id":%d,"events":[],"pad":"%s"}`+"\n", req.ID, strings.Repeat("a", 6<<20))
			flush()
			continue
		case "unterminated":
			chunk := strings.Repeat("a", 1<<20)
			for i := 0; i < 8; i++ {
				fmt.Fprint(out, chunk)
				flush()
			}
			time.Sleep(time.Minute)
		case "badjson":
			fmt.Fprintln(out, "this is not json")
			flush()
			continue
		case "wrongcount":
			resp["events"] = events[:max(0, n-1)]
		case "nullskip":
			if n > 0 {
				events[0] = nil
			}
		case "doublecount":
			if n > 0 {
				resp["unparsable"] = []int{0, 0}
				events[0] = nil
			}
		case "eventandunparsable":
			if n > 0 {
				resp["unparsable"] = []int{0}
			}
		case "badts":
			if n > 0 {
				events[0] = map[string]any{"ts": "yesterday", "fields": map[string]any{}}
			}
		case "wrongid":
			resp["id"] = req.ID + 100
		case "errorresp":
			resp = map[string]any{"id": req.ID, "error": "boom password=hunter2hunter2 \x1b[31mred\x1b[0m"}
		case "crash":
			if reqs >= 2 {
				fmt.Fprint(out, `{"id":`)
				flush()
				os.Exit(3)
			}
		case "printenv":
			resp["events"] = []any{map[string]any{"ts": "2026-01-02T03:04:05Z", "fields": map[string]any{"env": os.Environ()}}}
			resp["unparsable"] = []int{}
		case "cwd":
			wd, _ := os.Getwd()
			resp["events"] = []any{map[string]any{"ts": "2026-01-02T03:04:05Z", "fields": map[string]any{"cwd": wd}}}
			resp["unparsable"] = []int{}
		case "stderrflood":
			chunk := strings.Repeat("x ", 512) + " token=" + strings.Repeat("S", 40) + "\n"
			for i := 0; i < 2048; i++ {
				fmt.Fprint(os.Stderr, chunk)
			}
			fmt.Fprint(os.Stderr, "LASTLINE deadbeefdeadbeefdeadbeefdeadbeefdeadbeef api_key=abc123 \x1b[1mbold\x1b[0m\n")
		case "extra":
			resp["future"] = map[string]any{"z": 1}
			for i, e := range events {
				if m, ok := e.(map[string]any); ok {
					m["extra_key"] = true
					events[i] = m
				}
			}
		}
		b, _ := json.Marshal(resp)
		out.Write(b)
		out.WriteByte('\n')
		flush()
	}
}
