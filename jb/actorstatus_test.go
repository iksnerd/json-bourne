package jb

import (
	"context"
	"encoding/json"
	"iter"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/adapters/duckdb"
	"github.com/iksnerd/json-bourne/internal/core"
)

const actorUA = "ExampleBrowser/9.1 (Plan9; Win64; x64) InventedKit/537.36 (like Gecko) Chrome/9.1.0.0 Safari/537.36"

var actorT0 = time.Date(2026, 11, 5, 11, 0, 0, 0, time.UTC)

// seedStore creates the case's evidence store and saves evs in it (none: an empty store).
func seedStore(t *testing.T, dir string, evs ...core.Event) {
	t.Helper()
	st, err := duckdb.OpenContext(context.Background(), filepath.Join(dir, "evidence", "jb.duckdb"), false, duckdb.OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.Migrate(); err != nil {
		t.Fatal(err)
	}
	if len(evs) == 0 {
		return
	}
	if err := st.SaveEvents(context.Background(), "seed", iter.Seq2[core.Event, error](dbSeq(evs))); err != nil {
		t.Fatal(err)
	}
}

func webEvent(at time.Time, ua, path string) core.Event {
	return core.Event{Time: at, Source: "kibana:logs-http-*", Kind: "http", Fields: map[string]any{
		"user_agent": ua, "path": path, "status": 200, "client_ip": "203.0.113.11", "method": "GET"}}
}

func TestActorStatusReportsTheLastGenuineMatch(t *testing.T) {
	dir := copyCase(t)
	seedStore(t, dir,
		webEvent(actorT0.Add(5*time.Minute), actorUA, "/login"),
		webEvent(actorT0.Add(20*time.Minute), actorUA, "/wp-login.php"), // newer, but noise
		webEvent(actorT0.Add(9*time.Minute), "OtherClient/1.0", "/login"),
	)
	r, err := ActorStatus(context.Background(), dir, ActorStatusOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Events != 3 || len(r.Actors) != 1 || !r.Complete() {
		t.Fatalf("result = %+v", r)
	}
	a := r.Actors[0]
	if a.Actor != "actor-a" || a.UserAgent != actorUA || a.LastGenuine == nil || !a.LastGenuine.Equal(actorT0.Add(5*time.Minute)) || a.Noise != 1 {
		t.Errorf("actor = %+v", a)
	}
	out, _ := json.Marshal(r)
	for _, k := range []string{`"store":`, `"store_events":3`, `"store_from":`, `"store_to":`, `"actors":[`, `"last_genuine":`, `"examined":`} {
		if !strings.Contains(string(out), k) {
			t.Errorf("JSON lacks %s: %s", k, out)
		}
	}
}

func TestActorStatusRefusesWhatCannotBeAnswered(t *testing.T) {
	ctx := context.Background()
	if _, err := ActorStatus(ctx, "", ActorStatusOptions{}); !IsUsage(err) {
		t.Errorf("empty case dir: %v", err)
	}
	dir := copyCase(t)
	if _, err := ActorStatus(ctx, dir, ActorStatusOptions{Config: "config/none.yaml"}); err == nil {
		t.Error("a config that is not the case's was accepted")
	}
	seedStore(t, dir) // no events at all
	if _, err := ActorStatus(ctx, dir, ActorStatusOptions{}); err == nil {
		t.Error("an empty store must be an error, not never matched")
	}
}

func TestActorStatusResultIsIncompleteWhenAScanWasCapped(t *testing.T) {
	r := ActorStatusResult{Actors: []ActorMatch{{Actor: "a"}, {Actor: "b", Capped: true}}}
	if r.Complete() {
		t.Error("a capped scan gave no date, the result cannot be complete")
	}
	if !(&ActorStatusResult{}).Complete() {
		t.Error("no capped row is complete")
	}
}
