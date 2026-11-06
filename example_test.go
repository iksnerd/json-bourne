package jb_test

import (
	"context"
	"fmt"
	"time"

	jb "github.com/iksnerd/json-bourne"
)

// Hunt the last hour. A nil error is not a clean result: check Complete.
func ExampleHunt() {
	cfg, err := jb.LoadConfig("jb.yaml")
	if err != nil {
		fmt.Println(err)
		return
	}
	res, err := jb.Hunt(context.Background(), cfg, jb.HuntOptions{Window: time.Hour})
	if err != nil {
		fmt.Println(err)
		return
	}
	if !res.Complete() {
		fmt.Println("not a clean result:", res.Failed())
		return
	}
	for _, f := range res.Findings {
		fmt.Println(f.Tag)
	}
}
