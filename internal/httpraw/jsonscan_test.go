package httpraw

import (
	"bytes"
	"testing"
)

func TestJSONMutationPreservesUnrelatedBytesAndLargeInteger(t *testing.T) {
	body := []byte("{\n  \"id\": 900719925474099312345, \"nested\": [{\"name\" : \"old\"}], \"keep\":1e+09\n}")
	request := &Request{Method: "POST", Target: "/", Body: body, Headers: []Header{{Name: "Content-Type", Value: "application/json"}}}
	points := Discover(request, false)
	var target InsertionPoint
	for _, point := range points {
		if point.Path == "nested[0].name" {
			target = point
		}
	}
	mutated, err := Mutate(request, target, "new'")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(mutated.Body, []byte(`900719925474099312345`)) || !bytes.Contains(mutated.Body, []byte(`"keep":1e+09`)) || !bytes.Contains(mutated.Body, []byte(`"name" : "new'"`)) {
		t.Fatalf("unrelated JSON bytes changed: %s", mutated.Body)
	}
}

func TestJSONArrayNestedPoints(t *testing.T) {
	request := &Request{Method: "POST", Target: "/", Body: []byte(`[{"items":[{"id":1},{"id":2}]}]`), Headers: []Header{{Name: "Content-Type", Value: "application/json"}}}
	points := Discover(request, false)
	if len(points) != 2 || points[0].Path != "[0].items[0].id" || points[1].Path != "[0].items[1].id" {
		t.Fatalf("unexpected paths: %#v", points)
	}
}
