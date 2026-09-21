package httpraw

import (
	"testing"

	"jungle_happy_Scan/internal/config"
)

func TestParameterScopeExactMatchingAndDescriptions(t *testing.T) {
	req, err := Parse("POST /api/items?id=1&number=2 HTTP/1.1\r\nHost: bank.test\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nnumber=3&name=alice", "https")
	if err != nil {
		t.Fatal(err)
	}
	points := DiscoverAdvanced(req, config.Default())
	filtered := FilterInsertionPoints(points, []string{"[number]"})
	if len(filtered) != 2 {
		t.Fatalf("expected both query and form number points, got %#v", filtered)
	}
	if len(FilterInsertionPoints(points, []string{"id"})) != 1 || len(FilterInsertionPoints(points, []string{"id2"})) != 0 {
		t.Fatalf("scope must use exact matching: %#v", FilterInsertionPoints(points, []string{"id"}))
	}
	qualified := FilterInsertionPoints(points, []string{"query:number"})
	if len(qualified) != 1 || qualified[0].Location != "query" {
		t.Fatalf("location-qualified scope selected %#v", qualified)
	}
	descriptors := DescribeParameterPoints(points)
	if len(descriptors) != 4 || descriptors[0].Selector == "" {
		t.Fatalf("unexpected safe parameter descriptors: %#v", descriptors)
	}
	for _, item := range descriptors {
		if item.ValueType == "" {
			t.Fatalf("descriptor should preserve type metadata: %#v", item)
		}
	}
}

func TestNormalizeParameterScopeDeduplicatesBracketSelectors(t *testing.T) {
	got := NormalizeParameterScope([]string{"[number]\nquery:id", "number, [QUERY:ID]", ""})
	if len(got) != 2 || got[0] != "number" || got[1] != "query:id" {
		t.Fatalf("unexpected normalized scope: %#v", got)
	}
}

func TestParameterScopeMatchesNestedParentParameter(t *testing.T) {
	parent := InsertionPoint{Location: "form", Name: "cosp", Path: "cosp"}
	child := InsertionPoint{Location: "nested_xml", Name: "result", Path: "result", parent: &parent}
	if !MatchesParameterScope(child, []string{"cosp"}) {
		t.Fatal("outer form selector should include its nested XML point")
	}
}
