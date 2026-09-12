package assessment

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestReviewRequestMaxTokens(t *testing.T) {
	c, _ := localClient(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if string(body["max_tokens"]) != "1024" {
			t.Errorf("max_tokens=%s, want 1024", body["max_tokens"])
		}
		completion(w, validResult)
	})
	if _, err := c.Analyze(context.Background(), testInput()); err != nil {
		t.Fatal(err)
	}
}
