package plugin

import (
	"context"
	"errors"
	"testing"

	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

func TestRequestCohortReservesAtomicallyAndReturnsUnusedSlots(t *testing.T) {
	request, err := httpraw.Parse("GET / HTTP/1.1\r\nHost: bank.test\r\n\r\n", "https")
	if err != nil {
		t.Fatal(err)
	}
	sends := 0
	resolved := 0
	ctx := &Context{
		Context: context.Background(), RequestBudget: 4,
		SendFunc: func(context.Context, *httpraw.Request) (model.Response, error) {
			sends++
			return model.Response{StatusCode: 200}, nil
		},
		OnResolution: func(kind string, count int) {
			if kind == "budget_skipped" {
				resolved += count
			}
		},
	}
	cohort, err := ctx.ReserveCohort(4)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ctx.Send(request); !errors.Is(err, ErrPluginBudgetExhausted) {
		t.Fatalf("a direct request split an already-reserved cohort: %v", err)
	}
	if sends != 0 {
		t.Fatalf("request was sent across a reservation boundary: %d", sends)
	}
	if _, err := cohort.Send(request); err != nil {
		t.Fatal(err)
	}
	cohort.Close() // Three unsent reservations must be returned.

	second, err := ctx.ReserveCohort(3)
	if err != nil {
		t.Fatalf("unused cohort slots were not returned: %v", err)
	}
	for index := 0; index < 3; index++ {
		if _, err := second.Send(request); err != nil {
			t.Fatal(err)
		}
	}
	second.Close()
	if used, exhausted := ctx.BudgetState(); used != 4 || !exhausted {
		t.Fatalf("unexpected final budget state: used=%d exhausted=%t", used, exhausted)
	}
	if sends != 4 || resolved != 0 {
		t.Fatalf("unexpected sends/resolutions: sends=%d resolved=%d", sends, resolved)
	}
}

func TestRequestCohortRejectsWholeGroupWhenBudgetIsInsufficient(t *testing.T) {
	resolved := 0
	ctx := &Context{
		Context: context.Background(), RequestBudget: 3,
		SendFunc: func(context.Context, *httpraw.Request) (model.Response, error) {
			t.Fatal("an incomplete cohort must not send")
			return model.Response{}, nil
		},
		OnResolution: func(kind string, count int) {
			if kind == "budget_skipped" {
				resolved += count
			}
		},
	}
	if _, err := ctx.ReserveCohort(4); !errors.Is(err, ErrPluginBudgetExhausted) {
		t.Fatalf("expected atomic budget rejection, got %v", err)
	}
	if used, exhausted := ctx.BudgetState(); used != 0 || !exhausted {
		t.Fatalf("unexpected budget state: used=%d exhausted=%t", used, exhausted)
	}
	if resolved != 4 {
		t.Fatalf("rejected cohort did not resolve four budget-skipped slots: %d", resolved)
	}
}
