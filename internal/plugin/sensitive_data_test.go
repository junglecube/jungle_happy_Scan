package plugin

import "testing"

func TestValidCNIDRequiresSupportedBirthDateAndChecksum(t *testing.T) {
	valid := "11010519491231002X"
	for _, tc := range []struct {
		name  string
		value string
		want  bool
	}{
		{"valid", valid, true},
		{"year before 1900", "11010518991231002X", false},
		{"year after 2030", "11010520311231002X", false},
		{"invalid date", "11010520010229002X", false},
		{"invalid checksum", "11010519491231002A", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := validCNID(tc.value); got != tc.want {
				t.Fatalf("validCNID(%q) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

func TestLuhnRequiresDomesticCardShape(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
		want  bool
	}{
		{"common domestic BIN", "6222021234567894", true},
		{"too short", "622202123456789", false},
		{"too long", "62220212345678941234", false},
		{"repeated digits", "6666666666666666", false},
		{"bad checksum", "6222021234567895", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := luhn(tc.value); got != tc.want {
				t.Fatalf("luhn(%q) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}
