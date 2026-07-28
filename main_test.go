package main

import (
	"reflect"
	"testing"
)

func TestParseCommaSeparatedList(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
		want  []string
	}{
		{
			name:  "values without whitespace",
			value: "192.0.2.1,198.51.100.2",
			want:  []string{"192.0.2.1", "198.51.100.2"},
		},
		{
			name:  "spaces after commas",
			value: "192.0.2.1, 198.51.100.2",
			want:  []string{"192.0.2.1", "198.51.100.2"},
		},
		{
			name:  "surrounding whitespace",
			value: "  example.test,\tapi.example.test \n",
			want:  []string{"example.test", "api.example.test"},
		},
		{
			name:  "empty entries",
			value: "192.0.2.1, ,198.51.100.2,",
			want:  []string{"192.0.2.1", "198.51.100.2"},
		},
		{
			name:  "empty value",
			value: "",
			want:  nil,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := parseCommaSeparatedList(tt.value); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("parseCommaSeparatedList(%q) = %#v, want %#v", tt.value, got, tt.want)
			}
		})
	}
}
