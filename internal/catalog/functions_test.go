package catalog

import "testing"

func TestHasPinnedSearchPath(t *testing.T) {
	tests := []struct {
		name   string
		config []string
		want   bool
	}{
		{"no config", nil, false},
		{"empty config", []string{}, false},
		{"other settings only", []string{"work_mem=64MB"}, false},
		{"search_path set", []string{"search_path=public, pg_temp"}, true},
		{"search_path among others", []string{"work_mem=64MB", "search_path=app"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasPinnedSearchPath(tt.config)
			if got != tt.want {
				t.Errorf("hasPinnedSearchPath(%v) = %v, want %v", tt.config, got, tt.want)
			}
		})
	}
}
