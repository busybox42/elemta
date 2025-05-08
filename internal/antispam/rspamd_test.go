package antispam

import (
	"context"
	"strings"
	"testing"
)

func TestRspamdScanner_GTUBE(t *testing.T) {
	// Create a new Rspamd scanner with minimal config
	config := Config{
		Type:      "rspamd",
		Address:   "http://localhost:11333",
		Threshold: 5.0,
	}
	scanner := NewRspamd(config)
	scanner.connected = true // Bypass connection check

	// Test cases
	tests := []struct {
		name           string
		data           string
		expectClean    bool
		expectContains string
	}{
		{
			name:           "Clean message",
			data:           "This is a clean message without any spam patterns.",
			expectClean:    true,
			expectContains: "",
		},
		{
			name:           "Message with GTUBE pattern",
			data:           "This message contains the GTUBE pattern: XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X",
			expectClean:    false,
			expectContains: "GTUBE",
		},
		{
			name:           "Spam keywords",
			data:           "VIAGRA FREE!!! Click here to buy now! This is guaranteed to work.",
			expectClean:    false,
			expectContains: "SPAM",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := scanner.ScanBytes(context.Background(), []byte(tc.data))
			if err != nil {
				t.Fatalf("ScanBytes error: %v", err)
			}

			if result.Clean != tc.expectClean {
				t.Errorf("Expected Clean=%v, got Clean=%v", tc.expectClean, result.Clean)
			}

			if !tc.expectClean && tc.expectContains != "" {
				rulesStr := strings.Join(result.Rules, " ")
				if !strings.Contains(rulesStr, tc.expectContains) {
					t.Errorf("Expected rules to contain '%s', got rules: %v", tc.expectContains, result.Rules)
				}
			}

			// For debugging
			t.Logf("Result: Clean=%v, Score=%.2f, Rules=%v", result.Clean, result.Score, result.Rules)
		})
	}
}

func TestRspamdScanner_calculateSpamScore(t *testing.T) {
	tests := []struct {
		name          string
		content       string
		expectedScore float64
		threshold     float64
	}{
		{
			name:          "Clean message",
			content:       "This is a clean message without any spam patterns.",
			expectedScore: 0.0,
			threshold:     5.0,
		},
		{
			name:          "Low spam score",
			content:       "This message contains the word free but is otherwise clean.",
			expectedScore: 1.0, // "free" gives 1.0
			threshold:     5.0,
		},
		{
			name:          "High spam score",
			content:       "Viagra and Cialis for sale! Buy now! Free shipping!!!",
			expectedScore: 15.0, // "viagra" (5.0) + "cialis" (5.0) + "free" (1.0) + "buy now" (3.0) + "!!!" (1.0)
			threshold:     5.0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			score := calculateSpamScore(tc.content)
			if score < tc.expectedScore-0.1 || score > tc.expectedScore+0.1 {
				t.Errorf("Expected score around %.2f, got %.2f", tc.expectedScore, score)
			}

			// Test if the score would be classified correctly against the threshold
			config := Config{
				Type:      "rspamd",
				Threshold: tc.threshold,
			}
			scanner := NewRspamd(config)
			scanner.connected = true

			result, err := scanner.ScanBytes(context.Background(), []byte(tc.content))
			if err != nil {
				t.Fatalf("ScanBytes error: %v", err)
			}

			expectedClean := tc.expectedScore < tc.threshold
			if result.Clean != expectedClean {
				t.Errorf("Expected Clean=%v, got Clean=%v with score %.2f", expectedClean, result.Clean, result.Score)
			}
		})
	}
}
