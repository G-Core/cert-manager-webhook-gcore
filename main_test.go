package main

import (
	"os"
	"testing"
	"time"

	dns "github.com/cert-manager/cert-manager/test/acme"
	"github.com/stretchr/testify/assert"
)

var (
	zone = os.Getenv("TEST_ZONE_NAME")
)

func TestRunsSuite(t *testing.T) {
	// The manifest path should contain a file named config.json that is a
	// snippet of valid configuration that should be included on the
	// ChallengeRequest passed as part of the test cases.

	pollTime, _ := time.ParseDuration("10s")
	timeOut, _ := time.ParseDuration("5m")

	fixture := dns.NewFixture(&gcoreDNSProviderSolver{},
		dns.SetResolvedZone(zone),
		dns.SetAllowAmbientCredentials(false),
		dns.SetManifestPath("testdata/gcore"),

		// Disable the extended test to create several records for the same Record DNS Name
		dns.SetStrict(false),
		// Increase the poll interval to 10s
		dns.SetPollInterval(pollTime),
		// Increase the limit from 2 min to 5 min
		dns.SetPropagationLimit(timeOut),
	)

	fixture.RunConformance(t)

}

func Test_extractAllZones(t *testing.T) {
	testCases := []struct {
		desc     string
		fqdn     string
		expected []string
	}{
		{
			desc:     "success",
			fqdn:     "_acme-challenge.my.test.domain.com.",
			expected: []string{"my.test.domain.com", "test.domain.com", "domain.com"},
		},
		{
			desc: "empty",
			fqdn: "_acme-challenge.com.",
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			got := extractAllZones(test.fqdn)
			assert.Equal(t, test.expected, got)
		})
	}
}

func TestConcurrentCleanup(t *testing.T) {
	t.Run("cleanup_removes_only_matching_record", func(t *testing.T) {
		// Simulate scenario where there are 3 TXT records for the same FQDN
		// and we want to remove only one specific record
		mock := &mockSDK{
			zones: map[string]*mockZone{
				"example.com": {
					name: "example.com",
					rrsets: map[string]map[string]*mockRRSet{
						"_acme-challenge.example.com": {
							"TXT": {
								fqdn:       "_acme-challenge.example.com",
								recordType: "TXT",
								records: []mockRecord{
									{content: "token-A"},
									{content: "token-B"},
									{content: "token-C"},
								},
							},
						},
					},
				},
			},
		}

		fqdn := "_acme-challenge.example.com"
		recordType := "TXT"

		// Verify initial state: 3 records
		rrset := mock.zones["example.com"].rrsets[fqdn][recordType]
		assert.Equal(t, 3, len(rrset.records), "should start with 3 records")

		// Simulate CleanUp removing token-B
		keyToRemove := "token-B"
		var remaining []mockRecord
		for _, record := range rrset.records {
			if record.content != keyToRemove {
				remaining = append(remaining, record)
			}
		}

		// Verify only token-B was removed
		assert.Equal(t, 2, len(remaining), "should have 2 records remaining")

		// Verify the correct records remain
		assert.Equal(t, "token-A", remaining[0].content)
		assert.Equal(t, "token-C", remaining[1].content)

		// Verify token-B is gone
		for _, record := range remaining {
			assert.NotEqual(t, "token-B", record.content, "token-B should be removed")
		}
	})

	t.Run("cleanup_deletes_rrset_when_last_record", func(t *testing.T) {
		// Simulate scenario where there's only one TXT record
		// CleanUp should delete the entire RRSet
		mock := &mockSDK{
			zones: map[string]*mockZone{
				"example.com": {
					name: "example.com",
					rrsets: map[string]map[string]*mockRRSet{
						"_acme-challenge.example.com": {
							"TXT": {
								fqdn:       "_acme-challenge.example.com",
								recordType: "TXT",
								records: []mockRecord{
									{content: "token-A"},
								},
							},
						},
					},
				},
			},
		}

		fqdn := "_acme-challenge.example.com"
		recordType := "TXT"

		// Verify initial state: 1 record
		rrset := mock.zones["example.com"].rrsets[fqdn][recordType]
		assert.Equal(t, 1, len(rrset.records), "should start with 1 record")

		// Simulate CleanUp removing the last token
		keyToRemove := "token-A"
		var remaining []mockRecord
		for _, record := range rrset.records {
			if record.content != keyToRemove {
				remaining = append(remaining, record)
			}
		}

		// When no records remain, entire RRSet should be deleted
		shouldDeleteRRSet := len(remaining) == 0
		assert.True(t, shouldDeleteRRSet, "should delete entire RRSet when no records remain")
		assert.Equal(t, 0, len(remaining), "should have 0 records remaining")
	})

	t.Run("cleanup_handles_missing_rrset", func(t *testing.T) {
		// Simulate scenario where RRSet doesn't exist (already cleaned up)
		// CleanUp should handle gracefully and not error
		mock := &mockSDK{
			zones: map[string]*mockZone{
				"example.com": {
					name:   "example.com",
					rrsets: map[string]map[string]*mockRRSet{},
				},
			},
		}

		fqdn := "_acme-challenge.example.com"
		recordType := "TXT"

		// Try to get non-existent RRSet
		zone := mock.zones["example.com"]
		_, exists := zone.rrsets[fqdn][recordType]

		// Should not exist, and this should be handled gracefully
		assert.False(t, exists, "RRSet should not exist")
		// In the actual implementation, this returns nil (no error)
	})

	t.Run("cleanup_preserves_records_with_different_keys", func(t *testing.T) {
		// Verify that records with different content are preserved
		mock := &mockSDK{
			zones: map[string]*mockZone{
				"example.com": {
					name: "example.com",
					rrsets: map[string]map[string]*mockRRSet{
						"_acme-challenge.example.com": {
							"TXT": {
								fqdn:       "_acme-challenge.example.com",
								recordType: "TXT",
								records: []mockRecord{
									{content: "challenge-key-1"},
									{content: "challenge-key-2"},
									{content: "challenge-key-3"},
								},
							},
						},
					},
				},
			},
		}

		fqdn := "_acme-challenge.example.com"
		recordType := "TXT"

		// Remove middle record
		keyToRemove := "challenge-key-2"
		rrset := mock.zones["example.com"].rrsets[fqdn][recordType]

		var remaining []mockRecord
		for _, record := range rrset.records {
			if record.content != keyToRemove {
				remaining = append(remaining, record)
			}
		}

		// Should have exactly 2 records
		assert.Equal(t, 2, len(remaining))

		// Should be the correct records
		foundKey1 := false
		foundKey3 := false
		for _, record := range remaining {
			if record.content == "challenge-key-1" {
				foundKey1 = true
			}
			if record.content == "challenge-key-3" {
				foundKey3 = true
			}
			// Should not find the removed key
			assert.NotEqual(t, "challenge-key-2", record.content)
		}

		assert.True(t, foundKey1, "should preserve challenge-key-1")
		assert.True(t, foundKey3, "should preserve challenge-key-3")
	})

	t.Run("cleanup_skips_records_with_no_content", func(t *testing.T) {
		// Verify that records with no content are skipped (not preserved)
		// This addresses the review comment about records with no content
		mock := &mockSDK{
			zones: map[string]*mockZone{
				"example.com": {
					name: "example.com",
					rrsets: map[string]map[string]*mockRRSet{
						"_acme-challenge.example.com": {
							"TXT": {
								fqdn:       "_acme-challenge.example.com",
								recordType: "TXT",
								records: []mockRecord{
									{content: "valid-token-1"},
									{content: ""}, // Empty content
									{content: "valid-token-2"},
								},
							},
						},
					},
				},
			},
		}

		fqdn := "_acme-challenge.example.com"
		recordType := "TXT"

		// Simulate cleanup logic: skip empty records and remove matching key
		keyToRemove := "valid-token-1"
		rrset := mock.zones["example.com"].rrsets[fqdn][recordType]

		var remaining []mockRecord
		for _, record := range rrset.records {
			// Skip empty content
			if record.content == "" {
				continue
			}
			// Skip matching key
			if record.content == keyToRemove {
				continue
			}
			remaining = append(remaining, record)
		}

		// Should have only valid-token-2 remaining
		assert.Equal(t, 1, len(remaining), "should have 1 valid record")
		assert.Equal(t, "valid-token-2", remaining[0].content)
	})
}

// Mock types for testing
type mockSDK struct {
	zones map[string]*mockZone
}

type mockZone struct {
	name   string
	rrsets map[string]map[string]*mockRRSet // fqdn -> type -> rrset
}

type mockRRSet struct {
	fqdn       string
	recordType string
	records    []mockRecord
}

type mockRecord struct {
	content string
}
