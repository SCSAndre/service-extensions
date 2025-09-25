// Copyright 2024 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mask_data

import (
	"testing"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extproc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/stretchr/testify/assert"
)

func TestMaskPhone(t *testing.T) {
	// Atualizado para usar NewExampleCalloutService em vez de NewMaskDataCalloutService
	service := NewExampleCalloutService()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Standard phone format",
			input:    "555-987-6543",
			expected: "XXX-XXX-6543",
		},
		{
			name:     "Phone in text",
			input:    "My number is 123-456-7890 call me",
			expected: "My number is XXX-XXX-7890 call me",
		},
		{
			name:     "Multiple phone numbers",
			input:    "First: 111-222-3333, Second: 444-555-6666",
			expected: "First: XXX-XXX-3333, Second: XXX-XXX-6666",
		},
		{
			name:     "No phone numbers",
			input:    "No phone numbers here",
			expected: "No phone numbers here",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := service.maskPII(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestMaskEmail(t *testing.T) {
	// Atualizado para usar NewExampleCalloutService em vez de NewMaskDataCalloutService
	service := NewExampleCalloutService()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Standard email",
			input:    "alice.smith@example.org",
			expected: "a**@example.org",
		},
		{
			name:     "Email in text",
			input:    "Contact me at john.doe@gmail.com for details",
			expected: "Contact me at j**@gmail.com for details",
		},
		{
			name:     "Multiple emails",
			input:    "Primary: user1@domain.com Secondary: user2@test.org",
			expected: "Primary: u**@domain.com Secondary: u**@test.org",
		},
		{
			name:     "No emails",
			input:    "No email addresses here",
			expected: "No email addresses here",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := service.maskPII(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestHandleRequestHeaders(t *testing.T) {
	// Atualizado para usar NewExampleCalloutService em vez de NewMaskDataCalloutService
	service := NewExampleCalloutService()

	// Create test headers with PII data
	headers := &extproc.HttpHeaders{
		Headers: &core.HeaderMap{
			Headers: []*core.HeaderValue{
				{Key: "x-phone", Value: "555-987-6543"},
				{Key: "x-email", Value: "alice.smith@example.org"},
				{Key: "content-type", Value: "application/json"},
			},
		},
	}

	response, err := service.HandleRequestHeaders(headers)
	assert.NoError(t, err)

	requestHeaders := response.GetRequestHeaders()
	assert.NotNil(t, requestHeaders)

	headerMutations := requestHeaders.Response.HeaderMutation
	assert.NotNil(t, headerMutations)

	// Verify that PII headers were masked
	var foundPhone, foundEmail bool

	for _, header := range headerMutations.SetHeaders {
		if header.Header.Key == "x-phone" {
			foundPhone = true
			assert.Equal(t, "XXX-XXX-6543", string(header.Header.RawValue))
		}

		if header.Header.Key == "x-email" {
			foundEmail = true
			assert.Equal(t, "a**@example.org", string(header.Header.RawValue))
		}
	}

	assert.True(t, foundPhone, "Expected x-phone header mutation not found")
	assert.True(t, foundEmail, "Expected x-email header mutation not found")
}

func TestHandleResponseHeaders(t *testing.T) {
	// Atualizado para usar NewExampleCalloutService em vez de NewMaskDataCalloutService
	service := NewExampleCalloutService()

	// Create test headers with PII data
	headers := &extproc.HttpHeaders{
		Headers: &core.HeaderMap{
			Headers: []*core.HeaderValue{
				{Key: "x-phone", Value: "555-987-6543"},
				{Key: "x-email", Value: "alice.smith@example.org"},
				{Key: "content-type", Value: "application/json"},
			},
		},
	}

	response, err := service.HandleResponseHeaders(headers)
	assert.NoError(t, err)

	responseHeaders := response.GetResponseHeaders()
	assert.NotNil(t, responseHeaders)

	headerMutations := responseHeaders.Response.HeaderMutation
	assert.NotNil(t, headerMutations)

	// Verify that PII headers were masked
	var foundPhone, foundEmail bool

	for _, header := range headerMutations.SetHeaders {
		if header.Header.Key == "x-phone" {
			foundPhone = true
			assert.Equal(t, "XXX-XXX-6543", string(header.Header.RawValue))
		}

		if header.Header.Key == "x-email" {
			foundEmail = true
			assert.Equal(t, "a**@example.org", string(header.Header.RawValue))
		}
	}

	assert.True(t, foundPhone, "Expected x-phone header mutation not found")
	assert.True(t, foundEmail, "Expected x-email header mutation not found")
}

func TestProtectedHeaders(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		expected bool
	}{
		{
			name:     "Protected x-forwarded header",
			header:   "x-forwarded-for",
			expected: true,
		},
		{
			name:     "Protected x-google header",
			header:   "x-google-service",
			expected: true,
		},
		{
			name:     "Protected host header",
			header:   "host",
			expected: true,
		},
		{
			name:     "Regular header",
			header:   "x-phone",
			expected: false,
		},
		{
			name:     "Case insensitive check",
			header:   "X-Forwarded-For",
			expected: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := isProtectedHeader(tc.header)
			assert.Equal(t, tc.expected, result)
		})
	}
}
