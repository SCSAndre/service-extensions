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
	"regexp"
	"strings"

	extproc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"github.com/GoogleCloudPlatform/service-extensions/callouts/go/extproc/internal/server"
	"github.com/GoogleCloudPlatform/service-extensions/callouts/go/extproc/pkg/utils"
)

// MaskDataCalloutService is a gRPC service that handles masking PII data in headers.
type MaskDataCalloutService struct {
	server.GRPCCalloutService
}

// Regular expressions for phone numbers and emails
var (
	// Matches phone numbers in format XXX-XXX-XXXX
	phoneRegex = regexp.MustCompile(`\b(\d{3})-(\d{3})-(\d{4})\b`)

	// Matches email addresses
	emailRegex = regexp.MustCompile(`\b([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b`)
)

// NewExampleCalloutService creates a new instance of MaskDataCalloutService.
// Changed from NewMaskDataCalloutService to match the naming convention used in other examples.
func NewExampleCalloutService() *MaskDataCalloutService {
	service := &MaskDataCalloutService{}
	service.Handlers.RequestHeadersHandler = service.HandleRequestHeaders
	service.Handlers.ResponseHeadersHandler = service.HandleResponseHeaders
	return service
}

// HandleRequestHeaders handles incoming request headers and masks PII data.
func (s *MaskDataCalloutService) HandleRequestHeaders(headers *extproc.HttpHeaders) (*extproc.ProcessingResponse, error) {
	headerMutations := s.processHeaders(headers)

	return &extproc.ProcessingResponse{
		Response: &extproc.ProcessingResponse_RequestHeaders{
			RequestHeaders: utils.AddHeaderMutation(headerMutations, nil, false, nil),
		},
	}, nil
}

// HandleResponseHeaders handles outgoing response headers and masks PII data.
func (s *MaskDataCalloutService) HandleResponseHeaders(headers *extproc.HttpHeaders) (*extproc.ProcessingResponse, error) {
	headerMutations := s.processHeaders(headers)

	return &extproc.ProcessingResponse{
		Response: &extproc.ProcessingResponse_ResponseHeaders{
			ResponseHeaders: utils.AddHeaderMutation(headerMutations, nil, false, nil),
		},
	}, nil
}

// processHeaders examines all headers and masks PII data.
func (s *MaskDataCalloutService) processHeaders(headers *extproc.HttpHeaders) []struct{ Key, Value string } {
	var mutations []struct{ Key, Value string }

	// Extract headers from HeaderMap
	if headers.Headers == nil {
		return mutations
	}

	// Process each header entry
	for _, header := range headers.Headers.Headers {
		key := header.Key
		value := header.Value

		// Skip processing for headers we shouldn't modify
		if isProtectedHeader(key) {
			continue
		}

		// Process value to mask PII
		maskedValue := s.maskPII(value)

		// Only add to mutations if the value changed
		if value != maskedValue {
			mutations = append(mutations, struct{ Key, Value string }{
				Key:   key,
				Value: maskedValue,
			})
		}
	}

	return mutations
}

// maskPII applies masking to phone numbers and email addresses in a string.
func (s *MaskDataCalloutService) maskPII(input string) string {
	// Mask phone numbers (XXX-XXX-XXXX → XXX-XXX-XXXX, keeping last 4 digits)
	result := phoneRegex.ReplaceAllString(input, "XXX-XXX-$3")

	// Mask email addresses (user@domain.com → u**@domain.com)
	result = emailRegex.ReplaceAllStringFunc(result, func(email string) string {
		parts := emailRegex.FindStringSubmatch(email)
		if len(parts) < 3 {
			return email
		}

		username := parts[1]
		domain := parts[2]

		if len(username) > 0 {
			maskedUsername := string(username[0]) + "**"
			return maskedUsername + "@" + domain
		}

		return email
	})

	return result
}

// isProtectedHeader checks if a header should not be modified.
func isProtectedHeader(key string) bool {
	key = strings.ToLower(key)

	// Headers that shouldn't be modified as per documentation
	if strings.HasPrefix(key, "x-forwarded") ||
		strings.HasPrefix(key, "x-google") ||
		strings.HasPrefix(key, "x-gfe") ||
		strings.HasPrefix(key, "x-amz") {
		return true
	}

	// Other protected headers
	protectedHeaders := map[string]bool{
		"x-user-ip":           true,
		"cdn-loop":            true,
		"connection":          true,
		"keep-alive":          true,
		"transfer-encoding":   true,
		"te":                  true,
		"upgrade":             true,
		"proxy-connection":    true,
		"proxy-authenticate":  true,
		"proxy-authorization": true,
		"trailers":            true,
		":method":             true,
		":authority":          true,
		":scheme":             true,
		"host":                true,
	}

	return protectedHeaders[key]
}
