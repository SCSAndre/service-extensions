// Copyright 2024 Google LLC
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

// [START serviceextensions_plugin_mask_pii]
package main

import (
	"fmt"
	"regexp"

	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm"
	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm/types"
)

func main() {}
func init() {
	proxywasm.SetVMContext(&vmContext{})
}

type vmContext struct {
	types.DefaultVMContext
}

type pluginContext struct {
	types.DefaultPluginContext
	phoneRegex *regexp.Regexp
	emailRegex *regexp.Regexp
}

type httpContext struct {
	types.DefaultHttpContext
	phoneRegex *regexp.Regexp
	emailRegex *regexp.Regexp
}

func (*vmContext) NewPluginContext(contextID uint32) types.PluginContext {
	return &pluginContext{
		// Phone regex for format XXX-XXX-XXXX
		phoneRegex: regexp.MustCompile(`(\d{3})-(\d{3})-(\d{4})`),
		// Email regex - captures username and domain parts separately
		emailRegex: regexp.MustCompile(`([a-zA-Z0-9._%+\-]+)@([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})`),
	}
}

func (pluginContext *pluginContext) NewHttpContext(contextID uint32) types.HttpContext {
	return &httpContext{
		phoneRegex: pluginContext.phoneRegex,
		emailRegex: pluginContext.emailRegex,
	}
}

// Process request headers
func (ctx *httpContext) OnHttpRequestHeaders(numHeaders int, endOfStream bool) types.Action {
	defer func() {
		if err := recover(); err != nil {
			proxywasm.LogError(fmt.Sprintf("panic in OnHttpRequestHeaders: %v", err))
		}
	}()

	// Process x-phone and x-email headers
	phoneHeader, err := proxywasm.GetHttpRequestHeader("x-phone")
	if err == nil && phoneHeader != "" {
		maskedPhone := ctx.maskPhone(phoneHeader)
		proxywasm.ReplaceHttpRequestHeader("x-phone", maskedPhone)
	}

	emailHeader, err := proxywasm.GetHttpRequestHeader("x-email")
	if err == nil && emailHeader != "" {
		maskedEmail := ctx.maskEmail(emailHeader)
		proxywasm.ReplaceHttpRequestHeader("x-email", maskedEmail)
	}

	// Also scan all headers for PII
	headers, err := proxywasm.GetHttpRequestHeaders()
	if err == nil {
		for _, header := range headers {
			if header[0] != "x-phone" && header[0] != "x-email" {
				// Check if header value contains phone or email
				value := header[1]

				newValue := ctx.phoneRegex.ReplaceAllStringFunc(value, ctx.maskPhone)
				newValue = ctx.emailRegex.ReplaceAllStringFunc(newValue, ctx.maskEmail)

				if value != newValue {
					proxywasm.ReplaceHttpRequestHeader(header[0], newValue)
				}
			}
		}
	}

	return types.ActionContinue
}

// Process response headers
func (ctx *httpContext) OnHttpResponseHeaders(numHeaders int, endOfStream bool) types.Action {
	defer func() {
		if err := recover(); err != nil {
			proxywasm.LogError(fmt.Sprintf("panic in OnHttpResponseHeaders: %v", err))
		}
	}()

	// Process x-phone and x-email headers
	phoneHeader, err := proxywasm.GetHttpResponseHeader("x-phone")
	if err == nil && phoneHeader != "" {
		maskedPhone := ctx.maskPhone(phoneHeader)
		proxywasm.ReplaceHttpResponseHeader("x-phone", maskedPhone)
	}

	emailHeader, err := proxywasm.GetHttpResponseHeader("x-email")
	if err == nil && emailHeader != "" {
		maskedEmail := ctx.maskEmail(emailHeader)
		proxywasm.ReplaceHttpResponseHeader("x-email", maskedEmail)
	}

	// Also scan all headers for PII
	headers, err := proxywasm.GetHttpResponseHeaders()
	if err == nil {
		for _, header := range headers {
			if header[0] != "x-phone" && header[0] != "x-email" {
				// Check if header value contains phone or email
				value := header[1]

				newValue := ctx.phoneRegex.ReplaceAllStringFunc(value, ctx.maskPhone)
				newValue = ctx.emailRegex.ReplaceAllStringFunc(newValue, ctx.maskEmail)

				if value != newValue {
					proxywasm.ReplaceHttpResponseHeader(header[0], newValue)
				}
			}
		}
	}

	return types.ActionContinue
}

// Process response body
func (ctx *httpContext) OnHttpResponseBody(numBytes int, endOfStream bool) types.Action {
	defer func() {
		if err := recover(); err != nil {
			proxywasm.LogError(fmt.Sprintf("panic in OnHttpResponseBody: %v", err))
		}
	}()

	// Get the response body
	bodyBytes, err := proxywasm.GetHttpResponseBody(0, numBytes)
	if err != nil {
		proxywasm.LogError(fmt.Sprintf("failed to get response body: %v", err))
		return types.ActionContinue
	}

	// Convert to string for regex processing
	bodyStr := string(bodyBytes)

	// Apply masking to body content
	maskedBody := ctx.phoneRegex.ReplaceAllStringFunc(bodyStr, ctx.maskPhone)
	maskedBody = ctx.emailRegex.ReplaceAllStringFunc(maskedBody, ctx.maskEmail)

	// Only replace if changes were made
	if bodyStr != maskedBody {
		err = proxywasm.ReplaceHttpResponseBody([]byte(maskedBody))
		if err != nil {
			proxywasm.LogError(fmt.Sprintf("failed to replace response body: %v", err))
		}
	}

	return types.ActionContinue
}

// Phone masking function
func (ctx *httpContext) maskPhone(phone string) string {
	return ctx.phoneRegex.ReplaceAllString(phone, "XXX-XXX-$3")
}

// Email masking function
func (ctx *httpContext) maskEmail(email string) string {
	return ctx.emailRegex.ReplaceAllStringFunc(email, func(match string) string {
		parts := ctx.emailRegex.FindStringSubmatch(match)
		if len(parts) >= 3 {
			username := parts[1]
			domain := parts[2]

			if len(username) > 0 {
				firstChar := string(username[0])
				return firstChar + "**@" + domain
			}
		}
		return match // Return original if pattern doesn't match expectations
	})
}

// [END serviceextensions_plugin_mask_pii]
