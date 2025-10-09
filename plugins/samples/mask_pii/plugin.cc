// Copyright 2025 Google LLC
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
#include "proxy_wasm_intrinsics.h"
#include "re2/re2.h"

class MyRootContext : public RootContext {
 public:
  explicit MyRootContext(uint32_t id, std::string_view root_id)
      : RootContext(id, root_id) {}

  bool onConfigure(size_t) override {
    // Phone regex for format XXX-XXX-XXXX
    phone_regex.emplace("(\\d{3})-(\\d{3})-(\\d{4})");

    // Email regex - simple pattern for email matching
    email_regex.emplace("([a-zA-Z0-9._%+\\-]+)@([a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,})");

    // Email masking regex - captures first character separately
    email_mask_regex.emplace("([a-zA-Z0-9._%+\\-])[a-zA-Z0-9._%+\\-]*@([a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,})");

    return phone_regex->ok() && email_regex->ok() && email_mask_regex->ok();
  }

  std::optional<re2::RE2> phone_regex;
  std::optional<re2::RE2> email_regex;
  std::optional<re2::RE2> email_mask_regex;
};

class MyHttpContext : public Context {
 public:
  explicit MyHttpContext(uint32_t id, RootContext* root)
      : Context(id, root), root_(static_cast<MyRootContext*>(root)) {}

  FilterHeadersStatus onRequestHeaders(uint32_t headers, bool end_of_stream) override {
    const auto result = getRequestHeaderPairs();
    const auto pairs = result->pairs();
    bool changed = false;

    for (auto& p : pairs) {
      std::string header_value = std::string(p.second);
      bool header_changed = false;

      header_changed |= maskPhone(header_value);
      header_changed |= maskEmail(header_value);

      if (header_changed) {
        replaceRequestHeader(p.first, header_value);
        changed = true;
      }
    }

    return FilterHeadersStatus::Continue;
  }

  FilterHeadersStatus onResponseHeaders(uint32_t headers, bool end_of_stream) override {
    const auto result = getResponseHeaderPairs();
    const auto pairs = result->pairs();
    bool changed = false;

    for (auto& p : pairs) {
      std::string header_value = std::string(p.second);
      bool header_changed = false;

      header_changed |= maskPhone(header_value);
      header_changed |= maskEmail(header_value);

      if (header_changed) {
        replaceResponseHeader(p.first, header_value);
        changed = true;
      }
    }

    return FilterHeadersStatus::Continue;
  }

  FilterDataStatus onResponseBody(size_t body_buffer_length, bool end_of_stream) override {
    const auto body = getBufferBytes(WasmBufferType::HttpResponseBody, 0,
                                     body_buffer_length);
    std::string body_string = body->toString();

    bool changed = false;
    changed |= maskPhone(body_string);
    changed |= maskEmail(body_string);

    if (changed) {
      setBuffer(WasmBufferType::HttpResponseBody, 0, body_buffer_length,
                body_string);
    }

    return FilterDataStatus::Continue;
  }

 private:
  const MyRootContext* root_;

  // Masks phone numbers in the format XXX-XXX-XXXX, preserving the last 4 digits
  bool maskPhone(std::string& value) {
    return re2::RE2::GlobalReplace(&value, *root_->phone_regex, "XXX-XXX-\\3") > 0;
  }

  // Masks email addresses in the format x**@domain.com
  bool maskEmail(std::string& value) {
    return re2::RE2::GlobalReplace(&value, *root_->email_mask_regex, "\\1**@\\2") > 0;
  }
};

static RegisterContextFactory register_MaskPiiContext(
    CONTEXT_FACTORY(MyHttpContext), ROOT_FACTORY(MyRootContext));
// [END serviceextensions_plugin_mask_pii]