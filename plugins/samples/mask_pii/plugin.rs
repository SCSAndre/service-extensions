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
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use regex::Regex;
use std::borrow::Cow;
use std::rc::Rc;

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(MyRootContext::default())
    });
}}

struct MyRootContext {
    phone_matcher: Option<Rc<Regex>>,
    email_matcher: Option<Rc<Regex>>,
}

impl Context for MyRootContext {}

impl RootContext for MyRootContext {
    fn on_configure(&mut self, _: usize) -> bool {
        // Compile regex patterns once during configuration
        match Regex::new(r"(\d{3})-(\d{3})-(\d{4})") {
            Ok(re) => self.phone_matcher = Some(Rc::new(re)),
            Err(_) => return false,
        }

        match Regex::new(r"([a-zA-Z0-9._%+\-])[a-zA-Z0-9._%+\-]*@([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})") {
            Ok(re) => self.email_matcher = Some(Rc::new(re)),
            Err(_) => return false,
        }

        true
    }

    fn create_http_context(&self, _: u32) -> Option<Box<dyn HttpContext>> {
        // Pass the compiled regex patterns to the HTTP context
        let phone_matcher = self.phone_matcher.as_ref().map(Rc::clone);
        let email_matcher = self.email_matcher.as_ref().map(Rc::clone);

        Some(Box::new(MyHttpContext {
            phone_matcher,
            email_matcher,
        }))
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
}

struct MyHttpContext {
    phone_matcher: Option<Rc<Regex>>,
    email_matcher: Option<Rc<Regex>>,
}

impl MyHttpContext {
    // Mask PII in text using pre-compiled regex patterns
    fn mask_pii(&self, text: &mut String) -> bool {
        let mut modified = false;

        if let Some(ref phone_re) = self.phone_matcher {
            let replaced = phone_re.replace_all(text, "XXX-XXX-$3");
            if replaced != Cow::Borrowed(text.as_str()) {
                *text = replaced.to_string();
                modified = true;
            }
        }

        if let Some(ref email_re) = self.email_matcher {
            let replaced = email_re.replace_all(text, "$1**@$2");
            if replaced != Cow::Borrowed(text.as_str()) {
                *text = replaced.to_string();
                modified = true;
            }
        }

        modified
    }
}

impl Context for MyHttpContext {}

impl HttpContext for MyHttpContext {
    fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {
        // Set Accept-Encoding to ensure uncompressed responses
        self.set_http_request_header("accept-encoding", Some("identity"));

        // Get all headers at once
        let old_headers = self.get_http_request_headers();
        let mut changed = false;
        let mut updated_headers = Vec::with_capacity(old_headers.len());

        // Process each header uniformly
        for (name, value) in old_headers {
            let mut new_value = value;
            if self.mask_pii(&mut new_value) {
                changed = true;
            }
            updated_headers.push((name, new_value));
        }

        // Only update if any headers were changed
        if changed {
            let new_headers_refs: Vec<(&str, &str)> = updated_headers
                .iter()
                .map(|(n, v)| (n.as_str(), v.as_str()))
                .collect();
            self.set_http_request_headers(new_headers_refs);
        }

        Action::Continue
    }

    fn on_http_response_headers(&mut self, _: usize, _: bool) -> Action {
        // Get all headers at once
        let old_headers = self.get_http_response_headers();
        let mut changed = false;
        let mut updated_headers = Vec::with_capacity(old_headers.len());

        // Process each header uniformly
        for (name, value) in old_headers {
            let mut new_value = value;
            if self.mask_pii(&mut new_value) {
                changed = true;
            }
            updated_headers.push((name, new_value));
        }

        // Only update if any headers were changed
        if changed {
            let new_headers_refs: Vec<(&str, &str)> = updated_headers
                .iter()
                .map(|(n, v)| (n.as_str(), v.as_str()))
                .collect();
            self.set_http_response_headers(new_headers_refs);
        }

        Action::Continue
    }

    fn on_http_response_body(&mut self, body_size: usize, _: bool) -> Action {
        if body_size == 0 {
            return Action::Continue;
        }

        // Get response body
        if let Some(body_bytes) = self.get_http_response_body(0, body_size) {
            // Use lossy conversion for UTF-8 - more robust than unwrapping
            let mut body_string = String::from_utf8_lossy(&body_bytes).to_string();

            // Process the body
            if self.mask_pii(&mut body_string) {
                // Use original body_size, not body_string.len()!
                self.set_http_response_body(0, body_size, body_string.as_bytes());
            }
        }

        Action::Continue
    }
}
// [END serviceextensions_plugin_mask_pii]
