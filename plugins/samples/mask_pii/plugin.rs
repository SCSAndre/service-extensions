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
use std::rc::Rc;

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(PiiMaskingRoot::default())
    });
}}

#[derive(Default)]
struct PiiMaskingRoot {
    phone_matcher: Option<Rc<Regex>>,
    email_matcher: Option<Rc<Regex>>,
}

impl Context for PiiMaskingRoot {}

impl RootContext for PiiMaskingRoot {
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

        Some(Box::new(PiiMaskingHttp {
            phone_matcher,
            email_matcher,
        }))
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
}

struct PiiMaskingHttp {
    phone_matcher: Option<Rc<Regex>>,
    email_matcher: Option<Rc<Regex>>,
}

impl PiiMaskingHttp {
    // Mask phone numbers using pre-compiled regex
    fn mask_phone(&self, text: &str) -> String {
        if let Some(re) = &self.phone_matcher {
            re.replace_all(text, "XXX-XXX-$3").to_string()
        } else {
            text.to_string()
        }
    }

    // Mask email addresses using pre-compiled regex
    fn mask_email(&self, text: &str) -> String {
        if let Some(re) = &self.email_matcher {
            re.replace_all(text, "$1**@$2").to_string()
        } else {
            text.to_string()
        }
    }

    // Process text by applying all PII masking operations
    fn process_text(&self, text: &str) -> String {
        let mut result = text.to_string();
        result = self.mask_phone(&result);
        result = self.mask_email(&result);
        result
    }
}

impl Context for PiiMaskingHttp {}

impl HttpContext for PiiMaskingHttp {
    fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {
        // Set Accept-Encoding to ensure uncompressed responses
        self.set_http_request_header("accept-encoding", Some("identity"));

        // Get all headers at once
        let headers = self.get_http_request_headers();

        // Process each header uniformly
        for (name, value) in headers {
            let masked_value = self.process_text(&value);

            // Only update if changed
            if masked_value != value {
                self.set_http_request_header(&name, Some(&masked_value));
            }
        }

        Action::Continue
    }

    fn on_http_response_headers(&mut self, _: usize, _: bool) -> Action {
        // Get all headers at once
        let headers = self.get_http_response_headers();

        // Process each header uniformly
        for (name, value) in headers {
            let masked_value = self.process_text(&value);

            // Only update if changed
            if masked_value != value {
                self.set_http_response_header(&name, Some(&masked_value));
            }
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
            let body_str = String::from_utf8_lossy(&body_bytes);

            // Process the body
            let masked_body = self.process_text(&body_str);

            // Only update if changed, using ORIGINAL body_size
            if masked_body != body_str {
                self.set_http_response_body(0, body_size, masked_body.as_bytes());
            }
        }

        Action::Continue
    }
}
// [END serviceextensions_plugin_mask_pii]