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
        Box::new(MyRootContext::new())
    });
}}

struct MyRootContext {
    phone_regex: Option<Rc<Regex>>,
    email_regex: Option<Rc<Regex>>,
}

impl MyRootContext {
    fn new() -> Self {
        MyRootContext {
            phone_regex: None,
            email_regex: None,
        }
    }
}

impl Context for MyRootContext {}

impl RootContext for MyRootContext {
    fn on_configure(&mut self, _config_size: usize) -> bool {
        // Phone regex for format XXX-XXX-XXXX
        let phone_regex = Regex::new(r"(\d{3})-(\d{3})-(\d{4})");
        if phone_regex.is_err() {
            log(LogLevel::Error, &format!("Failed to compile phone regex: {:?}", phone_regex.err()));
            return false;
        }

        // Email regex - captures username and domain parts separately
        let email_regex = Regex::new(r"([a-zA-Z0-9._%+\-]+)@([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})");
        if email_regex.is_err() {
            log(LogLevel::Error, &format!("Failed to compile email regex: {:?}", email_regex.err()));
            return false;
        }

        self.phone_regex = Some(Rc::new(phone_regex.unwrap()));
        self.email_regex = Some(Rc::new(email_regex.unwrap()));

        true
    }

    fn create_http_context(&self, context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(MyHttpContext::new(
            self.phone_regex.clone(),
            self.email_regex.clone(),
        )))
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
}

struct MyHttpContext {
    phone_regex: Option<Rc<Regex>>,
    email_regex: Option<Rc<Regex>>,
}

impl MyHttpContext {
    fn new(
        phone_regex: Option<Rc<Regex>>,
        email_regex: Option<Rc<Regex>>,
    ) -> Self {
        MyHttpContext {
            phone_regex,
            email_regex,
        }
    }

    /// Process headers with a uniform approach for both request and response
    fn process_headers(&mut self, is_request: bool) -> Action {
        // Get headers
        let headers = if is_request {
            self.get_http_request_headers()
        } else {
            self.get_http_response_headers()
        };

        let mut changed = false;
        let mut updated_headers = Vec::with_capacity(headers.len());

        // Process specific headers (x-phone, x-email) first
        let mut phone_header_value = String::new();
        let mut email_header_value = String::new();
        let mut has_phone_header = false;
        let mut has_email_header = false;

        for (name, value) in &headers {
            if name == "x-phone" {
                phone_header_value = value.clone();
                has_phone_header = true;
            } else if name == "x-email" {
                email_header_value = value.clone();
                has_email_header = true;
            }
        }

        // Mask x-phone if present
        if has_phone_header {
            let mut phone_value = phone_header_value;
            if self.mask_pii(&mut phone_value) {
                changed = true;
                if is_request {
                    self.set_http_request_header("x-phone", Some(&phone_value));
                } else {
                    self.set_http_response_header("x-phone", Some(&phone_value));
                }
            }
        }

        // Mask x-email if present
        if has_email_header {
            let mut email_value = email_header_value;
            if self.mask_pii(&mut email_value) {
                changed = true;
                if is_request {
                    self.set_http_request_header("x-email", Some(&email_value));
                } else {
                    self.set_http_response_header("x-email", Some(&email_value));
                }
            }
        }

        // Process all other headers for PII
        for (name, value) in headers {
            if name != "x-phone" && name != "x-email" {
                // Performance optimization: check if there's PII before processing
                if let (Some(ref phone_re), Some(ref email_re)) = (&self.phone_regex, &self.email_regex) {
                    if !phone_re.is_match(&value) && !email_re.is_match(&value) {
                        updated_headers.push((name, value));
                        continue;
                    }
                }

                // Process header value
                let mut new_value = value;
                if self.mask_pii(&mut new_value) {
                    changed = true;
                }
                updated_headers.push((name, new_value));
            }
        }

        // Update headers if any values changed
        if changed {
            let new_headers_refs: Vec<(&str, &str)> = updated_headers
                .iter()
                .map(|(n, v)| (n.as_str(), v.as_str()))
                .collect();

            if is_request {
                self.set_http_request_headers(new_headers_refs);
            } else {
                self.set_http_response_headers(new_headers_refs);
            }
        }

        Action::Continue
    }

    /// Mask PII (phone numbers and email addresses) in-place on a given string,
    /// returning `true` if modifications occurred.
    fn mask_pii(&self, text: &mut String) -> bool {
        let mut modified = false;

        // Mask phone numbers
        if let Some(ref phone_re) = self.phone_regex {
            let replaced = phone_re.replace_all(text, "XXX-XXX-$3");
            if replaced != Cow::Borrowed(text.as_str()) {
                *text = replaced.to_string();
                modified = true;
            }
        }

        // Mask email addresses
        if let Some(ref email_re) = self.email_regex {
            let replaced = email_re.replace_all(text, |caps: &regex::Captures| {
                let username = &caps[1];
                let domain = &caps[2];

                if !username.is_empty() {
                    // Keep first character of username, mask the rest with **
                    format!("{}**@{}", &username[0..1], domain)
                } else {
                    caps[0].to_string()
                }
            });

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
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        // Set Accept-Encoding to ensure uncompressed responses
        self.set_http_request_header("accept-encoding", Some("identity"));

        // Process request headers
        self.process_headers(true)
    }

    fn on_http_response_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        // Process response headers
        self.process_headers(false)
    }

    fn on_http_response_body(&mut self, body_size: usize, _end_of_stream: bool) -> Action {
        if body_size == 0 {
            return Action::Continue;
        }

        // Get response body
        if let Some(body_bytes) = self.get_http_response_body(0, body_size) {
            // Convert to string for processing, assuming UTF-8 encoding
            match String::from_utf8(body_bytes) {
                Ok(mut body_string) => {
                    // Mask PII in body
                    if self.mask_pii(&mut body_string) {
                        // Only update if changes were made
                        if let Err(err) = self.set_http_response_body(0, body_string.len(), body_string.as_bytes()) {
                            log(LogLevel::Error, &format!("Failed to replace response body: {:?}", err));
                        }
                    }
                }
                Err(err) => {
                    log(LogLevel::Error, &format!("Failed to convert body to string: {:?}", err));
                }
            }
        }

        Action::Continue
    }
}
// [END serviceextensions_plugin_mask_pii]