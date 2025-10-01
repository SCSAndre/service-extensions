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
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use regex::Regex;
use std::str;

#[no_mangle]
pub fn _start() {
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> { Box::new(MaskPiiRoot::default()) });
}

#[derive(Default)]
struct MaskPiiRoot;

impl Context for MaskPiiRoot {}

impl RootContext for MaskPiiRoot {
    fn create_http_context(&self, context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(MaskPiiHttp { context_id }))
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
}

struct MaskPiiHttp {
    context_id: u32,
}

impl MaskPiiHttp {
    // Masks phone numbers in format XXX-XXX-XXXX
    fn mask_phone(&self, phone: &str) -> String {
        let re = Regex::new(r"(\d{3})-(\d{3})-(\d{4})").unwrap();
        re.replace_all(phone, "XXX-XXX-$3").to_string()
    }

    // Masks email addresses in format x**@domain.com
    fn mask_email(&self, email: &str) -> String {
        let re = Regex::new(r"([a-zA-Z0-9._%+\-]+)@([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})").unwrap();
        re.replace_all(email, |caps: &regex::Captures| {
            let username = caps.get(1).map_or("", |m| m.as_str());
            let domain = caps.get(2).map_or("", |m| m.as_str());

            if let Some(first_char) = username.chars().next() {
                format!("{}**@{}", first_char, domain)
            } else {
                format!("@{}", domain)
            }
        }).to_string()
    }
}

impl Context for MaskPiiHttp {}

impl HttpContext for MaskPiiHttp {
    fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {
        // Process x-phone header
        if let Some(value) = self.get_http_request_header("x-phone") {
            let masked = self.mask_phone(&value);
            if masked != value {
                self.set_http_request_header("x-phone", Some(&masked));
            }
        }

        // Process x-email header
        if let Some(value) = self.get_http_request_header("x-email") {
            let masked = self.mask_email(&value);
            if masked != value {
                self.set_http_request_header("x-email", Some(&masked));
            }
        }

        // Process all other headers
        let headers = self.get_http_request_headers();
        for (name, value) in headers.iter() {
            if name != "x-phone" && name != "x-email" {
                let mut new_value = value.clone();
                let mut changed = false;

                // Check for phone numbers
                let phone_masked = self.mask_phone(&new_value);
                if phone_masked != new_value {
                    new_value = phone_masked;
                    changed = true;
                }

                // Check for email addresses
                let email_masked = self.mask_email(&new_value);
                if email_masked != new_value {
                    new_value = email_masked;
                    changed = true;
                }

                if changed {
                    self.set_http_request_header(name, Some(&new_value));
                }
            }
        }

        Action::Continue
    }

    fn on_http_response_headers(&mut self, _: usize, _: bool) -> Action {
        // Process x-phone header
        if let Some(value) = self.get_http_response_header("x-phone") {
            let masked = self.mask_phone(&value);
            if masked != value {
                self.set_http_response_header("x-phone", Some(&masked));
            }
        }

        // Process x-email header
        if let Some(value) = self.get_http_response_header("x-email") {
            let masked = self.mask_email(&value);
            if masked != value {
                self.set_http_response_header("x-email", Some(&masked));
            }
        }

        // Process all other headers
        let headers = self.get_http_response_headers();
        for (name, value) in headers.iter() {
            if name != "x-phone" && name != "x-email" {
                let mut new_value = value.clone();
                let mut changed = false;

                // Check for phone numbers
                let phone_masked = self.mask_phone(&new_value);
                if phone_masked != new_value {
                    new_value = phone_masked;
                    changed = true;
                }

                // Check for email addresses
                let email_masked = self.mask_email(&new_value);
                if email_masked != new_value {
                    new_value = email_masked;
                    changed = true;
                }

                if changed {
                    self.set_http_response_header(name, Some(&new_value));
                }
            }
        }

        Action::Continue
    }

    fn on_http_response_body(&mut self, body_size: usize, end_of_stream: bool) -> Action {
        if !end_of_stream {
            return Action::Pause;
        }

        if let Some(body_bytes) = self.get_http_response_body(0, body_size) {
            if let Ok(body_string) = str::from_utf8(&body_bytes) {
                let mut masked_body = self.mask_phone(body_string);
                masked_body = self.mask_email(&masked_body);

                if masked_body != body_string {
                    self.set_http_response_body(0, body_size, masked_body.as_bytes());
                }
            }
        }

        Action::Continue
    }
}
// [END serviceextensions_plugin_mask_pii]
