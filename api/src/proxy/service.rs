use axum::{
    Router,
    body::Body,
    extract::Request,
    http::{StatusCode, Method},
    response::Response,
    routing::{get, post, put, delete},
};
use futures_util::StreamExt;
use reqwest::Client;
use tracing::{error, info, warn};

use std::collections::HashMap;
use crate::{get_amp_api_key, get_google_api_key};
use super::config::{ProxyConfig, EndpointConfig};

pub struct ProxyService {
    config: ProxyConfig,
}

impl ProxyService {
    pub fn new(config: ProxyConfig) -> Self {
        Self {
            config,
        }
    }

    pub fn create_router(&self) -> Router {
        let mut router = Router::new();

        for endpoint in self.config.enabled_endpoints() {
            let endpoint_clone = endpoint.clone();
            let path = endpoint.path.clone();

            let method = endpoint.method.to_uppercase();
            let has_wildcard = path.contains("{*");

            match method.as_str() {
                "GET" => {
                    if has_wildcard {
                        router = router.route(&path, get(move |axum::extract::Path(rest): axum::extract::Path<String>, req| {
                            let mut params = HashMap::new();
                            params.insert("rest".to_string(), rest);
                            Self::handle_proxy_request_with_params(endpoint_clone, params, req)
                        }));
                    } else {
                        router = router.route(&path, get(move |req| {
                            Self::handle_proxy_request(endpoint_clone, req)
                        }));
                    }
                }
                "POST" => {
                    if has_wildcard {
                        router = router.route(&path, post(move |axum::extract::Path(rest): axum::extract::Path<String>, req| {
                            let mut params = HashMap::new();
                            params.insert("rest".to_string(), rest);
                            Self::handle_proxy_request_with_params(endpoint_clone, params, req)
                        }));
                    } else {
                        router = router.route(&path, post(move |req| {
                            Self::handle_proxy_request(endpoint_clone, req)
                        }));
                    }
                }
                "PUT" => {
                    if has_wildcard {
                        router = router.route(&path, put(move |axum::extract::Path(rest): axum::extract::Path<String>, req| {
                            let mut params = HashMap::new();
                            params.insert("rest".to_string(), rest);
                            Self::handle_proxy_request_with_params(endpoint_clone, params, req)
                        }));
                    } else {
                        router = router.route(&path, put(move |req| {
                            Self::handle_proxy_request(endpoint_clone, req)
                        }));
                    }
                }
                "DELETE" => {
                    if has_wildcard {
                        router = router.route(&path, delete(move |axum::extract::Path(rest): axum::extract::Path<String>, req| {
                            let mut params = HashMap::new();
                            params.insert("rest".to_string(), rest);
                            Self::handle_proxy_request_with_params(endpoint_clone, params, req)
                        }));
                    } else {
                        router = router.route(&path, delete(move |req| {
                            Self::handle_proxy_request(endpoint_clone, req)
                        }));
                    }
                }
                _ => {
                    warn!("Unsupported HTTP method: {} for path: {}", endpoint.method, endpoint.path);
                }
            }
        }

        router
    }

    fn substitute_placeholders(template: &str, params: &HashMap<String, String>) -> String {
        let mut out = template.to_string();
        // Build a local copy with some normalized params
        let mut norm = params.clone();
        // If we have a "rest" and template wants {model}, try to derive it
        if out.contains("{model}") {
            if let Some(rest) = norm.get("rest").cloned() {
                let model = rest.split(':').next().unwrap_or(rest.as_str()).to_string();
                norm.insert("model".to_string(), model);
            }
        }
        for (k, v) in norm.iter() {
            let key = format!("{{{}}}", k);
            if out.contains(&key) {
                out = out.replace(&key, v);
            }
        }
        out
    }

    async fn handle_proxy_request(
        config: EndpointConfig,
        req: Request,
    ) -> Result<Response, (StatusCode, String)> {
        let target_url = config.target_url.clone();
        info!("Forwarding request: {} -> {}", config.path, target_url);

        let client = Client::new();
        let (parts, body) = req.into_parts();

        // Read request body
        let body_bytes = match axum::body::to_bytes(body, usize::MAX).await {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("Failed to read request body: {}", e);
                return Err((StatusCode::BAD_REQUEST, "Unable to read request body".to_string()));
            }
        };

        // Build request
        let method = Method::from_bytes(config.method.as_bytes())
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid HTTP method".to_string()))?;

        let mut req_builder = client
            .request(method, &target_url)
            .body(body_bytes);

        // Add forwarded request headers
        for header_name in &config.forward_request_headers {
            if let Some(header_value) = parts.headers.get(header_name) {
                req_builder = req_builder.header(header_name, header_value);
            }
        }

        // Add custom request headers
        for (name, value) in &config.custom_headers {
            req_builder = req_builder.header(name, value);
        }

        // Special handling: add auth header for LLM proxy
        if config.path.contains("llm-proxy") {
            req_builder = req_builder.header("authorization", format!("Bearer {}", get_amp_api_key()));
        }

        // Special handling: add Google API key header when proxying Google endpoints
        if config.path.contains("/api/provider/google/") {
            if let Some(key) = get_google_api_key() {
                req_builder = req_builder.header("x-goog-api-key", key);
            } else {
                warn!("GOOGLE_API_KEY not set; skipping x-goog-api-key injection for {}", config.path);
            }
        }

        // Send request
        let response = match req_builder.send().await {
            Ok(resp) => resp,
            Err(e) => {
                error!("Failed to forward request: {}", e);
                return Err((StatusCode::BAD_GATEWAY, format!("Forward failed: {e}")));
            }
        };

        if !response.status().is_success() {
            error!("Upstream server returned error status: {}", response.status());
            return Err((StatusCode::BAD_GATEWAY, "Upstream server error".to_string()));
        }

        // Always forward as raw byte stream without any parsing
        Self::handle_stream_response(response, &config).await
    }

    async fn handle_proxy_request_with_params(
        mut config: EndpointConfig,
        params: HashMap<String, String>,
        req: Request,
    ) -> Result<Response, (StatusCode, String)> {
        // Compute target URL from template and params
        let target = Self::substitute_placeholders(&config.target_url, &params);
        config.target_url = target;
        Self::handle_proxy_request(config, req).await
    }

    async fn handle_stream_response(
        response: reqwest::Response,
        config: &EndpointConfig,
    ) -> Result<Response, (StatusCode, String)> {
        let status = response.status();
        let headers = response.headers().clone();

        let mut response_builder = Response::builder().status(status);

        // Forward response headers
        for header_name in &config.forward_response_headers {
            if let Some(header_value) = headers.get(header_name) {
                let name_str = header_name.as_str();
                if !name_str.starts_with("connection") && !name_str.starts_with("transfer-encoding") {
                    response_builder = response_builder.header(header_name, header_value);
                }
            }
        }

        // Always forward as raw byte stream without parsing
        let stream = response.bytes_stream().map(|result| {
            result.map_err(std::io::Error::other)
        });
        let body = Body::from_stream(stream);

        response_builder.body(body)
            .map_err(|e| {
                error!("Failed to build streaming response: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Failed to build streaming response".to_string())
            })
    }


}
