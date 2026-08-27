use std::{
    io,
    sync::{Arc, Mutex},
    time::Instant,
};

use async_stream::stream;
use axum::{
    body::{Body, Bytes},
    extract::State,
    http::{header, HeaderMap, HeaderName, Request, Response, StatusCode},
    routing::{get, post},
    Router,
};
use chrono::Utc;
use futures_util::StreamExt;
use reqwest::header::HeaderValue;
use serde_json::json;
use subtle::ConstantTimeEq;
use tokio::time::{timeout, Duration};
use tower_http::trace::TraceLayer;
use uuid::Uuid;

use crate::{models::RequestLog, state::AppState, storage::ContentCapture};

const UPLOAD_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/models", get(proxy_models))
        .route("/v1/models", get(proxy_models))
        .route("/responses", post(proxy_responses))
        .route("/v1/responses", post(proxy_responses))
        .route("/responses/compact", post(proxy_responses_compact))
        .route("/v1/responses/compact", post(proxy_responses_compact))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn healthz(State(state): State<Arc<AppState>>) -> Response<Body> {
    json_response(
        StatusCode::OK,
        json!({
            "status": "ok",
            "active_provider": state.providers.active_id(),
            "in_flight": state.stats.status(&state.providers, &state.listen_address).in_flight_requests
        }),
    )
}

async fn proxy_models(
    State(state): State<Arc<AppState>>,
    request: Request<Body>,
) -> Response<Body> {
    if !authorized(request.headers(), &state.local_token) {
        return json_response(
            StatusCode::UNAUTHORIZED,
            json!({"error": {"message": "EasyAPI local proxy authentication failed", "type": "authentication_error"}}),
        );
    }

    let Some(provider) = state.providers.active() else {
        return json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error": {"message": "No active provider is configured in EasyAPI", "type": "easyapi_configuration_error"}}),
        );
    };

    let (parts, _) = request.into_parts();
    let mut url = provider.models_url();
    if let Some(query) = parts.uri.query() {
        url.push('?');
        url.push_str(query);
    }

    let (token, account_id) = match upstream_token(&state, &provider).await {
        Ok(value) => value,
        Err(error) => {
            return json_response(
                StatusCode::UNAUTHORIZED,
                json!({"error": {"message": error, "type": "authentication_error"}}),
            )
        }
    };
    let mut builder = state
        .http_client
        .get(url)
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    for (name, value) in &parts.headers {
        if should_forward_request_header(name) {
            builder = builder.header(name, value);
        }
    }
    for (name, value) in &provider.headers {
        builder = builder.header(name, value);
    }
    if let Some(account_id) = account_id {
        builder = builder
            .header("chatgpt-account-id", account_id)
            .header("originator", crate::codex_oauth::CODEX_OAUTH_ORIGINATOR)
            .header("version", crate::codex_oauth::CODEX_OAUTH_CLIENT_VERSION);
    }

    let upstream = match builder.send().await {
        Ok(response) => response,
        Err(error) => {
            let message = sanitized_reqwest_error(&error);
            return json_response(
                StatusCode::BAD_GATEWAY,
                json!({"error": {"message": message, "type": "easyapi_upstream_error"}}),
            );
        }
    };

    let mut response_builder = Response::builder()
        .status(upstream.status())
        .header("x-easyapi-request-id", Uuid::new_v4().to_string());
    for (name, value) in upstream.headers() {
        if should_forward_response_header(name) {
            response_builder = response_builder.header(name, value);
        }
    }

    let response_stream = upstream
        .bytes_stream()
        .map(|item| item.map_err(|error| io::Error::other(sanitized_reqwest_error(&error))));
    response_builder
        .body(Body::from_stream(response_stream))
        .unwrap_or_else(|error| {
            json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": {"message": error.to_string(), "type": "easyapi_internal_error"}}),
            )
        })
}

async fn proxy_responses(
    State(state): State<Arc<AppState>>,
    request: Request<Body>,
) -> Response<Body> {
    proxy_responses_endpoint(state, request, false).await
}

async fn proxy_responses_compact(
    State(state): State<Arc<AppState>>,
    request: Request<Body>,
) -> Response<Body> {
    proxy_responses_endpoint(state, request, true).await
}

async fn proxy_responses_endpoint(
    state: Arc<AppState>,
    request: Request<Body>,
    compact: bool,
) -> Response<Body> {
    let request_id = Uuid::new_v4().to_string();
    let started_at = Utc::now().to_rfc3339();
    let started = Instant::now();
    let request_bytes = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());

    let provider = state.providers.active();
    let mut guard = RequestGuard::new(
        state.clone(),
        request_id.clone(),
        started_at,
        started,
        provider.as_ref().map(|p| p.provider.id.clone()),
        provider.as_ref().map(|p| p.provider.name.clone()),
        request_bytes,
    );

    if !authorized(request.headers(), &state.local_token) {
        guard.fail(StatusCode::UNAUTHORIZED, "本地代理认证失败");
        return json_response(
            StatusCode::UNAUTHORIZED,
            json!({"error": {"message": "EasyAPI local proxy authentication failed", "type": "authentication_error"}}),
        );
    }

    let Some(provider) = provider else {
        guard.fail(StatusCode::SERVICE_UNAVAILABLE, "未选择 Provider");
        return json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error": {"message": "No active provider is configured in EasyAPI", "type": "easyapi_configuration_error"}}),
        );
    };

    let (parts, body) = request.into_parts();
    if state.content_capture_enabled() {
        let request_content_type = parts
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        match state.start_content_capture(&request_id, request_content_type) {
            Ok(capture) => guard.set_content_capture(capture),
            Err(error) => {
                tracing::warn!(%error, request_id, "failed to start request content capture")
            }
        }
    }
    let upstream_url = if compact {
        provider.responses_compact_url()
    } else {
        provider.responses_url()
    };
    let normalize_codex_request = provider.uses_codex_oauth() && !compact;
    let (token, account_id) = match upstream_token(&state, &provider).await {
        Ok(value) => value,
        Err(error) => {
            guard.fail(StatusCode::UNAUTHORIZED, &error);
            return json_response(
                StatusCode::UNAUTHORIZED,
                json!({"error": {"message": error, "type": "authentication_error"}}),
            );
        }
    };
    let mut builder = state
        .http_client
        .post(upstream_url)
        .header(header::AUTHORIZATION, format!("Bearer {token}"));

    for (name, value) in &parts.headers {
        if should_forward_request_header_for_body(name, normalize_codex_request) {
            builder = builder.header(name, value);
        }
    }
    for (name, value) in &provider.headers {
        builder = builder.header(name, value);
    }
    if let Some(account_id) = account_id {
        builder = builder
            .header("chatgpt-account-id", account_id)
            .header("originator", crate::codex_oauth::CODEX_OAUTH_ORIGINATOR)
            .header("version", crate::codex_oauth::CODEX_OAUTH_CLIENT_VERSION);
    }

    let mut incoming = body.into_data_stream();
    let model_extractor = Arc::new(Mutex::new(RequestModelExtractor::default()));
    let model_extractor_for_stream = model_extractor.clone();
    let request_capture = guard.content_capture();
    let upload_stream = stream! {
        let mut codex_normalizer = normalize_codex_request.then(CodexRequestNormalizer::default);
        loop {
            match timeout(UPLOAD_IDLE_TIMEOUT, incoming.next()).await {
                Ok(Some(Ok(bytes))) => {
                    if let Ok(mut extractor) = model_extractor_for_stream.lock() {
                        extractor.observe(&bytes);
                    }
                    if let Some(capture) = &request_capture {
                        capture.write_request(&bytes);
                    }
                    if let Some(normalizer) = &mut codex_normalizer {
                        let normalized = normalizer.observe(&bytes);
                        if !normalized.is_empty() {
                            yield Ok::<_, io::Error>(Bytes::from(normalized));
                        }
                    } else {
                        yield Ok::<_, io::Error>(bytes);
                    }
                }
                Ok(Some(Err(error))) => {
                    yield Err(io::Error::other(error));
                    break;
                }
                Ok(None) => {
                    if let Some(capture) = &request_capture {
                        capture.mark_request_complete();
                    }
                    break;
                }
                Err(_) => {
                    yield Err(io::Error::new(io::ErrorKind::TimedOut, "request upload idle timeout"));
                    break;
                }
            }
        }
    };

    let upstream_result = builder
        .body(reqwest::Body::wrap_stream(upload_stream))
        .send()
        .await;
    let model = model_extractor
        .lock()
        .ok()
        .map(|mut extractor| std::mem::take(&mut *extractor).finish())
        .flatten();
    guard.set_model(model);
    let upstream = match upstream_result {
        Ok(response) => response,
        Err(error) => {
            let message = sanitized_reqwest_error(&error);
            guard.fail(StatusCode::BAD_GATEWAY, &message);
            return json_response(
                StatusCode::BAD_GATEWAY,
                json!({"error": {"message": message, "type": "easyapi_upstream_error"}}),
            );
        }
    };

    let status = upstream.status();
    guard.set_status(status);
    let response_capture = guard.content_capture();
    if let Some(capture) = &response_capture {
        let response_content_type = upstream
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        capture.set_response_content_type(response_content_type);
    }
    let mut response_builder = Response::builder()
        .status(status)
        .header("x-easyapi-request-id", request_id);

    for (name, value) in upstream.headers() {
        if should_forward_response_header(name) {
            response_builder = response_builder.header(name, value);
        }
    }

    let mut upstream_stream = upstream.bytes_stream();
    let response_stream = stream! {
        let mut stream_error = None;
        let mut usage = TokenUsageExtractor::default();
        while let Some(item) = upstream_stream.next().await {
            match item {
                Ok(bytes) => {
                    usage.observe(&bytes);
                    if let Some(capture) = &response_capture {
                        capture.write_response(&bytes);
                    }
                    yield Ok::<_, io::Error>(bytes);
                }
                Err(error) => {
                    let message = sanitized_reqwest_error(&error);
                    stream_error = Some(message.clone());
                    guard.mark_stream_error(message.clone());
                    yield Err(io::Error::other(message));
                    break;
                }
            }
        }
        guard.set_usage(usage.finish());
        if stream_error.is_none() {
            if let Some(capture) = &response_capture {
                capture.mark_response_complete();
            }
            guard.complete();
        }
    };

    response_builder
        .body(Body::from_stream(response_stream))
        .unwrap_or_else(|error| {
            json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": {"message": error.to_string(), "type": "easyapi_internal_error"}}),
            )
        })
}

fn authorized(headers: &HeaderMap, expected: &str) -> bool {
    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return false;
    };
    let Ok(value) = value.to_str() else {
        return false;
    };
    let Some(token) = value.strip_prefix("Bearer ") else {
        return false;
    };
    token.as_bytes().ct_eq(expected.as_bytes()).into()
}

async fn upstream_token(
    state: &AppState,
    provider: &crate::state::ProviderRuntime,
) -> Result<(String, Option<String>), String> {
    if provider.uses_codex_oauth() {
        let (token, account_id) = state.oauth.access_token().await?;
        return Ok((token, (!account_id.is_empty()).then_some(account_id)));
    }
    Ok((provider.api_key().to_string(), None))
}

fn should_forward_request_header(name: &HeaderName) -> bool {
    !matches!(
        name.as_str().to_ascii_lowercase().as_str(),
        "authorization"
            | "host"
            | "connection"
            | "proxy-connection"
            | "keep-alive"
            | "transfer-encoding"
            | "te"
            | "trailer"
            | "upgrade"
    )
}

fn should_forward_request_header_for_body(name: &HeaderName, body_rewritten: bool) -> bool {
    should_forward_request_header(name) && !(body_rewritten && name == header::CONTENT_LENGTH)
}

fn should_forward_response_header(name: &HeaderName) -> bool {
    !matches!(
        name.as_str().to_ascii_lowercase().as_str(),
        "connection"
            | "proxy-connection"
            | "keep-alive"
            | "transfer-encoding"
            | "te"
            | "trailer"
            | "upgrade"
    )
}

fn json_response(status: StatusCode, value: serde_json::Value) -> Response<Body> {
    let body = serde_json::to_vec(&value).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )
        .body(Body::from(body))
        .expect("static response is valid")
}

fn sanitized_reqwest_error(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        "上游请求超时".to_string()
    } else if error.is_connect() {
        "无法连接上游 API".to_string()
    } else if error.is_body() {
        "上游响应流中断".to_string()
    } else {
        "上游请求失败".to_string()
    }
}

const REQUEST_MODEL_BUFFER_LIMIT: usize = 64 * 1024;
const USAGE_SCAN_BUFFER_LIMIT: usize = 4 * 1024;

#[derive(Default)]
struct CodexRequestNormalizer {
    state: CodexRequestState,
    separator: Vec<u8>,
    member_prefix: Vec<u8>,
    key_literal: Vec<u8>,
    key_escaped: bool,
    dropping_member: bool,
    emitted_member: bool,
    value_kind: JsonValueKind,
    value_depth: usize,
    value_in_string: bool,
    value_escaped: bool,
}

#[derive(Clone, Copy, Default)]
enum CodexRequestState {
    #[default]
    BeforeRoot,
    BetweenMembers,
    Key,
    AfterKey,
    Value,
    AfterValue,
    Done,
}

#[derive(Clone, Copy, Default)]
enum JsonValueKind {
    #[default]
    Unknown,
    Primitive,
    String,
    Container,
}

impl CodexRequestNormalizer {
    fn observe(&mut self, bytes: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(bytes.len());
        for &byte in bytes {
            match self.state {
                CodexRequestState::BeforeRoot => {
                    output.push(byte);
                    if byte == b'{' {
                        self.state = CodexRequestState::BetweenMembers;
                    }
                }
                CodexRequestState::BetweenMembers => {
                    self.observe_between_members(byte, &mut output)
                }
                CodexRequestState::Key => self.observe_key(byte),
                CodexRequestState::AfterKey => self.observe_after_key(byte, &mut output),
                CodexRequestState::Value => self.observe_value(byte, &mut output),
                CodexRequestState::AfterValue => self.observe_after_value(byte, &mut output),
                CodexRequestState::Done => output.push(byte),
            }
        }
        output
    }

    fn observe_between_members(&mut self, byte: u8, output: &mut Vec<u8>) {
        match byte {
            b'"' => {
                self.member_prefix.push(byte);
                self.key_literal.push(byte);
                self.key_escaped = false;
                self.state = CodexRequestState::Key;
            }
            b'}' => self.finish_root(output),
            _ => self.separator.push(byte),
        }
    }

    fn observe_key(&mut self, byte: u8) {
        self.member_prefix.push(byte);
        self.key_literal.push(byte);
        match (byte, self.key_escaped) {
            (b'"', false) => self.state = CodexRequestState::AfterKey,
            (b'\\', false) => self.key_escaped = true,
            _ => self.key_escaped = false,
        }
    }

    fn observe_after_key(&mut self, byte: u8, output: &mut Vec<u8>) {
        self.member_prefix.push(byte);
        if byte != b':' {
            return;
        }

        let key = serde_json::from_slice::<String>(&self.key_literal).ok();
        self.dropping_member = key
            .as_deref()
            .is_some_and(|key| matches!(key, "max_output_tokens" | "store"));
        if !self.dropping_member {
            self.flush_separator(output);
            output.extend_from_slice(&self.member_prefix);
            self.emitted_member = true;
        }
        self.separator.clear();
        self.member_prefix.clear();
        self.key_literal.clear();
        self.value_kind = JsonValueKind::Unknown;
        self.value_depth = 0;
        self.value_in_string = false;
        self.value_escaped = false;
        self.state = CodexRequestState::Value;
    }

    fn observe_value(&mut self, byte: u8, output: &mut Vec<u8>) {
        match self.value_kind {
            JsonValueKind::Unknown => {
                if byte.is_ascii_whitespace() {
                    self.write_value_byte(byte, output);
                    return;
                }
                self.value_kind = match byte {
                    b'"' => JsonValueKind::String,
                    b'{' | b'[' => JsonValueKind::Container,
                    _ => JsonValueKind::Primitive,
                };
                if matches!(self.value_kind, JsonValueKind::Container) {
                    self.value_depth = 1;
                }
                self.write_value_byte(byte, output);
            }
            JsonValueKind::Primitive => match byte {
                b',' => self.begin_next_member(),
                b'}' => self.finish_root(output),
                _ if byte.is_ascii_whitespace() => {
                    self.write_value_byte(byte, output);
                    self.state = CodexRequestState::AfterValue;
                }
                _ => self.write_value_byte(byte, output),
            },
            JsonValueKind::String => {
                self.write_value_byte(byte, output);
                match (byte, self.value_escaped) {
                    (b'"', false) => self.state = CodexRequestState::AfterValue,
                    (b'\\', false) => self.value_escaped = true,
                    _ => self.value_escaped = false,
                }
            }
            JsonValueKind::Container => {
                self.write_value_byte(byte, output);
                if self.value_in_string {
                    match (byte, self.value_escaped) {
                        (b'"', false) => self.value_in_string = false,
                        (b'\\', false) => self.value_escaped = true,
                        _ => self.value_escaped = false,
                    }
                    return;
                }

                match byte {
                    b'"' => self.value_in_string = true,
                    b'{' | b'[' => self.value_depth += 1,
                    b'}' | b']' => {
                        self.value_depth = self.value_depth.saturating_sub(1);
                        if self.value_depth == 0 {
                            self.state = CodexRequestState::AfterValue;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    fn observe_after_value(&mut self, byte: u8, output: &mut Vec<u8>) {
        match byte {
            b',' => self.begin_next_member(),
            b'}' => self.finish_root(output),
            _ => self.write_value_byte(byte, output),
        }
    }

    fn write_value_byte(&self, byte: u8, output: &mut Vec<u8>) {
        if !self.dropping_member {
            output.push(byte);
        }
    }

    fn begin_next_member(&mut self) {
        self.separator.clear();
        self.separator.push(b',');
        self.state = CodexRequestState::BetweenMembers;
    }

    fn flush_separator(&self, output: &mut Vec<u8>) {
        if self.emitted_member {
            output.extend_from_slice(&self.separator);
            return;
        }
        output.extend(self.separator.iter().copied().filter(|byte| *byte != b','));
    }

    fn finish_root(&mut self, output: &mut Vec<u8>) {
        if matches!(self.state, CodexRequestState::BetweenMembers) {
            output.extend(self.separator.iter().copied().filter(|byte| *byte != b','));
        }
        if self.emitted_member {
            output.push(b',');
        }
        output.extend_from_slice(br#""store":false}"#);
        self.separator.clear();
        self.state = CodexRequestState::Done;
    }
}

#[derive(Default)]
struct RequestModelExtractor {
    buffer: Vec<u8>,
    model: Option<String>,
}

impl RequestModelExtractor {
    fn observe(&mut self, bytes: &[u8]) {
        if self.model.is_some() {
            return;
        }
        self.buffer.extend_from_slice(bytes);
        self.model = extract_json_string_field(&self.buffer, b"model");
        if self.model.is_none() && self.buffer.len() > REQUEST_MODEL_BUFFER_LIMIT {
            let keep_from = self.buffer.len() - REQUEST_MODEL_BUFFER_LIMIT / 2;
            self.buffer.drain(..keep_from);
        }
    }

    fn finish(self) -> Option<String> {
        self.model
            .or_else(|| extract_json_string_field(&self.buffer, b"model"))
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct TokenUsage {
    input_tokens: Option<i64>,
    output_tokens: Option<i64>,
    total_tokens: Option<i64>,
    cached_input_tokens: Option<i64>,
    reasoning_tokens: Option<i64>,
}

#[derive(Default)]
struct TokenUsageExtractor {
    buffer: Vec<u8>,
    usage: TokenUsage,
}

impl TokenUsageExtractor {
    fn observe(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
        if let Some(value) = find_json_number(&self.buffer, b"input_tokens") {
            self.usage.input_tokens = Some(value);
        }
        if let Some(value) = find_json_number(&self.buffer, b"output_tokens") {
            self.usage.output_tokens = Some(value);
        }
        if let Some(value) = find_json_number(&self.buffer, b"total_tokens") {
            self.usage.total_tokens = Some(value);
        }
        if let Some(value) = find_json_number(&self.buffer, b"cached_tokens") {
            self.usage.cached_input_tokens = Some(value);
        }
        if let Some(value) = find_json_number(&self.buffer, b"reasoning_tokens") {
            self.usage.reasoning_tokens = Some(value);
        }
        if self.buffer.len() > USAGE_SCAN_BUFFER_LIMIT {
            let keep_from = self.buffer.len() - USAGE_SCAN_BUFFER_LIMIT;
            self.buffer.drain(..keep_from);
        }
    }

    fn finish(mut self) -> TokenUsage {
        self.observe(&[]);
        self.usage
    }
}

fn extract_json_string_field(bytes: &[u8], key: &[u8]) -> Option<String> {
    let mut needle = Vec::with_capacity(key.len() + 2);
    needle.push(b'"');
    needle.extend_from_slice(key);
    needle.push(b'"');
    let mut offset = 0;
    while offset + needle.len() <= bytes.len() {
        let relative = bytes[offset..]
            .windows(needle.len())
            .position(|window| window == needle)?;
        let start = offset + relative + needle.len();
        let mut cursor = start;
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if cursor >= bytes.len() || bytes[cursor] != b':' {
            offset = start;
            continue;
        }
        cursor += 1;
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if cursor >= bytes.len() || bytes[cursor] != b'"' {
            offset = start;
            continue;
        }
        let value_start = cursor;
        cursor += 1;
        let mut escaped = false;
        while cursor < bytes.len() {
            match (bytes[cursor], escaped) {
                (b'"', false) => {
                    return serde_json::from_slice(&bytes[value_start..=cursor]).ok();
                }
                (b'\\', false) => escaped = true,
                (_, _) => escaped = false,
            }
            cursor += 1;
        }
        return None;
    }
    None
}

fn find_json_number(bytes: &[u8], key: &[u8]) -> Option<i64> {
    let mut needle = Vec::with_capacity(key.len() + 2);
    needle.push(b'"');
    needle.extend_from_slice(key);
    needle.push(b'"');
    let mut offset = 0;
    let mut result = None;
    while offset + needle.len() <= bytes.len() {
        let Some(relative) = bytes[offset..]
            .windows(needle.len())
            .position(|window| window == needle)
        else {
            break;
        };
        let key_end = offset + relative + needle.len();
        let mut cursor = key_end;
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if cursor >= bytes.len() || bytes[cursor] != b':' {
            offset = key_end;
            continue;
        }
        cursor += 1;
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        let number_start = cursor;
        if cursor < bytes.len() && bytes[cursor] == b'-' {
            cursor += 1;
        }
        let digits_start = cursor;
        while cursor < bytes.len() && bytes[cursor].is_ascii_digit() {
            cursor += 1;
        }
        if cursor == digits_start {
            offset = key_end;
            continue;
        }
        if let Some(value) = std::str::from_utf8(&bytes[number_start..cursor])
            .ok()
            .and_then(|value| value.parse().ok())
        {
            result = Some(value);
        }
        offset = cursor;
    }
    result
}

struct RequestGuard {
    state: Arc<AppState>,
    id: String,
    provider_id: Option<String>,
    provider_name: Option<String>,
    started_at: String,
    started: Instant,
    status_code: Option<u16>,
    outcome: String,
    error: Option<String>,
    request_bytes: Option<u64>,
    model: Option<String>,
    usage: TokenUsage,
    content_capture: Option<Arc<ContentCapture>>,
}

impl RequestGuard {
    fn new(
        state: Arc<AppState>,
        id: String,
        started_at: String,
        started: Instant,
        provider_id: Option<String>,
        provider_name: Option<String>,
        request_bytes: Option<u64>,
    ) -> Self {
        state.stats.begin();
        Self {
            state,
            id,
            provider_id,
            provider_name,
            started_at,
            started,
            status_code: None,
            outcome: "cancelled".to_string(),
            error: None,
            request_bytes,
            model: None,
            usage: TokenUsage::default(),
            content_capture: None,
        }
    }

    fn set_status(&mut self, status: StatusCode) {
        self.status_code = Some(status.as_u16());
        self.outcome = if status.is_success() {
            "client_cancelled".to_string()
        } else {
            "upstream_http_error".to_string()
        };
    }

    fn fail(&mut self, status: StatusCode, error: &str) {
        self.status_code = Some(status.as_u16());
        self.outcome = "proxy_error".to_string();
        self.error = Some(error.to_string());
    }

    fn mark_stream_error(&mut self, error: String) {
        self.outcome = "stream_error".to_string();
        self.error = Some(error);
    }

    fn complete(&mut self) {
        if self.status_code.is_some_and(|status| status < 400) {
            self.outcome = "completed".to_string();
        }
    }

    fn set_content_capture(&mut self, capture: Arc<ContentCapture>) {
        self.content_capture = Some(capture);
    }

    fn content_capture(&self) -> Option<Arc<ContentCapture>> {
        self.content_capture.clone()
    }

    fn set_model(&mut self, model: Option<String>) {
        self.model = model;
    }

    fn set_usage(&mut self, usage: TokenUsage) {
        self.usage = usage;
    }
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        let error = self.error.clone();
        self.state.stats.finish(error.clone());
        self.state.record_log(&RequestLog {
            id: self.id.clone(),
            provider_id: self.provider_id.clone(),
            provider_name: self.provider_name.clone(),
            model: self.model.clone(),
            started_at: self.started_at.clone(),
            duration_ms: self.started.elapsed().as_millis().min(i64::MAX as u128) as i64,
            status_code: self.status_code,
            outcome: self.outcome.clone(),
            error,
            request_bytes: self.request_bytes,
            input_tokens: self.usage.input_tokens,
            output_tokens: self.usage.output_tokens,
            total_tokens: self.usage.total_tokens,
            cached_input_tokens: self.usage.cached_input_tokens,
            reasoning_tokens: self.usage.reasoning_tokens,
            content_captured: false,
        });
        if let Some(capture) = self.content_capture.take() {
            self.state
                .record_content_capture(&self.id, &capture.finish());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_auth_requires_exact_bearer_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer secret"),
        );
        assert!(authorized(&headers, "secret"));
        assert!(!authorized(&headers, "secret2"));
    }

    #[test]
    fn filters_hop_by_hop_headers() {
        assert!(!should_forward_request_header(&header::AUTHORIZATION));
        assert!(!should_forward_request_header(&header::CONNECTION));
        assert!(should_forward_request_header(&header::CONTENT_TYPE));
        assert!(!should_forward_response_header(&header::TRANSFER_ENCODING));
    }

    #[test]
    fn codex_body_rewrite_drops_the_original_content_length() {
        assert!(should_forward_request_header_for_body(
            &header::CONTENT_LENGTH,
            false
        ));
        assert!(!should_forward_request_header_for_body(
            &header::CONTENT_LENGTH,
            true
        ));
    }

    #[test]
    fn normalizes_codex_request_fields_across_chunk_boundaries() {
        let request = br#"{
            "model":"gpt-5",
            "input":[{"role":"user","content":"keep max_output_tokens and store here"}],
            "max_output_tokens":512,
            "store":true,
            "stream":true
        }"#;
        let expected = serde_json::json!({
            "model": "gpt-5",
            "input": [{"role": "user", "content": "keep max_output_tokens and store here"}],
            "store": false,
            "stream": true
        });

        for chunk_size in 1..=request.len() {
            let mut normalizer = CodexRequestNormalizer::default();
            let mut normalized = Vec::new();
            for chunk in request.chunks(chunk_size) {
                normalized.extend(normalizer.observe(chunk));
            }
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&normalized).unwrap(),
                expected,
                "chunk size {chunk_size}"
            );
        }
    }

    #[test]
    fn normalizes_first_middle_last_and_missing_codex_fields() {
        let cases = [
            br#"{"max_output_tokens":128,"model":"gpt-5","store":true}"#.as_slice(),
            br#"{"model":"gpt-5","store":null,"stream":true,"max_output_tokens":128}"#.as_slice(),
            br#"{"model":"gpt-5","max_output_tokens":128}"#.as_slice(),
            br#"{}"#.as_slice(),
        ];

        for request in cases {
            let mut normalizer = CodexRequestNormalizer::default();
            let normalized = request
                .iter()
                .flat_map(|byte| normalizer.observe(std::slice::from_ref(byte)))
                .collect::<Vec<_>>();
            let value = serde_json::from_slice::<serde_json::Value>(&normalized).unwrap();
            assert_eq!(value["store"], false);
            assert!(value.get("max_output_tokens").is_none());
        }
    }

    #[test]
    fn preserves_nested_fields_with_codex_restricted_names() {
        let request = br#"{"input":{"max_output_tokens":64,"store":true},"max_output_tokens":256}"#;
        let mut normalizer = CodexRequestNormalizer::default();
        let normalized = normalizer.observe(request);
        let value = serde_json::from_slice::<serde_json::Value>(&normalized).unwrap();

        assert_eq!(value["input"]["max_output_tokens"], 64);
        assert_eq!(value["input"]["store"], true);
        assert_eq!(value["store"], false);
        assert!(value.get("max_output_tokens").is_none());
    }

    #[test]
    fn extracts_model_across_request_chunks() {
        let mut extractor = RequestModelExtractor::default();
        extractor.observe(br#"{"mo"#);
        extractor.observe(br#"del":"gpt-5"}"#);
        assert_eq!(extractor.finish().as_deref(), Some("gpt-5"));
    }

    #[test]
    fn extracts_usage_across_response_chunks() {
        let mut extractor = TokenUsageExtractor::default();
        extractor.observe(br#"{"usage":{"input_tokens":12,"output_tokens":"#);
        extractor.observe(br#"34,"total_tokens":46,"input_tokens_details":{"cached_tokens":5},"output_tokens_details":{"reasoning_tokens":7}}}"#);
        assert_eq!(
            extractor.finish(),
            TokenUsage {
                input_tokens: Some(12),
                output_tokens: Some(34),
                total_tokens: Some(46),
                cached_input_tokens: Some(5),
                reasoning_tokens: Some(7),
            }
        );
    }

    #[test]
    fn final_usage_overrides_zero_values_from_earlier_response_events() {
        let mut extractor = TokenUsageExtractor::default();
        extractor.observe(
            br#"event: response.created\ndata: {"response":{"usage":{"input_tokens":0,"output_tokens":0,"total_tokens":0}}}\n\n"#,
        );
        extractor.observe(
            br#"event: response.completed\ndata: {"response":{"usage":{"input_tokens":20698,"input_tokens_details":{"cached_tokens":12032},"output_tokens":251,"output_tokens_details":{"reasoning_tokens":102},"total_tokens":20949}}}\n\n"#,
        );
        assert_eq!(
            extractor.finish(),
            TokenUsage {
                input_tokens: Some(20698),
                output_tokens: Some(251),
                total_tokens: Some(20949),
                cached_input_tokens: Some(12032),
                reasoning_tokens: Some(102),
            }
        );
    }

    #[tokio::test]
    async fn streams_request_and_response_without_json_buffering() {
        use axum::{body::Bytes, routing::post, Router};
        use http_body_util::BodyExt;
        use tempfile::tempdir;
        use tower::ServiceExt;

        async fn upstream(body: Bytes) -> Response<Body> {
            assert_eq!(
                body,
                Bytes::from_static(br#"{"model":"test","input":"hello"}"#)
            );
            let chunks = futures_util::stream::iter([
                Ok::<_, io::Error>(Bytes::from_static(b"event: response.created\ndata: {}\n\n")),
                Ok::<_, io::Error>(Bytes::from_static(
                    b"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":12,\"output_tokens\":34,\"total_tokens\":46,\"input_tokens_details\":{\"cached_tokens\":5},\"output_tokens_details\":{\"reasoning_tokens\":7}}}}\n\n",
                )),
            ]);
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/event-stream")
                .body(Body::from_stream(chunks))
                .unwrap()
        }

        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_address = upstream_listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                upstream_listener,
                Router::new().route("/v1/responses", post(upstream)),
            )
            .await
            .unwrap();
        });

        let temp = tempdir().unwrap();
        let db =
            Arc::new(crate::storage::Database::open(&temp.path().join("test.sqlite3")).unwrap());
        let state = crate::state::AppState::new(
            db,
            "127.0.0.1:8787".to_string(),
            crate::codex_oauth::CodexOAuthManager::new(temp.path().join("oauth.json")).unwrap(),
        )
        .unwrap();
        state.set_content_capture_enabled(true).unwrap();
        state
            .providers
            .set_active_for_test(crate::state::ProviderRuntime::new_for_test(
                crate::models::Provider {
                    id: "test".to_string(),
                    name: "Test".to_string(),
                    base_url: format!("http://{upstream_address}/v1"),
                    test_model: "test".to_string(),
                    extra_headers: vec![],
                    auth_type: crate::models::AUTH_TYPE_API_KEY.to_string(),
                    created_at: Utc::now().to_rfc3339(),
                    updated_at: Utc::now().to_rfc3339(),
                },
                "upstream-key".to_string(),
            ));

        let request = Request::builder()
            .method("POST")
            .uri("/v1/responses")
            .header(
                header::AUTHORIZATION,
                format!("Bearer {}", state.local_token),
            )
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"model":"test","input":"hello"}"#))
            .unwrap();
        let response = router(state.clone()).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "text/event-stream"
        );
        let request_id = response.headers()["x-easyapi-request-id"]
            .to_str()
            .unwrap()
            .to_string();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            bytes,
            Bytes::from_static(
                b"event: response.created\ndata: {}\n\nevent: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":12,\"output_tokens\":34,\"total_tokens\":46,\"input_tokens_details\":{\"cached_tokens\":5},\"output_tokens_details\":{\"reasoning_tokens\":7}}}}\n\n"
            )
        );
        let capture = state.db.get_request_capture(&request_id).unwrap();
        assert_eq!(
            capture.request_content.as_deref(),
            Some(r#"{"model":"test","input":"hello"}"#)
        );
        assert_eq!(
            capture.response_content.as_deref(),
            Some("event: response.created\ndata: {}\n\nevent: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":12,\"output_tokens\":34,\"total_tokens\":46,\"input_tokens_details\":{\"cached_tokens\":5},\"output_tokens_details\":{\"reasoning_tokens\":7}}}}\n\n")
        );
        assert!(capture.request_complete);
        assert!(capture.response_complete);
        let logs = state.db.list_request_logs(None).unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].model.as_deref(), Some("test"));
        assert_eq!(logs[0].input_tokens, Some(12));
        assert_eq!(logs[0].output_tokens, Some(34));
        assert_eq!(logs[0].total_tokens, Some(46));
        assert_eq!(logs[0].cached_input_tokens, Some(5));
        assert_eq!(logs[0].reasoning_tokens, Some(7));
    }

    #[tokio::test]
    async fn forwards_compact_requests_to_the_upstream_compact_endpoint() {
        use axum::{body::Bytes, routing::post, Router};
        use http_body_util::BodyExt;
        use tempfile::tempdir;
        use tower::ServiceExt;

        async fn upstream(request: Request<Body>) -> Response<Body> {
            assert_eq!(
                request.headers()[header::AUTHORIZATION],
                "Bearer upstream-key"
            );
            let body = request.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(
                body,
                Bytes::from_static(
                    br#"{"model":"test","input":[{"role":"user","content":"hello"}]}"#
                )
            );
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"object":"response.compaction","output":[{"type":"compaction","encrypted_content":"opaque"}]}"#,
                ))
                .unwrap()
        }

        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_address = upstream_listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                upstream_listener,
                Router::new().route("/v1/responses/compact", post(upstream)),
            )
            .await
            .unwrap();
        });

        let temp = tempdir().unwrap();
        let db =
            Arc::new(crate::storage::Database::open(&temp.path().join("compact.sqlite3")).unwrap());
        let state = crate::state::AppState::new(
            db,
            "127.0.0.1:8787".to_string(),
            crate::codex_oauth::CodexOAuthManager::new(temp.path().join("oauth.json")).unwrap(),
        )
        .unwrap();
        state
            .providers
            .set_active_for_test(crate::state::ProviderRuntime::new_for_test(
                crate::models::Provider {
                    id: "compact-test".to_string(),
                    name: "Compact Test".to_string(),
                    base_url: format!("http://{upstream_address}/v1"),
                    test_model: "test".to_string(),
                    extra_headers: vec![],
                    auth_type: crate::models::AUTH_TYPE_API_KEY.to_string(),
                    created_at: Utc::now().to_rfc3339(),
                    updated_at: Utc::now().to_rfc3339(),
                },
                "upstream-key".to_string(),
            ));

        let request = Request::builder()
            .method("POST")
            .uri("/v1/responses/compact")
            .header(
                header::AUTHORIZATION,
                format!("Bearer {}", state.local_token),
            )
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"model":"test","input":[{"role":"user","content":"hello"}]}"#,
            ))
            .unwrap();
        let response = router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            body,
            Bytes::from_static(
                br#"{"object":"response.compaction","output":[{"type":"compaction","encrypted_content":"opaque"}]}"#,
            )
        );
    }

    #[tokio::test]
    async fn forwards_model_lists_with_upstream_authentication() {
        use axum::{body::Bytes, routing::get, Router};
        use http_body_util::BodyExt;
        use tempfile::tempdir;
        use tower::ServiceExt;

        async fn upstream(request: Request<Body>) -> Response<Body> {
            assert_eq!(request.uri().query(), Some("limit=1"));
            assert_eq!(
                request.headers()[header::AUTHORIZATION],
                "Bearer upstream-key"
            );
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"object":"list","data":[{"id":"test-model"}]}"#,
                ))
                .unwrap()
        }

        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_address = upstream_listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                upstream_listener,
                Router::new().route("/v1/models", get(upstream)),
            )
            .await
            .unwrap();
        });

        let temp = tempdir().unwrap();
        let db =
            Arc::new(crate::storage::Database::open(&temp.path().join("models.sqlite3")).unwrap());
        let state = crate::state::AppState::new(
            db,
            "127.0.0.1:8787".to_string(),
            crate::codex_oauth::CodexOAuthManager::new(temp.path().join("oauth.json")).unwrap(),
        )
        .unwrap();
        state
            .providers
            .set_active_for_test(crate::state::ProviderRuntime::new_for_test(
                crate::models::Provider {
                    id: "models-test".to_string(),
                    name: "Models Test".to_string(),
                    base_url: format!("http://{upstream_address}/v1"),
                    test_model: "test".to_string(),
                    extra_headers: vec![],
                    auth_type: crate::models::AUTH_TYPE_API_KEY.to_string(),
                    created_at: Utc::now().to_rfc3339(),
                    updated_at: Utc::now().to_rfc3339(),
                },
                "upstream-key".to_string(),
            ));

        let request = Request::builder()
            .method("GET")
            .uri("/v1/models?limit=1")
            .header(
                header::AUTHORIZATION,
                format!("Bearer {}", state.local_token),
            )
            .body(Body::empty())
            .unwrap();
        let response = router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            bytes,
            Bytes::from_static(br#"{"object":"list","data":[{"id":"test-model"}]}"#)
        );
    }

    #[tokio::test]
    async fn accepts_request_bodies_larger_than_common_buffered_extractor_limits() {
        use axum::{body::Bytes, routing::post, Router};
        use http_body_util::BodyExt;
        use tempfile::tempdir;
        use tower::ServiceExt;

        async fn upstream(body: Body) -> Response<Body> {
            let bytes = body.collect().await.unwrap().to_bytes();
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from(bytes.len().to_string()))
                .unwrap()
        }

        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_address = upstream_listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                upstream_listener,
                Router::new().route("/v1/responses", post(upstream)),
            )
            .await
            .unwrap();
        });

        let temp = tempdir().unwrap();
        let db =
            Arc::new(crate::storage::Database::open(&temp.path().join("large.sqlite3")).unwrap());
        let state = crate::state::AppState::new(
            db,
            "127.0.0.1:8787".to_string(),
            crate::codex_oauth::CodexOAuthManager::new(temp.path().join("oauth.json")).unwrap(),
        )
        .unwrap();
        state
            .providers
            .set_active_for_test(crate::state::ProviderRuntime::new_for_test(
                crate::models::Provider {
                    id: "large-test".to_string(),
                    name: "Large Test".to_string(),
                    base_url: format!("http://{upstream_address}/v1"),
                    test_model: "test".to_string(),
                    extra_headers: vec![],
                    auth_type: crate::models::AUTH_TYPE_API_KEY.to_string(),
                    created_at: Utc::now().to_rfc3339(),
                    updated_at: Utc::now().to_rfc3339(),
                },
                "upstream-key".to_string(),
            ));

        let chunk = Bytes::from(vec![b'x'; 64 * 1024]);
        let chunks =
            futures_util::stream::iter((0..64).map(move |_| Ok::<_, io::Error>(chunk.clone())));
        let request = Request::builder()
            .method("POST")
            .uri("/v1/responses")
            .header(
                header::AUTHORIZATION,
                format!("Bearer {}", state.local_token),
            )
            .body(Body::from_stream(chunks))
            .unwrap();
        let response = router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, Bytes::from_static(b"4194304"));
    }
}
