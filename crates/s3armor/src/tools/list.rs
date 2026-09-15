//! A minimal `ListObjectsV2` client and response parser for `rewrap` to
//! walk a bucket. Not a general XML parser — only the elements
//! `ListBucketResult` actually contains.

use http_body_util::BodyExt;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use quick_xml::events::Event;
use quick_xml::Reader;

use crate::config::Backend;
use crate::proxy::body;
use crate::proxy::{forward, ProxyState};

use super::ToolError;

pub(super) struct ListedObject {
    /// Plain text, **not** wire-encoded — build a request path with
    /// `proxy::route::encode_key_for_path`. `list_page` deliberately does
    /// not request `encoding-type=url`: MinIO's implementation of it
    /// encodes a space as `+` (form-encoding, not RFC 3986), which is
    /// ambiguous with an object that has a literal `+` in its key — one of
    /// the golden vectors (`gcm-key-plus+sign.txt`) does. Plain XML text,
    /// unescaped once, has no such ambiguity.
    pub key: String,
}

pub(super) struct ListPage {
    pub objects: Vec<ListedObject>,
    /// `Some` when the listing continues — feed back into the next call's
    /// `continuation_token`.
    pub next_token: Option<String>,
}

/// One `ListObjectsV2` page (max 1000 keys — the S3 default and cap),
/// direct to the backend, signed the same way `serve`'s passthrough path
/// signs everything else.
pub(super) async fn list_page(
    state: &ProxyState,
    backend: &Backend,
    bucket: &str,
    prefix: &str,
    continuation_token: Option<&str>,
) -> Result<ListPage, ToolError> {
    // No `encoding-type=url` — see `ListedObject::key`'s doc comment.
    // XML's own entity escaping (handled below via `unescape`) is enough
    // to round-trip any key text, including control characters.
    let mut query = "list-type=2&max-keys=1000".to_string();
    if !prefix.is_empty() {
        query.push_str("&prefix=");
        query.push_str(&utf8_percent_encode(prefix, NON_ALPHANUMERIC).to_string());
    }
    if let Some(token) = continuation_token {
        query.push_str("&continuation-token=");
        query.push_str(&utf8_percent_encode(token, NON_ALPHANUMERIC).to_string());
    }
    let path = format!("/{bucket}");
    let resp = forward(
        state,
        backend,
        "GET",
        &path,
        &query,
        Vec::new(),
        body::empty(),
    )
    .await?;
    if !resp.status().is_success() {
        return Err(ToolError::Backend(format!(
            "ListObjectsV2 on {bucket} failed: HTTP {}",
            resp.status()
        )));
    }
    let bytes = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| ToolError::Backend(format!("reading list response: {e}")))?
        .to_bytes();
    let xml = String::from_utf8_lossy(&bytes);
    parse_list_xml(&xml)
}

fn parse_list_xml(xml: &str) -> Result<ListPage, ToolError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text_start = true;
    reader.config_mut().trim_text_end = true;

    let (objects, next_token, is_truncated) = process_list_xml_events(&mut reader)?;

    check_truncation_state(is_truncated, next_token.as_ref())?;
    Ok(ListPage {
        objects,
        next_token: if is_truncated { next_token } else { None },
    })
}

/// Process XML events from a list response. Extract objects, continuation
/// token, and truncation flag from the event stream. Handles Start, Text, and
/// End events to parse object keys and metadata fields.
fn process_list_xml_events(
    reader: &mut Reader<&[u8]>,
) -> Result<(Vec<ListedObject>, Option<String>, bool), ToolError> {
    let mut objects = Vec::new();
    let mut next_token = None;
    let mut is_truncated = false;
    let mut current_tag: Vec<u8> = Vec::new();
    let mut in_contents = false;
    let mut key: Option<String> = None;

    loop {
        match reader
            .read_event()
            .map_err(|e| ToolError::Xml(e.to_string()))?
        {
            Event::Start(e) => {
                handle_start_event(&e, &mut current_tag, &mut in_contents, &mut key);
            }
            Event::Text(t) => {
                assign_list_field(
                    &current_tag,
                    event_text(&t)?,
                    in_contents,
                    &mut key,
                    &mut is_truncated,
                    &mut next_token,
                );
            }
            Event::End(e) => {
                handle_end_event(&e, &mut in_contents, &mut key, &mut objects);
            }
            Event::Eof => break,
            _ => {}
        }
    }

    Ok((objects, next_token, is_truncated))
}

/// Process a Start event. Set the current tag name and initialize object
/// parsing when entering a Contents element.
fn handle_start_event(
    e: &quick_xml::events::BytesStart<'_>,
    current_tag: &mut Vec<u8>,
    in_contents: &mut bool,
    key: &mut Option<String>,
) {
    current_tag.clear();
    current_tag.extend_from_slice(e.name().as_ref());
    if current_tag == b"Contents" {
        *in_contents = true;
        *key = None;
    }
}

/// Process an End event. Finalize object parsing when exiting a Contents
/// element and push the object to the result list.
fn handle_end_event(
    e: &quick_xml::events::BytesEnd<'_>,
    in_contents: &mut bool,
    key: &mut Option<String>,
    objects: &mut Vec<ListedObject>,
) {
    if e.name().as_ref() == b"Contents" {
        *in_contents = false;
        if let Some(k) = key.take() {
            objects.push(ListedObject { key: k });
        }
    }
}

/// Verify that truncation and continuation token state are consistent.
/// Backends must include a continuation token if they report truncation.
fn check_truncation_state(
    is_truncated: bool,
    next_token: Option<&String>,
) -> Result<(), ToolError> {
    if is_truncated && next_token.is_none() {
        // Ending the walk here would report success over only the first page.
        return Err(ToolError::Backend(
            "backend reported truncation with no continuation token".to_string(),
        ));
    }
    Ok(())
}

/// Decodes and unescapes an XML text event's raw bytes.
fn event_text(t: &quick_xml::events::BytesText<'_>) -> Result<String, ToolError> {
    let decoded = t.decode().map_err(|e| ToolError::Xml(e.to_string()))?;
    Ok(quick_xml::escape::unescape(&decoded)
        .map_err(|e| ToolError::Xml(e.to_string()))?
        .into_owned())
}

fn assign_list_field(
    tag: &[u8],
    text: String,
    in_contents: bool,
    key: &mut Option<String>,
    is_truncated: &mut bool,
    next_token: &mut Option<String>,
) {
    match tag {
        b"Key" if in_contents => *key = Some(text),
        b"IsTruncated" => *is_truncated = text == "true",
        b"NextContinuationToken" => *next_token = Some(text),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_truncated_page() {
        let xml = r#"<?xml version="1.0"?>
<ListBucketResult>
  <IsTruncated>true</IsTruncated>
  <NextContinuationToken>tok-1</NextContinuationToken>
  <Contents><Key>a.txt</Key><Size>10</Size><ETag>"x"</ETag></Contents>
  <Contents><Key>b dir/c.txt</Key><Size>0</Size></Contents>
</ListBucketResult>"#;
        let page = parse_list_xml(xml).unwrap();
        assert_eq!(page.objects.len(), 2);
        assert_eq!(page.objects[0].key, "a.txt");
        assert_eq!(page.objects[1].key, "b dir/c.txt");
        assert_eq!(page.next_token.as_deref(), Some("tok-1"));
    }

    #[test]
    fn final_page_has_no_next_token() {
        let xml = r"<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>";
        let page = parse_list_xml(xml).unwrap();
        assert!(page.objects.is_empty());
        assert_eq!(page.next_token, None);
    }
}
