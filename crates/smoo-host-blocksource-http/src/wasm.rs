use crate::HttpError;
use gloo_net::http::Request;
use http::header::{CONTENT_LENGTH, CONTENT_RANGE, RANGE};
use std::ops::RangeInclusive;
use url::Url;

#[derive(Clone)]
pub struct Client;

impl Client {
    pub fn new() -> Result<Self, crate::BlockSourceError> {
        Ok(Self)
    }

    pub async fn probe_size(&self, url: &Url) -> Result<u64, HttpError> {
        let resp = Request::get(url.as_str())
            .header(RANGE.as_str(), "bytes=0-0")
            .send()
            .await
            .map_err(|err| HttpError::Msg(format!("probe GET: {err}")))?;
        tracing::debug!(%url, status = resp.status(), "http probe response");
        if let Some(len) = resp
            .headers()
            .get(CONTENT_RANGE.as_str())
            .and_then(|s| parse_content_range_total(s))
        {
            return Ok(len);
        }
        if resp.ok() {
            if let Some(len) = resp
                .headers()
                .get(CONTENT_LENGTH.as_str())
                .and_then(|s| s.parse::<u64>().ok())
            {
                return Ok(len);
            }
        }
        // Final fallback: HEAD (best effort)
        if let Ok(resp) = Request::head(url.as_str()).send().await {
            if resp.ok() {
                if let Some(len) = resp
                    .headers()
                    .get(CONTENT_LENGTH.as_str())
                    .and_then(|s| s.parse::<u64>().ok())
                {
                    return Ok(len);
                }
            }
        }
        Err(HttpError::Msg("unable to determine content length".into()))
    }

    pub async fn read_range(
        &self,
        url: &Url,
        range: RangeInclusive<u64>,
        buf: &mut [u8],
    ) -> Result<usize, HttpError> {
        let header = format!("bytes={}-{}", range.start(), range.end());
        let resp = Request::get(url.as_str())
            .header(RANGE.as_str(), &header)
            .send()
            .await
            .map_err(|err| HttpError::Msg(format!("GET: {err}")))?;
        tracing::trace!(
            status = resp.status(),
            start = *range.start(),
            end = *range.end(),
            "http read response"
        );
        if !(resp.ok() || resp.status() == 206) {
            return Err(HttpError::Msg(format!("GET status {}", resp.status())));
        }
        let bytes = resp
            .binary()
            .await
            .map_err(|err| HttpError::Msg(format!("read body: {err}")))?;
        let read = bytes.len().min(buf.len());
        buf[..read].copy_from_slice(&bytes[..read]);
        tracing::trace!(read, expected = buf.len(), "http read done");
        Ok(read)
    }
}

fn parse_content_range_total(hdr: &str) -> Option<u64> {
    // e.g. "bytes 0-0/12345"
    let parts: Vec<&str> = hdr.split('/').collect();
    if parts.len() != 2 {
        return None;
    }
    parts[1].parse::<u64>().ok()
}
