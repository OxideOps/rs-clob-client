//! Rate limiting for HTTP requests to Polymarket APIs.
//!
//! This module provides rate limiting functionality based on Polymarket's documented
//! rate limits. Rate limits are enforced using token bucket algorithm via the `governor` crate.
//!
//! # Rate Limits
//!
//! See <https://docs.polymarket.com/quickstart/introduction/rate-limits> for official documentation.
//!
//! ## CLOB API
//! - General: 9,000 requests/10s
//! - Book/Price/Midpoint: 1,500 requests/10s each
//! - POST Order: 3,500 requests/10s burst OR 36,000 requests/10 minutes sustained
//! - DELETE Order: 3,000 requests/10s burst OR 30,000 requests/10 minutes sustained
//! - Submit (relayer): 25 requests/1 minute
//! - User PNL: 200 requests/10s
//!
//! ## Gamma API
//! - General: 4,000 requests/10s
//! - Events: 500 requests/10s
//! - Markets: 300 requests/10s
//! - Comments: 200 requests/10s
//! - Tags: 200 requests/10s
//! - Search: 350 requests/10s
//!
//! ## Data API
//! - General: 1,000 requests/10s
//! - Trades: 200 requests/10s
//! - Positions: 150 requests/10s
//! - Closed Positions: 150 requests/10s
//!
//! ## Global
//! - 15,000 requests/10s across all APIs
//!
//! # Examples
//!
//! ```rust,no_run
//! use polymarket_client_sdk::clob::{Client, Config};
//! use polymarket_client_sdk::http::rate_limit::Config;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Enable with default limits
//! let config = Config::builder()
//!     .rate_limit_config(Config::default())
//!     .build();
//!
//! let client = Client::new("https://clob.polymarket.com", config)?;
//! # Ok(())
//! # }
//! ```

use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use governor::{
    Quota, RateLimiter,
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
};
use reqwest::{Method, Url};

/// Type alias for a rate limiter instance.
pub type Limiter = Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>;

/// Configuration for rate limiting.
///
/// This struct allows configuring rate limits for different APIs and endpoints.
/// By default, uses the limits documented by Polymarket. Set fields to `None` to disable
/// specific limiters.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct Config {
    /// Global rate limit across all APIs (15,000 requests/10s)
    pub global_limit: Option<Quota>,

    // === CLOB API Limits ===
    /// General CLOB API limit (9,000 requests/10s)
    pub clob_general: Option<Quota>,
    /// CLOB book endpoint (1,500 requests/10s)
    pub clob_book: Option<Quota>,
    /// CLOB price endpoint (1,500 requests/10s)
    pub clob_price: Option<Quota>,
    /// CLOB midpoint endpoint (1,500 requests/10s)
    pub clob_midpoint: Option<Quota>,
    /// CLOB POST order endpoint (burst + sustained)
    pub clob_post_order: Option<MultiWindowQuota>,
    /// CLOB DELETE order endpoint (burst + sustained)
    pub clob_delete_order: Option<MultiWindowQuota>,
    /// CLOB submit/relayer endpoint (25 requests/1 minute)
    pub clob_submit: Option<Quota>,
    /// CLOB user PNL endpoint (200 requests/10s)
    pub clob_user_pnl: Option<Quota>,

    // === Gamma API Limits ===
    /// General Gamma API limit (4,000 requests/10s)
    pub gamma_general: Option<Quota>,
    /// Gamma events endpoint (500 requests/10s)
    pub gamma_events: Option<Quota>,
    /// Gamma markets endpoint (300 requests/10s)
    pub gamma_markets: Option<Quota>,
    /// Gamma markets events listing (900 requests/10s)
    pub gamma_markets_events: Option<Quota>,
    /// Gamma comments endpoint (200 requests/10s)
    pub gamma_comments: Option<Quota>,
    /// Gamma tags endpoint (200 requests/10s)
    pub gamma_tags: Option<Quota>,
    /// Gamma search endpoint (350 requests/10s)
    pub gamma_search: Option<Quota>,

    // === Data API Limits ===
    /// General Data API limit (1,000 requests/10s)
    pub data_general: Option<Quota>,
    /// Data trades endpoint (200 requests/10s)
    pub data_trades: Option<Quota>,
    /// Data positions endpoint (150 requests/10s)
    pub data_positions: Option<Quota>,
    /// Data closed positions endpoint (150 requests/10s)
    pub data_closed_positions: Option<Quota>,

    // === Bridge API Limits ===
    /// General Bridge API limit (no documented limit)
    pub bridge_general: Option<Quota>,
}

/// Multi-window rate limit quota for endpoints with both burst and sustained limits.
///
/// Some endpoints (like POST/DELETE order) have both a short-term burst limit and
/// a longer sustained limit. Both must be respected.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct MultiWindowQuota {
    /// Short-term burst limit (typically 10 seconds)
    pub burst: Quota,
    /// Longer sustained limit (typically 10 minutes)
    pub sustained: Quota,
}

impl Default for Config {
    fn default() -> Self {
        // Helper to create a 10-second quota
        let per_ten_seconds = |count: u32| {
            Quota::with_period(Duration::from_secs(10))
                .expect("quota is valid")
                .allow_burst(NonZeroU32::new(count).expect("count is non-zero"))
        };

        // Helper for 10-minute quotas
        let per_ten_minutes = |count: u32| {
            Quota::with_period(Duration::from_secs(600))
                .expect("quota is valid")
                .allow_burst(NonZeroU32::new(count).expect("count is non-zero"))
        };

        Self {
            // Global limit
            global_limit: Some(per_ten_seconds(15000)),

            // CLOB limits
            clob_general: Some(per_ten_seconds(9000)),
            clob_book: Some(per_ten_seconds(1500)),
            clob_price: Some(per_ten_seconds(1500)),
            clob_midpoint: Some(per_ten_seconds(1500)),
            clob_post_order: Some(MultiWindowQuota {
                burst: per_ten_seconds(3500),
                sustained: per_ten_minutes(36000),
            }),
            clob_delete_order: Some(MultiWindowQuota {
                burst: per_ten_seconds(3000),
                sustained: per_ten_minutes(30000),
            }),
            clob_submit: Some(Quota::per_minute(
                NonZeroU32::new(25).expect("25 is non-zero"),
            )),
            clob_user_pnl: Some(per_ten_seconds(200)),

            // Gamma limits
            gamma_general: Some(per_ten_seconds(4000)),
            gamma_events: Some(per_ten_seconds(500)),
            gamma_markets: Some(per_ten_seconds(300)),
            gamma_markets_events: Some(per_ten_seconds(900)),
            gamma_comments: Some(per_ten_seconds(200)),
            gamma_tags: Some(per_ten_seconds(200)),
            gamma_search: Some(per_ten_seconds(350)),

            // Data limits
            data_general: Some(per_ten_seconds(1000)),
            data_trades: Some(per_ten_seconds(200)),
            data_positions: Some(per_ten_seconds(150)),
            data_closed_positions: Some(per_ten_seconds(150)),

            // Bridge limits (no documented limit)
            bridge_general: None,
        }
    }
}

impl Config {
    /// Create a configuration with all rate limiting disabled.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            global_limit: None,
            clob_general: None,
            clob_book: None,
            clob_price: None,
            clob_midpoint: None,
            clob_post_order: None,
            clob_delete_order: None,
            clob_submit: None,
            clob_user_pnl: None,
            gamma_general: None,
            gamma_events: None,
            gamma_markets: None,
            gamma_markets_events: None,
            gamma_comments: None,
            gamma_tags: None,
            gamma_search: None,
            data_general: None,
            data_trades: None,
            data_positions: None,
            data_closed_positions: None,
            bridge_general: None,
        }
    }
}

/// Collection of rate limiters for all APIs and endpoints.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct RateLimiters {
    /// Global rate limiter
    pub global: Option<Limiter>,

    // CLOB limiters
    /// General CLOB limiter
    pub clob_general: Option<Limiter>,
    /// CLOB book endpoint limiter
    pub clob_book: Option<Limiter>,
    /// CLOB price endpoint limiter
    pub clob_price: Option<Limiter>,
    /// CLOB midpoint endpoint limiter
    pub clob_midpoint: Option<Limiter>,
    /// CLOB POST order burst limiter
    pub clob_post_order_burst: Option<Limiter>,
    /// CLOB POST order sustained limiter
    pub clob_post_order_sustained: Option<Limiter>,
    /// CLOB DELETE order burst limiter
    pub clob_delete_order_burst: Option<Limiter>,
    /// CLOB DELETE order sustained limiter
    pub clob_delete_order_sustained: Option<Limiter>,
    /// CLOB submit limiter
    pub clob_submit: Option<Limiter>,
    /// CLOB user PNL limiter
    pub clob_user_pnl: Option<Limiter>,

    // Gamma limiters
    /// General Gamma limiter
    pub gamma_general: Option<Limiter>,
    /// Gamma events limiter
    pub gamma_events: Option<Limiter>,
    /// Gamma markets limiter
    pub gamma_markets: Option<Limiter>,
    /// Gamma markets events limiter
    pub gamma_markets_events: Option<Limiter>,
    /// Gamma comments limiter
    pub gamma_comments: Option<Limiter>,
    /// Gamma tags limiter
    pub gamma_tags: Option<Limiter>,
    /// Gamma search limiter
    pub gamma_search: Option<Limiter>,

    // Data limiters
    /// General Data API limiter
    pub data_general: Option<Limiter>,
    /// Data trades limiter
    pub data_trades: Option<Limiter>,
    /// Data positions limiter
    pub data_positions: Option<Limiter>,
    /// Data closed positions limiter
    pub data_closed_positions: Option<Limiter>,

    // Bridge limiters
    /// General Bridge limiter
    pub bridge_general: Option<Limiter>,
}

impl RateLimiters {
    /// Create rate limiters from configuration.
    #[must_use]
    pub fn new(config: &Config) -> Self {
        Self {
            global: config
                .global_limit
                .map(|q| Arc::new(RateLimiter::direct(q))),

            // CLOB
            clob_general: config
                .clob_general
                .map(|q| Arc::new(RateLimiter::direct(q))),
            clob_book: config.clob_book.map(|q| Arc::new(RateLimiter::direct(q))),
            clob_price: config.clob_price.map(|q| Arc::new(RateLimiter::direct(q))),
            clob_midpoint: config
                .clob_midpoint
                .map(|q| Arc::new(RateLimiter::direct(q))),
            clob_post_order_burst: config
                .clob_post_order
                .as_ref()
                .map(|mq| Arc::new(RateLimiter::direct(mq.burst))),
            clob_post_order_sustained: config
                .clob_post_order
                .as_ref()
                .map(|mq| Arc::new(RateLimiter::direct(mq.sustained))),
            clob_delete_order_burst: config
                .clob_delete_order
                .as_ref()
                .map(|mq| Arc::new(RateLimiter::direct(mq.burst))),
            clob_delete_order_sustained: config
                .clob_delete_order
                .as_ref()
                .map(|mq| Arc::new(RateLimiter::direct(mq.sustained))),
            clob_submit: config.clob_submit.map(|q| Arc::new(RateLimiter::direct(q))),
            clob_user_pnl: config
                .clob_user_pnl
                .map(|q| Arc::new(RateLimiter::direct(q))),

            // Gamma
            gamma_general: config
                .gamma_general
                .map(|q| Arc::new(RateLimiter::direct(q))),
            gamma_events: config
                .gamma_events
                .map(|q| Arc::new(RateLimiter::direct(q))),
            gamma_markets: config
                .gamma_markets
                .map(|q| Arc::new(RateLimiter::direct(q))),
            gamma_markets_events: config
                .gamma_markets_events
                .map(|q| Arc::new(RateLimiter::direct(q))),
            gamma_comments: config
                .gamma_comments
                .map(|q| Arc::new(RateLimiter::direct(q))),
            gamma_tags: config.gamma_tags.map(|q| Arc::new(RateLimiter::direct(q))),
            gamma_search: config
                .gamma_search
                .map(|q| Arc::new(RateLimiter::direct(q))),

            // Data
            data_general: config
                .data_general
                .map(|q| Arc::new(RateLimiter::direct(q))),
            data_trades: config.data_trades.map(|q| Arc::new(RateLimiter::direct(q))),
            data_positions: config
                .data_positions
                .map(|q| Arc::new(RateLimiter::direct(q))),
            data_closed_positions: config
                .data_closed_positions
                .map(|q| Arc::new(RateLimiter::direct(q))),

            // Bridge
            bridge_general: config
                .bridge_general
                .map(|q| Arc::new(RateLimiter::direct(q))),
        }
    }
}

/// API type detected from the request URL.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApiType {
    /// CLOB trading API
    Clob,
    /// Gamma metadata API
    Gamma,
    /// Data API
    Data,
    /// Bridge deposit API
    Bridge,
    /// Unknown/unrecognized API
    Unknown,
}

/// Specific endpoint detected from the request.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Endpoint {
    // CLOB endpoints
    /// CLOB order book endpoint
    ClobBook,
    /// CLOB price endpoint
    ClobPrice,
    /// CLOB midpoint endpoint
    ClobMidpoint,
    /// CLOB POST order endpoint
    ClobPostOrder,
    /// CLOB DELETE order endpoint
    ClobDeleteOrder,
    /// CLOB submit/relayer endpoint
    ClobSubmit,
    /// CLOB user PNL endpoint
    ClobUserPnl,
    /// General CLOB endpoint
    ClobGeneral,

    // Gamma endpoints
    /// Gamma events endpoint
    GammaEvents,
    /// Gamma markets endpoint
    GammaMarkets,
    /// Gamma markets events listing
    GammaMarketsEvents,
    /// Gamma comments endpoint
    GammaComments,
    /// Gamma tags endpoint
    GammaTags,
    /// Gamma search endpoint
    GammaSearch,
    /// General Gamma endpoint
    GammaGeneral,

    // Data endpoints
    /// Data trades endpoint
    DataTrades,
    /// Data positions endpoint
    DataPositions,
    /// Data closed positions endpoint
    DataClosedPositions,
    /// General Data API endpoint
    DataGeneral,

    // Bridge endpoints
    /// General Bridge API endpoint
    BridgeGeneral,

    /// Unknown/unrecognized endpoint
    Unknown,
}

/// Detect the API type and specific endpoint from a request URL and method.
///
/// # Arguments
///
/// * `url` - The request URL
/// * `method` - The HTTP method
///
/// # Returns
///
/// A tuple of `(ApiType, Endpoint)` identifying the request.
#[must_use]
pub fn detect_endpoint(url: &Url, method: &Method) -> (ApiType, Endpoint) {
    let host = url.host_str().unwrap_or("");
    let path = url.path();

    // Detect API type from host
    let api_type = if host.contains("clob.polymarket.com")
        || host.contains("localhost") && path.starts_with("/clob")
    {
        ApiType::Clob
    } else if host.contains("gamma-api.polymarket.com")
        || host.contains("localhost") && path.starts_with("/gamma")
    {
        ApiType::Gamma
    } else if host.contains("data-api.polymarket.com")
        || host.contains("localhost") && path.starts_with("/data")
    {
        ApiType::Data
    } else if host.contains("bridge.polymarket.com")
        || host.contains("localhost") && path.starts_with("/bridge")
    {
        ApiType::Bridge
    } else {
        ApiType::Unknown
    };

    // Detect specific endpoint
    let endpoint = match (api_type, method.as_str(), path) {
        // CLOB endpoints
        (ApiType::Clob, "GET", p) if p.starts_with("/book") => Endpoint::ClobBook,
        (ApiType::Clob, "GET", p) if p.starts_with("/price") && !p.starts_with("/prices") => {
            Endpoint::ClobPrice
        }
        (ApiType::Clob, "GET", p) if p.starts_with("/midpoint") => Endpoint::ClobMidpoint,
        (ApiType::Clob, "POST", "/order" | "/orders") => Endpoint::ClobPostOrder,
        (ApiType::Clob, "DELETE", p) if p.starts_with("/order") => Endpoint::ClobDeleteOrder,
        (ApiType::Clob, "POST", "/submit") => Endpoint::ClobSubmit,
        (ApiType::Clob, _, p) if p.contains("rewards") && p.contains("user") => {
            Endpoint::ClobUserPnl
        }
        (ApiType::Clob, _, _) => Endpoint::ClobGeneral,

        // Gamma endpoints
        (ApiType::Gamma, "GET", p) if p.starts_with("/events") => Endpoint::GammaEvents,
        (ApiType::Gamma, "GET", p) if p.starts_with("/markets") => {
            // Check if it's the markets events listing endpoint
            if p.contains("/events") {
                Endpoint::GammaMarketsEvents
            } else {
                Endpoint::GammaMarkets
            }
        }
        (ApiType::Gamma, "GET", p) if p.starts_with("/comments") => Endpoint::GammaComments,
        (ApiType::Gamma, "GET", p) if p.starts_with("/tags") => Endpoint::GammaTags,
        (ApiType::Gamma, "GET", "/public-search" | "/search") => Endpoint::GammaSearch,
        (ApiType::Gamma, _, _) => Endpoint::GammaGeneral,

        // Data endpoints
        (ApiType::Data, "GET", "/trades") => Endpoint::DataTrades,
        (ApiType::Data, "GET", "/positions") => Endpoint::DataPositions,
        (ApiType::Data, "GET", "/closed-positions") => Endpoint::DataClosedPositions,
        (ApiType::Data, _, _) => Endpoint::DataGeneral,

        // Bridge endpoints
        (ApiType::Bridge, _, _) => Endpoint::BridgeGeneral,

        // Unknown
        _ => Endpoint::Unknown,
    };

    (api_type, endpoint)
}

/// Check rate limits for a request and wait if necessary.
///
/// This function checks endpoint-specific, API-level, and global rate limiters
/// in that order (most specific to least specific). It will wait asynchronously
/// if any limiter indicates the quota is exhausted.
///
/// # Arguments
///
/// * `limiters` - The collection of rate limiters
/// * `api_type` - The detected API type
/// * `endpoint` - The detected specific endpoint
///
/// # Errors
///
/// Currently, does not return errors, but waits until quota is available.
/// Future versions may add fail-fast behavior.
pub async fn check(
    limiters: &RateLimiters,
    api_type: ApiType,
    endpoint: Endpoint,
) -> crate::Result<()> {
    // Check endpoint-specific limiters first (most specific)
    match endpoint {
        Endpoint::ClobBook => {
            if let Some(limiter) = &limiters.clob_book {
                limiter.until_ready().await;
            }
        }
        Endpoint::ClobPrice => {
            if let Some(limiter) = &limiters.clob_price {
                limiter.until_ready().await;
            }
        }
        Endpoint::ClobMidpoint => {
            if let Some(limiter) = &limiters.clob_midpoint {
                limiter.until_ready().await;
            }
        }
        Endpoint::ClobPostOrder => {
            // Check both burst and sustained limits
            if let Some(limiter) = &limiters.clob_post_order_burst {
                limiter.until_ready().await;
            }
            if let Some(limiter) = &limiters.clob_post_order_sustained {
                limiter.until_ready().await;
            }
        }
        Endpoint::ClobDeleteOrder => {
            // Check both burst and sustained limits
            if let Some(limiter) = &limiters.clob_delete_order_burst {
                limiter.until_ready().await;
            }
            if let Some(limiter) = &limiters.clob_delete_order_sustained {
                limiter.until_ready().await;
            }
        }
        Endpoint::ClobSubmit => {
            if let Some(limiter) = &limiters.clob_submit {
                limiter.until_ready().await;
            }
        }
        Endpoint::ClobUserPnl => {
            if let Some(limiter) = &limiters.clob_user_pnl {
                limiter.until_ready().await;
            }
        }
        Endpoint::GammaEvents => {
            if let Some(limiter) = &limiters.gamma_events {
                limiter.until_ready().await;
            }
        }
        Endpoint::GammaMarkets => {
            if let Some(limiter) = &limiters.gamma_markets {
                limiter.until_ready().await;
            }
        }
        Endpoint::GammaMarketsEvents => {
            if let Some(limiter) = &limiters.gamma_markets_events {
                limiter.until_ready().await;
            }
        }
        Endpoint::GammaComments => {
            if let Some(limiter) = &limiters.gamma_comments {
                limiter.until_ready().await;
            }
        }
        Endpoint::GammaTags => {
            if let Some(limiter) = &limiters.gamma_tags {
                limiter.until_ready().await;
            }
        }
        Endpoint::GammaSearch => {
            if let Some(limiter) = &limiters.gamma_search {
                limiter.until_ready().await;
            }
        }
        Endpoint::DataTrades => {
            if let Some(limiter) = &limiters.data_trades {
                limiter.until_ready().await;
            }
        }
        Endpoint::DataPositions => {
            if let Some(limiter) = &limiters.data_positions {
                limiter.until_ready().await;
            }
        }
        Endpoint::DataClosedPositions => {
            if let Some(limiter) = &limiters.data_closed_positions {
                limiter.until_ready().await;
            }
        }
        _ => {}
    }

    // Check general API-level limiter (less specific)
    let general_limiter = match api_type {
        ApiType::Clob => &limiters.clob_general,
        ApiType::Gamma => &limiters.gamma_general,
        ApiType::Data => &limiters.data_general,
        ApiType::Bridge => &limiters.bridge_general,
        ApiType::Unknown => &None,
    };

    if let Some(limiter) = general_limiter {
        limiter.until_ready().await;
    }

    // Check global limiter (least specific)
    if let Some(limiter) = &limiters.global {
        limiter.until_ready().await;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_clob_book_endpoint() {
        let url = Url::parse("https://clob.polymarket.com/book?token_id=123").unwrap();
        let method = Method::GET;
        let (api, endpoint) = detect_endpoint(&url, &method);
        assert_eq!(api, ApiType::Clob);
        assert_eq!(endpoint, Endpoint::ClobBook);
    }

    #[test]
    fn detect_clob_post_order() {
        let url = Url::parse("https://clob.polymarket.com/order").unwrap();
        let method = Method::POST;
        let (api, endpoint) = detect_endpoint(&url, &method);
        assert_eq!(api, ApiType::Clob);
        assert_eq!(endpoint, Endpoint::ClobPostOrder);
    }

    #[test]
    fn detect_gamma_events() {
        let url = Url::parse("https://gamma-api.polymarket.com/events").unwrap();
        let method = Method::GET;
        let (api, endpoint) = detect_endpoint(&url, &method);
        assert_eq!(api, ApiType::Gamma);
        assert_eq!(endpoint, Endpoint::GammaEvents);
    }

    #[test]
    fn detect_data_trades() {
        let url = Url::parse("https://data-api.polymarket.com/trades").unwrap();
        let method = Method::GET;
        let (api, endpoint) = detect_endpoint(&url, &method);
        assert_eq!(api, ApiType::Data);
        assert_eq!(endpoint, Endpoint::DataTrades);
    }

    #[test]
    fn default_config_has_limits() {
        let config = Config::default();
        assert!(config.global_limit.is_some());
        assert!(config.clob_general.is_some());
        assert!(config.gamma_general.is_some());
    }

    #[test]
    fn disabled_config_has_no_limits() {
        let config = Config::disabled();
        assert!(config.global_limit.is_none());
        assert!(config.clob_general.is_none());
        assert!(config.gamma_general.is_none());
    }

    #[tokio::test]
    async fn rate_limiters_can_be_created() {
        let config = Config::default();
        let limiters = RateLimiters::new(&config);
        assert!(limiters.global.is_some());
        assert!(limiters.clob_general.is_some());
    }
}
