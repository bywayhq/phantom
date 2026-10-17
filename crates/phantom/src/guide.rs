//! Learn to use Phantom.
//!
//! Start with [`getting_started`], then choose a guide for the task at hand.
//! Each guide links to API documentation for the available options and limits.
//!
//! | Guide | What you'll do |
//! | --- | --- |
//! | [`getting_started`] | Install Phantom, send a request, and read the response |
//! | [`browser_profiles`] | Choose connection settings and request headers |
//! | [`requests_and_responses`] | Send data, handle status codes, and read bodies |
//! | [`proxies`] | Route requests through HTTP and SOCKS proxies |

#[doc = include_str!("docs/getting-started.md")]
pub mod getting_started {}

#[doc = include_str!("docs/browser-profiles.md")]
pub mod browser_profiles {}

#[doc = include_str!("docs/requests-and-responses.md")]
pub mod requests_and_responses {}

#[doc = include_str!("docs/proxies.md")]
pub mod proxies {}
