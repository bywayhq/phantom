use std::{ops::Deref, sync::Arc};

use http::{HeaderMap, HeaderValue};

/// Registers a callback that preserves request-trailer order and field-name casing.
#[inline]
pub fn on_preserve_trailer<B, C>(req: &mut http::Request<B>, callback: C)
where
    C: OnPreserveTrailerCallback,
{
    req.extensions_mut()
        .insert(OnPreserveTrailer(Arc::new(callback)));
}

/// Visits request trailers in their exact wire order.
pub trait OnPreserveTrailerCallback: Sync + Send + 'static {
    /// Emits each request trailer using its caller-supplied field-name bytes.
    #[allow(clippy::type_complexity)]
    fn call_visit(
        &self,
        trailers: &HeaderMap,
        destination: &mut dyn FnMut(&dyn AsRef<[u8]>, &HeaderValue),
    );
}

#[derive(Clone)]
pub(crate) struct OnPreserveTrailer(Arc<dyn OnPreserveTrailerCallback>);

impl Deref for OnPreserveTrailer {
    type Target = Arc<dyn OnPreserveTrailerCallback>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
