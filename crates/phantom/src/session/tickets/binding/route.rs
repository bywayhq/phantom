use crate::Route;

use super::{PreparationError, encoding::Encoder};

pub(super) fn encode(e: &mut Encoder, route: &Route) -> Result<(), PreparationError> {
    e.bytes(b"phantom-ticket-route")?;
    e.u16(2)?;
    match route {
        Route::Direct => e.u8(0),
        Route::HttpProxy(proxy) => {
            e.u8(1)?;
            proxy.encode_ticket_route(e)
        }
        Route::Socks4(proxy) => {
            e.u8(2)?;
            proxy.encode_ticket_route(e)
        }
        Route::Socks5(proxy) => {
            e.u8(3)?;
            proxy.encode_ticket_route(e)
        }
        Route::ConnectUdp(proxy) => {
            e.u8(4)?;
            proxy.encode_ticket_route(e)
        }
    }
}
