//! Optional offline IP→country resolution. The admin supplies a GeoLite2-Country
//! `.mmdb` file (no network, fully self-hosted); without it, geo is simply off and
//! every country resolves to None. Used for the jurisdiction placement constraint
//! (`geoip_allow`) and to label peers / this node by country.

use maxminddb::{geoip2, Reader};

pub struct GeoResolver {
    reader: Reader<Vec<u8>>,
}

impl GeoResolver {
    /// Open a GeoLite2 database; None (with a warning) if it can't be read.
    pub fn open(path: &str) -> Option<Self> {
        match Reader::open_readfile(path) {
            Ok(reader) => {
                tracing::info!(path, "GeoIP database loaded — geo-aware placement enabled");
                Some(GeoResolver { reader })
            }
            Err(e) => {
                tracing::warn!(path, error = %e, "GeoIP database load failed — geo features disabled");
                None
            }
        }
    }

    /// ISO country code for an IP (`"FR"`, `"US"`, …), or None.
    pub fn country(&self, ip: &str) -> Option<String> {
        let ip: std::net::IpAddr = ip.parse().ok()?;
        let c: geoip2::Country = self.reader.lookup(ip).ok()?;
        c.country.and_then(|x| x.iso_code).map(|s| s.to_string())
    }
}

/// Country of the host part of an `ip:port` (or bare ip) address.
pub fn country_of_addr(geo: &Option<GeoResolver>, addr: &str) -> Option<String> {
    let geo = geo.as_ref()?;
    let host = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr);
    geo.country(host)
}
