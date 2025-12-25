use std::fmt::{self, Display, Formatter};
use tapyrus::consensus::encode;
use tapyrus::hashes::hex::FromHex;
use tapyrus::network::constants::Network;
use tapyrus::util::address::Payload;
use tapyrus::util::base58;

/// A Open Assets Address
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address {
    pub network: Network,
    pub payload: Payload,
}

const NAMESPACE: u8 = 0x13;

impl Address {
    pub fn new(
        payload: Payload,
        network: tapyrus::network::constants::Network,
    ) -> Result<Self, encode::Error> {
        Ok(Address { payload, network })
    }

    pub fn to_btc_addr(&self) -> Result<tapyrus::Address, encode::Error> {
        Ok(tapyrus::Address {
            network: self.network,
            payload: self.payload.clone(),
        })
    }
}

impl Display for Address {
    fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
        match self.payload {
            Payload::PubkeyHash(ref hash) => {
                let mut prefixed = [0; 22];
                prefixed[0] = NAMESPACE;
                prefixed[1] = match self.network {
                    Network::Prod => 0,
                    Network::Dev => 111,
                };
                prefixed[2..].copy_from_slice(&hash[..]);
                base58::check_encode_slice_to_fmt(fmt, &prefixed[..])
            }
            Payload::ScriptHash(ref hash) => {
                let mut prefixed = [0; 22];
                prefixed[0] = NAMESPACE;
                prefixed[1] = match self.network {
                    Network::Prod => 5,
                    Network::Dev => 196,
                };
                prefixed[2..].copy_from_slice(&hash[..]);
                base58::check_encode_slice_to_fmt(fmt, &prefixed[..])
            }
            Payload::ColoredPubkeyHash(ref color_id, ref hash) => {
                let mut prefixed = [0; 55];
                prefixed[0] = NAMESPACE;
                prefixed[1] = match self.network {
                    Network::Prod => 1,
                    Network::Dev => 112,
                };
                prefixed[2..35].copy_from_slice(&Vec::from_hex(&format!("{}", color_id)).unwrap());
                prefixed[35..].copy_from_slice(&hash[..]);
                base58::check_encode_slice_to_fmt(fmt, &prefixed[..])
            }
            Payload::ColoredScriptHash(ref color_id, ref hash) => {
                let mut prefixed = [0; 55];
                prefixed[0] = NAMESPACE;
                prefixed[1] = match self.network {
                    Network::Prod => 6,
                    Network::Dev => 197,
                };
                prefixed[2..35].copy_from_slice(&Vec::from_hex(&format!("{}", color_id)).unwrap());
                prefixed[35..].copy_from_slice(&hash[..]);
                base58::check_encode_slice_to_fmt(fmt, &prefixed[..])
            }
        }
    }
}

pub trait OAAddressConverter {
    fn to_oa_address(&self) -> Result<Address, encode::Error>;
}

impl OAAddressConverter for tapyrus::Address {
    fn to_oa_address(&self) -> Result<Address, encode::Error> {
        Address::new(self.payload.clone(), self.network)
    }
}

#[cfg(test)]
mod tests {
    use crate::openassets::address::OAAddressConverter;
    use std::str::FromStr;
    use std::string::ToString;
    use tapyrus::network::constants::Network;

    #[test]
    fn test_oa_address_for_p2kph() {
        // for Prod
        let addr = tapyrus::Address::from_str("1F2AQr6oqNtcJQ6p9SiCLQTrHuM9en44H8").unwrap();
        assert_eq!(addr.network, Network::Prod);
        assert_eq!(
            "akQz3f1v9JrnJAeGBC4pNzGNRdWXKan4U6E",
            addr.to_oa_address().unwrap().to_string()
        );
        assert_eq!(addr, addr.to_oa_address().unwrap().to_btc_addr().unwrap());

        // for Dev
        let dev_addr = tapyrus::Address::from_str("mkgW6hNYBctmqDtTTsTJrsf2Gh2NPtoCU4").unwrap();
        assert_eq!(dev_addr.network, Network::Dev);
        assert_eq!(
            "bWvePLsBsf6nThU3pWVZVWjZbcJCYQxHCpE",
            dev_addr.to_oa_address().unwrap().to_string()
        );
        assert_eq!(
            dev_addr,
            dev_addr.to_oa_address().unwrap().to_btc_addr().unwrap()
        );
    }

    #[test]
    fn test_oa_address_for_p2sh() {
        // for Prod
        let addr = tapyrus::Address::from_str("3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX").unwrap();
        assert_eq!(addr.network, Network::Prod);
        assert_eq!(
            "anQin2TDYaubr6M5MQM8kNXMitHc2hsmfGc",
            addr.to_oa_address().unwrap().to_string()
        );
        assert_eq!(addr, addr.to_oa_address().unwrap().to_btc_addr().unwrap());
        assert_eq!(addr, addr.to_oa_address().unwrap().to_btc_addr().unwrap());

        // for Dev
        let dev_addr = tapyrus::Address::from_str("2N6K6r2LEitDWRtYY2reSLcSQm2e2W9xEjB").unwrap();
        assert_eq!(dev_addr.network, Network::Dev);
        assert_eq!(
            "c7GGz6C9aCN7CJ8hu5UkczULz6dpCWSBVnF",
            dev_addr.to_oa_address().unwrap().to_string()
        );
        assert_eq!(
            dev_addr,
            dev_addr.to_oa_address().unwrap().to_btc_addr().unwrap()
        );
    }

    #[test]
    fn test_oa_address_for_cp2pkh() {
        // Color ID: c36db65fd59fd356f6729140571b5bcd6bb3b83492a16e1bf0a3884442fc3c8a0e
        // PubkeyHash: 8f55563b9a19f321c211e9b9f38cdf686ea07845

        // for Prod
        let addr = tapyrus::Address::from_str(
            "4Zxhb33iSoydtcKzWc7hpoRjtJh2W9otwDeqP5PbZHGoq7x6JndvyoFpAn5vzLCtLA5hyYTuJsH4gNP",
        )
        .unwrap();
        assert_eq!(addr.network, Network::Prod);
        assert_eq!(
            "mJkjc5fgLN5sbo5FHJDj5M5YuhmRYNS8D8A5EFg4tRuohzLfNCNf4L1k7xBRm46mReKxkaUnpZutQyeJ",
            addr.to_oa_address().unwrap().to_string()
        );
        assert_eq!(addr, addr.to_oa_address().unwrap().to_btc_addr().unwrap());

        // for Dev
        let dev_addr = tapyrus::Address::from_str(
            "2oLaMRRokHWpeVx78biGm6DUnfgUdENWy4SnSrqtpy3U8h642g55gfJxhrcRdjmLdJ7hknTzUoorTUdC",
        )
        .unwrap();
        assert_eq!(dev_addr.network, Network::Dev);
        assert_eq!(
            "o3XMFv4SNCnicQR2RPKt8cVbxV9D96eqHFPCqjSa7qg12rJmJZf6p1XT1e1mToXuAcHaoPQKQ4w1AmkL",
            dev_addr.to_oa_address().unwrap().to_string()
        );
        assert_eq!(
            dev_addr,
            dev_addr.to_oa_address().unwrap().to_btc_addr().unwrap()
        );
    }

    #[test]
    fn test_oa_address_for_cp2sh() {
        // Color ID: c36db65fd59fd356f6729140571b5bcd6bb3b83492a16e1bf0a3884442fc3c8a0e
        // ScriptHash: 8f55563b9a19f321c211e9b9f38cdf686ea07845

        // for Prod
        let addr = tapyrus::Address::from_str(
            "4Zxhb33iSoydtcKzWc7hpoRjtJh2W9otwDeqP5PbZHGoq7x6JndvyoFpAn5vzLCtLA5hyYTuJsH4gNP",
        )
        .unwrap();
        assert_eq!(addr.network, Network::Prod);
        assert_eq!(
            "mJkjc5fgLN5sbo5FHJDj5M5YuhmRYNS8D8A5EFg4tRuohzLfNCNf4L1k7xBRm46mReKxkaUnpZutQyeJ",
            addr.to_oa_address().unwrap().to_string()
        );
        assert_eq!(addr, addr.to_oa_address().unwrap().to_btc_addr().unwrap());

        // for Dev
        let dev_addr = tapyrus::Address::from_str(
            "2oLaMRRokHWpeVx78biGm6DUnfgUdENWy4SnSrqtpy3U8h642g55gfJxhrcRdjmLdJ7hknTzUoorTUdC",
        )
        .unwrap();
        assert_eq!(dev_addr.network, Network::Dev);
        assert_eq!(
            "o3XMFv4SNCnicQR2RPKt8cVbxV9D96eqHFPCqjSa7qg12rJmJZf6p1XT1e1mToXuAcHaoPQKQ4w1AmkL",
            dev_addr.to_oa_address().unwrap().to_string()
        );
        assert_eq!(
            dev_addr,
            dev_addr.to_oa_address().unwrap().to_btc_addr().unwrap()
        );
    }
}
