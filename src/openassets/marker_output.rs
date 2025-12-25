use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use std::fmt;
use std::io::{Read, Write};

use tapyrus::blockdata::script::Instruction;
use tapyrus::consensus::encode::Error;
use tapyrus::consensus::{deserialize, Decodable, Encodable};
use tapyrus::{TxOut, VarInt};

pub const MARKER: u16 = 0x4f41;
pub const VERSION: u16 = 0x0100;

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct Payload {
    pub quantities: Vec<u64>,
    pub metadata: Metadata,
}

impl Encodable for Payload {
    fn consensus_encode<S: Write>(&self, mut s: S) -> Result<usize, Error> {
        let mut len = MARKER.to_be().consensus_encode(&mut s)?;
        len += VERSION.to_be().consensus_encode(&mut s)?;
        len += VarInt(self.quantities.len() as u64).consensus_encode(&mut s)?;
        // asset quantity
        for &q in self.quantities.iter() {
            let mut value: u64 = q;
            loop {
                let mut byte = value & 0x7F;
                value >>= 7;
                if value != 0 {
                    byte |= 0x80;
                }
                len += Encodable::consensus_encode(&(byte as u8), &mut s)?;
                if value == 0 {
                    break;
                }
            }
        }
        len += self.metadata.consensus_encode(&mut s)?;
        Ok(len)
    }
}

impl Decodable for Payload {
    fn consensus_decode<D: Read>(mut d: D) -> Result<Payload, Error> {
        let marker: u16 = Decodable::consensus_decode(&mut d)?;
        if marker != MARKER.to_be() {
            return Err(Error::ParseFailed("Invalid marker."));
        }

        let version: u16 = Decodable::consensus_decode(&mut d)?;
        if version != VERSION.to_be() {
            return Err(Error::ParseFailed("Invalid version."));
        }

        let VarInt(count): VarInt = Decodable::consensus_decode(&mut d)?;
        let mut quantities: Vec<u64> = Vec::with_capacity(count as usize);

        for _ in 0..count {
            let mut value: u64 = 0;
            let mut offset: u64 = 0;
            loop {
                let b: u8 = Decodable::consensus_decode(&mut d)?;
                value |= ((b as u64) & 0x7f) << offset;
                if (b as u64) & 0x80 == 0 {
                    break;
                }
                offset += 7;
            }
            quantities.push(value);
        }

        let payload = Payload {
            quantities,
            metadata: Decodable::consensus_decode(d)?,
        };
        return Ok(payload);
    }
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct Metadata(Vec<u8>);

impl Metadata {
    pub fn new(data: Vec<u8>) -> Self {
        Metadata(data)
    }
}
impl fmt::Display for Metadata {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match String::from_utf8(self.0.clone()) {
            Ok(s) => write!(f, "{}", s),
            _ => panic!("invalid utf-8 string"),
        }
    }
}

impl Encodable for Metadata {
    fn consensus_encode<S: Write>(&self, s: S) -> Result<usize, Error> {
        self.0.consensus_encode(s)
    }
}

impl Decodable for Metadata {
    fn consensus_decode<D: Read>(d: D) -> Result<Metadata, Error> {
        Ok(Metadata(Decodable::consensus_decode(d)?))
    }
}

impl Serialize for Metadata {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Metadata", 2)?;
        let hex = hex::encode(self.0.clone());
        state.serialize_field("hex", &hex)?;
        match String::from_utf8(self.0.clone()) {
            Ok(s) => state.serialize_field("utf8", &s)?,
            _ => {}
        }
        state.end()
    }
}

pub trait TxOutExt {
    fn get_op_return_data(&self) -> Vec<u8>;

    fn is_openassets_marker(&self) -> bool;

    fn get_oa_payload(&self) -> Result<Payload, Error>;
}

impl TxOutExt for TxOut {
    fn get_op_return_data(&self) -> Vec<u8> {
        if self.script_pubkey.is_op_return() {
            let mut script_iter = self.script_pubkey.instructions();
            script_iter.next(); // OP_RETURN
            let item = script_iter.next();
            if item.is_some() {
                return match item.unwrap().ok() {
                    Some(Instruction::PushBytes(value)) => value.to_vec(),
                    _ => vec![],
                };
            } else {
                return vec![];
            }
        } else {
            return vec![];
        }
    }

    fn is_openassets_marker(&self) -> bool {
        if self.script_pubkey.is_op_return() {
            let payload: Result<Payload, _> = self.get_oa_payload();
            return payload.is_ok();
        } else {
            return false;
        }
    }

    fn get_oa_payload(&self) -> Result<Payload, Error> {
        let op_return_data: Vec<u8> = self.get_op_return_data();
        let payload: Result<Payload, _> = deserialize(&op_return_data);
        return payload;
    }
}

#[cfg(test)]
mod tests {
    use hex::decode as hex_decode;
    use crate::openassets::marker_output::{Metadata, Payload, TxOutExt};
    use serde_json::json;
    use tapyrus::blockdata::script::Builder;
    use tapyrus::consensus::serialize;
    use tapyrus::hashes::hex::FromHex;
    use tapyrus::{Script, TxOut};

    #[test]
    fn test_op_return_data() {
        // op return data
        let script: Script = Builder::from(
            hex_decode(
                "6a244f4101000364007b1b753d68747470733a2f2f6370722e736d2f35596753553150672d71",
            )
            .unwrap(),
        )
        .into_script();
        let txout = TxOut {
            value: 0,
            script_pubkey: script,
        };
        assert_eq!(
            Vec::<u8>::from_hex(
                "4f4101000364007b1b753d68747470733a2f2f6370722e736d2f35596753553150672d71"
            )
            .unwrap(),
            txout.get_op_return_data()
        );

        // no op return
        let script: Script = Builder::from(
            hex_decode("76a91446c2fbfbecc99a63148fa076de58cf29b0bcf0b088ac").unwrap(),
        )
        .into_script();
        let no_data = TxOut {
            value: 0,
            script_pubkey: script,
        };
        assert_eq!(0, no_data.get_op_return_data().len());
    }

    #[test]
    fn test_is_openassets_marker() {
        // no op return
        let no_data = TxOut {
            value: 0,
            script_pubkey: Builder::from(
                hex_decode("76a91446c2fbfbecc99a63148fa076de58cf29b0bcf0b088ac").unwrap(),
            )
            .into_script(),
        };
        assert!(!no_data.is_openassets_marker());

        // valid marker
        let valid_marker = TxOut {
            value: 0,
            script_pubkey: Builder::from(
                hex_decode(
                    "6a244f4101000364007b1b753d68747470733a2f2f6370722e736d2f35596753553150672d71",
                )
                .unwrap(),
            )
            .into_script(),
        };
        assert!(valid_marker.is_openassets_marker());

        // invalid marker
        let invalid_marker = TxOut {
            value: 0,
            script_pubkey: Builder::from(
                hex_decode(
                    "6a4f4201000364007b1b753d68747470733a2f2f6370722e736d2f35596753553150672d71",
                )
                .unwrap(),
            )
            .into_script(),
        };
        assert!(!invalid_marker.is_openassets_marker());

        // invalid version
        let invalid_marker = TxOut {
            value: 0,
            script_pubkey: Builder::from(
                hex_decode(
                    "6a4f4102000364007b1b753d68747470733a2f2f6370722e736d2f35596753553150672d71",
                )
                .unwrap(),
            )
            .into_script(),
        };
        assert!(!invalid_marker.is_openassets_marker());

        // can not parse varint
        let invalid_marker = TxOut {
            value: 0,
            script_pubkey: Builder::from(hex_decode("6a4f410100ff").unwrap()).into_script(),
        };
        assert!(!invalid_marker.is_openassets_marker());

        // can not decode leb128 data(invalid format)
        let invalid_marker = TxOut {
            value: 0,
            script_pubkey: Builder::from(hex_decode("6a4f410100018f8f").unwrap()).into_script(),
        };
        assert!(!invalid_marker.is_openassets_marker());

        // can not decode leb128 data(EOFError)
        let invalid_marker = TxOut {
            value: 0,
            script_pubkey: Builder::from(hex_decode("6a4f410100028f7f").unwrap()).into_script(),
        };
        assert!(!invalid_marker.is_openassets_marker());

        // no metadata length
        let invalid_marker = TxOut {
            value: 0,
            script_pubkey: Builder::from(hex_decode("6a4f410100018f7f").unwrap()).into_script(),
        };
        assert!(!invalid_marker.is_openassets_marker());

        // invalid metadata length
        let invalid_marker = TxOut {
            value: 0,
            script_pubkey: Builder::from(
                hex_decode(
                    "6a4f4101000364007b1b753d68747470733a2f2f6370722e736d2f35596753553150672d",
                )
                .unwrap(),
            )
            .into_script(),
        };
        assert!(!invalid_marker.is_openassets_marker());
    }

    #[test]
    fn test_get_oa_payload() {
        // valid marker
        let marker_output = TxOut {
            value: 0,
            script_pubkey: Builder::from(
                hex_decode(
                    "6a244f4101000364007b1b753d68747470733a2f2f6370722e736d2f35596753553150672d71",
                )
                .unwrap(),
            )
            .into_script(),
        };
        let payload: Payload = marker_output.get_oa_payload().unwrap();
        assert_eq!(vec![100, 0, 123], payload.quantities);
        assert_eq!(
            "u=https://cpr.sm/5YgSU1Pg-q".to_string(),
            payload.metadata.to_string()
        );

        // empty metadata
        let marker_output = TxOut {
            value: 0,
            script_pubkey: Builder::from(hex_decode("6a084f41010002014400").unwrap()).into_script(),
        };
        let payload: Payload = marker_output.get_oa_payload().unwrap();
        assert_eq!(vec![1, 68], payload.quantities);
        assert_eq!(Vec::<u8>::new(), payload.metadata.0);

        // binary metadata
        let marker_output = TxOut {
            value: 0,
            script_pubkey: Builder::from(
                hex_decode("6a104f4101000201440801020304fffefdfc").unwrap(),
            )
            .into_script(),
        };
        let payload: Payload = marker_output.get_oa_payload().unwrap();
        assert_eq!(
            vec![0x01, 0x02, 0x03, 0x04, 0xff, 0xfe, 0xfd, 0xfc],
            payload.metadata.0
        );

        // test for leb128
        let marker_output = TxOut {
            value: 0,
            script_pubkey: Builder::from(hex_decode("6a0b4f410100037f8001b96400").unwrap())
                .into_script(),
        };
        let payload: Payload = marker_output.get_oa_payload().unwrap();
        assert_eq!(vec![127, 128, 12857], payload.quantities);
    }

    #[test]
    fn test_encode_payload() {
        let metadata = Metadata("u=https://cpr.sm/5YgSU1Pg-q".as_bytes().to_vec());
        let payload = Payload {
            quantities: vec![100, 0, 123],
            metadata,
        };
        let result: Vec<u8> = serialize(&payload);
        assert_eq!(
            hex_decode("4f4101000364007b1b753d68747470733a2f2f6370722e736d2f35596753553150672d71")
                .unwrap(),
            result
        );

        let metadata = Metadata(vec![]);
        let payload = Payload {
            quantities: vec![1, 68],
            metadata,
        };
        let result: Vec<u8> = serialize(&payload);
        assert_eq!(hex_decode("4f41010002014400").unwrap(), result);

        // binary metadata
        let metadata = Metadata(vec![0x01, 0x02, 0x03, 0x04, 0xff, 0xfe, 0xfd, 0xfc]);
        let payload = Payload {
            quantities: vec![1, 68],
            metadata,
        };
        let result: Vec<u8> = serialize(&payload);
        assert_eq!(
            hex_decode("4f4101000201440801020304fffefdfc").unwrap(),
            result
        );

        // test for leb128
        let metadata = Metadata(vec![]);
        let payload = Payload {
            quantities: vec![127, 128, 12857],
            metadata,
        };
        let result: Vec<u8> = serialize(&payload);
        assert_eq!(hex_decode("4f410100037f8001b96400").unwrap(), result);
    }

    #[test]
    fn test_serialize_metadata() {
        // utf8 string
        let metadata = Metadata("u=https://cpr.sm/5YgSU1Pg-q".as_bytes().to_vec());
        assert_eq!(
            json!(metadata),
            json!({"hex": "753d68747470733a2f2f6370722e736d2f35596753553150672d71", "utf8": "u=https://cpr.sm/5YgSU1Pg-q"})
        );

        // empty
        let metadata = Metadata(vec![]);
        assert_eq!(json!(metadata), json!({"hex": "", "utf8": ""}));

        // binary
        let metadata = Metadata(vec![0x01, 0x02, 0x03, 0x04, 0xff, 0xfe, 0xfd, 0xfc]);
        assert_eq!(json!(metadata), json!({"hex": "01020304fffefdfc"}));
    }
}
