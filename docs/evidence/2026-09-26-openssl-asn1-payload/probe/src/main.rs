//! Spike only (round 4, task 5). For every payload file given, decodes
//! `SET OF SEQUENCE { type INTEGER, version ANY, value OCTET STRING }` with
//! der (RustCrypto, BER rules), rasn (BER codec) and bcder (BER mode), and
//! prints per crate: OK with the attribute count and an FNV-1a digest of the
//! (type bytes, value bytes) list in encoding order, or the error. The
//! Xcode double wrap (one outer OCTET STRING) is unwrapped with the same
//! crate first. Same digest for every crate and every BER spelling of one
//! payload = the crate read the same attributes.

use std::fmt::Write as _;

type Attrs = Vec<(Vec<u8>, Vec<u8>)>;

fn digest(attrs: &Attrs) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for (t, v) in attrs {
        for b in t.iter().chain([0xff_u8].iter()).chain(v.iter()).chain([0xfe_u8].iter()) {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
    }
    format!("{} attrs {:016x}", attrs.len(), h)
}

mod with_der {
    use super::Attrs;
    use der::asn1::{Any, Int, OctetString, SetOfVec};
    use der::{Decode, EncodingRules, Sequence, ValueOrd};

    #[derive(Sequence, ValueOrd, Clone, Debug, PartialEq, Eq)]
    pub struct Attr {
        ty: Int,
        version: Any,
        value: OctetString,
    }

    fn set(bytes: &[u8]) -> Result<Attrs, String> {
        let set = SetOfVec::<Attr>::from_ber(bytes).map_err(|e| e.to_string())?;
        Ok(set.iter().map(|a| (a.ty.as_bytes().to_vec(), a.value.as_bytes().to_vec())).collect())
    }

    pub fn read(bytes: &[u8]) -> Result<Attrs, String> {
        let _ = EncodingRules::Ber;
        match OctetString::from_ber(bytes) {
            Ok(wrapped) => set(wrapped.as_bytes()),
            Err(_) => set(bytes),
        }
    }
}

mod with_rasn {
    use super::Attrs;
    use rasn::prelude::*;

    #[derive(AsnType, Decode, Encode, Clone, Debug, PartialEq, Eq, Hash)]
    pub struct Attr {
        ty: Integer,
        version: Any,
        value: OctetString,
    }

    fn set(bytes: &[u8]) -> Result<Attrs, String> {
        let set: SetOf<Attr> = rasn::ber::decode(bytes).map_err(|e| e.to_string())?;
        Ok(set
            .to_vec()
            .into_iter()
            .map(|a| {
                let (buf, used) = a.ty.to_signed_bytes_be();
                (buf.as_ref()[..used].to_vec(), a.value.to_vec())
            })
            .collect())
    }

    pub fn read(bytes: &[u8]) -> Result<Attrs, String> {
        match rasn::ber::decode::<OctetString>(bytes) {
            Ok(wrapped) => set(&wrapped),
            Err(_) => set(bytes),
        }
    }
}

mod with_bcder {
    use super::Attrs;
    use bcder::decode::{Constructed, DecodeError};
    use bcder::{Integer, Mode, OctetString};

    fn set(bytes: &[u8]) -> Result<Attrs, String> {
        Constructed::decode(bytes, Mode::Ber, |cons| {
            cons.take_set(|cons| {
                let mut out = Attrs::new();
                while let Some(attr) = cons.take_opt_sequence(|cons| {
                    let ty = Integer::take_from(cons)?;
                    cons.skip_one()?;
                    let value = OctetString::take_from(cons)?;
                    Ok((ty.as_slice().to_vec(), value.to_bytes().to_vec()))
                })? {
                    out.push(attr);
                }
                Ok::<_, DecodeError<_>>(out)
            })
        })
        .map_err(|e| e.to_string())
    }

    pub fn read(bytes: &[u8]) -> Result<Attrs, String> {
        match Constructed::decode(bytes, Mode::Ber, |cons| OctetString::take_from(cons)) {
            Ok(wrapped) => set(&wrapped.to_bytes()),
            Err(_) => set(bytes),
        }
    }
}

fn main() {
    for path in std::env::args().skip(1) {
        let bytes = std::fs::read(&path).expect("readable");
        let name = std::path::Path::new(&path).file_name().unwrap().to_string_lossy().into_owned();
        let mut line = name;
        for (crate_name, result) in [
            ("der", with_der::read(&bytes)),
            ("rasn", with_rasn::read(&bytes)),
            ("bcder", with_bcder::read(&bytes)),
        ] {
            let text = match result {
                Ok(attrs) => digest(&attrs),
                Err(e) => format!("ERR {}", e.chars().take(70).collect::<String>().replace('\t', " ")),
            };
            let _ = write!(line, "\t{crate_name}: {text}");
        }
        println!("{line}");
    }
}
