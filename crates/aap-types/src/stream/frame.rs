use super::*;

impl Header {
    pub fn parse(bytes: [u8; 5]) -> Result<Self> {
        let kind = match bytes[0] {
            1 => Kind::Pending,
            2 => Kind::Opened,
            3 => Kind::Data,
            4 => Kind::SendEnd,
            5 => Kind::Terminal,
            _ => return Err(ErrorCode::RequestInvalid.into()),
        };
        Self::new(
            kind,
            u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize,
        )
    }

    fn new(kind: Kind, length: usize) -> Result<Self> {
        if (kind == Kind::SendEnd) != (length == 0) {
            return Err(ErrorCode::RequestInvalid.into());
        }
        let max = if kind == Kind::Data {
            MAX_DATA_BYTES
        } else {
            MAX_CONTROL_BYTES
        };
        if length > max {
            return Err(ErrorCode::LimitExceeded.into());
        }
        Ok(Self { kind, length })
    }

    fn encode(self) -> [u8; 5] {
        let mut bytes = [self.kind as u8, 0, 0, 0, 0];
        bytes[1..].copy_from_slice(&(self.length as u32).to_be_bytes());
        bytes
    }
}

impl Frame {
    /// DATA shares its immutable allocation; encoding never copies the payload.
    /// Control fields are validated before serialization and remain bounded.
    pub fn encode(&self) -> Result<Encoded> {
        let (kind, payload) = match self {
            Self::Pending(value) => {
                value.validate()?;
                (Kind::Pending, control_bytes(value)?)
            }
            Self::Opened(value) => {
                value.validate()?;
                (Kind::Opened, control_bytes(value)?)
            }
            Self::Data(bytes) => (Kind::Data, bytes.clone()),
            Self::SendEnd => (Kind::SendEnd, Bytes::new()),
            Self::Terminal(value) => {
                value.validate()?;
                (Kind::Terminal, control_bytes(value)?)
            }
        };
        let header = Header::new(kind, payload.len())?.encode();
        Ok(Encoded { header, payload })
    }

    pub fn decode(header: Header, payload: Bytes) -> Result<Self> {
        if header.length != payload.len() {
            return Err(ErrorCode::RequestInvalid.into());
        }
        Ok(match header.kind {
            Kind::Pending => {
                let value: Pending = decode_control(&payload)?;
                value.validate()?;
                Self::Pending(value)
            }
            Kind::Opened => {
                let value: Opened = decode_control(&payload)?;
                value.validate()?;
                Self::Opened(value)
            }
            Kind::Data => Self::Data(payload),
            Kind::SendEnd => Self::SendEnd,
            Kind::Terminal => {
                let value: Terminal = decode_control(&payload)?;
                value.validate()?;
                Self::Terminal(value)
            }
        })
    }

    pub(super) fn header(&self) -> Result<Header> {
        Header::parse(self.encode()?.header)
    }
}

fn control_bytes(value: &impl Serialize) -> Result<Bytes> {
    // Only closed DTOs with prevalidated, bounded strings and scalar fields reach
    // this helper. No user-provided Value, map, or arbitrary body is serialized.
    let bytes = serde_json::to_vec(value).map_err(|_| ErrorCode::InternalError)?;
    if bytes.len() > MAX_CONTROL_BYTES {
        return Err(ErrorCode::LimitExceeded.into());
    }
    Ok(Bytes::from(bytes))
}
