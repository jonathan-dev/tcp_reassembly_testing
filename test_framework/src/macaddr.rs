/// A MAC address.
#[derive(PartialEq, Eq, Clone, Copy, Default, Hash, Ord, PartialOrd)]
pub struct MacAddr(pub u8, pub u8, pub u8, pub u8, pub u8, pub u8);

impl MacAddr {
    /// Construct a new `MacAddr` instance.
    pub fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> MacAddr {
        MacAddr(a, b, c, d, e, f)
    }
}

/// Represents an error which occurred whilst parsing a MAC address.
#[derive(Copy, Debug, PartialEq, Eq, Clone)]
pub enum ParseMacAddrErr {
    /// The MAC address has too many components, eg. 00:11:22:33:44:55:66.
    TooManyComponents,
    /// The MAC address has too few components, eg. 00:11.
    TooFewComponents,
    /// One of the components contains an invalid value, eg. 00:GG:22:33:44:55.
    InvalidComponent,
}

impl fmt::Display for MacAddr {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(
            fmt,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0, self.1, self.2, self.3, self.4, self.5
        )
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, fmt)
    }
}

impl Error for ParseMacAddrErr {}

impl ParseMacAddrErr {
    fn description(&self) -> &str {
        match *self {
            ParseMacAddrErr::TooManyComponents => "Too many components in a MAC address string",
            ParseMacAddrErr::TooFewComponents => "Too few components in a MAC address string",
            ParseMacAddrErr::InvalidComponent => "Invalid component in a MAC address string",
        }
    }
}

impl fmt::Display for ParseMacAddrErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

impl FromStr for MacAddr {
    type Err = ParseMacAddrErr;
    fn from_str(s: &str) -> Result<MacAddr, ParseMacAddrErr> {
        let mut parts = [0u8; 6];
        let splits = s.split(':');
        let mut i = 0;
        for split in splits {
            if i == 6 {
                return Err(ParseMacAddrErr::TooManyComponents);
            }
            match u8::from_str_radix(split, 16) {
                Ok(b) if split.len() != 0 => parts[i] = b,
                _ => return Err(ParseMacAddrErr::InvalidComponent),
            }
            i += 1;
        }

        if i == 6 {
            Ok(MacAddr(
                parts[0], parts[1], parts[2], parts[3], parts[4], parts[5],
            ))
        } else {
            Err(ParseMacAddrErr::TooFewComponents)
        }
    }
}
