//! Finding code by a byte pattern.
//!
//! A pattern is hex bytes separated by spaces, with `?` or `??` for any byte:
//! `"48 89 5C 24 ?? 57"`. It's searched for in a loaded module's executable
//! sections and must match exactly once, so a pattern that no longer fits the
//! program fails instead of landing somewhere else. [`Hook::scan`] and
//! [`Injection::scan`] patch what a pattern finds.
//!
//! [`Hook::scan`]: crate::Hook::scan
//! [`Injection::scan`]: crate::Injection::scan
//!
//! # Examples
//!
//! ```no_run
//! let address = imping_hook::scan::find("48 89 5C 24 ?? 57 48 83 EC 20")?;
//! let address = imping_hook::scan::find_in("engine.dll", "48 89 5C 24 ?? 57")?;
//! # Ok::<(), imping_hook::Error>(())
//! ```

use crate::error::{Error, Result};
use pelite::image::IMAGE_SCN_MEM_EXECUTE;
use pelite::pattern::Atom;
use pelite::pe::{Pe, PeView};

/// Finds the one place in the main module's code that `pattern` matches.
///
/// # Errors
///
/// - [`Error::InvalidPattern`] if `pattern` can't be parsed.
/// - [`Error::PatternNotFound`] or [`Error::PatternNotUnique`] unless it
///   matches exactly once.
pub fn find(pattern: &str) -> Result<*const ()> {
    Search::new(pattern).locate()
}

/// Finds the one place in a loaded module's code that `pattern` matches.
///
/// `module` is a module name such as `"engine.dll"`. It must stay loaded while
/// it's searched.
///
/// # Errors
///
/// As for [`find`], plus [`Error::ModuleNotFound`] if no module of that name is
/// loaded.
pub fn find_in(module: &str, pattern: &str) -> Result<*const ()> {
    Search::new(pattern).in_module(module).locate()
}

/// Where a hook or injection goes: an address, or the result of a search.
pub(crate) enum Target {
    Address(*const ()),
    Search(Search),
}

impl Target {
    /// Returns the address, running the search if there is one.
    pub(crate) fn resolve(self) -> Result<*const ()> {
        match self {
            Target::Address(address) => Ok(address),
            Target::Search(search) => search.locate(),
        }
    }
}

/// A pattern search, plus what to do with its match.
pub(crate) struct Search {
    pattern: String,
    module: Option<String>,
    offset: isize,
    follow_call: bool,
}

impl Search {
    pub(crate) fn new(pattern: &str) -> Self {
        Search {
            pattern: pattern.to_owned(),
            module: None,
            offset: 0,
            follow_call: false,
        }
    }

    pub(crate) fn in_module(mut self, module: &str) -> Self {
        self.module = Some(module.to_owned());
        self
    }

    pub(crate) fn offset(mut self, bytes: isize) -> Self {
        self.offset = bytes;
        self
    }

    pub(crate) fn follow_call(mut self) -> Self {
        self.follow_call = true;
        self
    }

    /// Runs the search and returns the address it points at.
    pub(crate) fn locate(&self) -> Result<*const ()> {
        let bytes = parse(&self.pattern)?;
        if self.follow_call {
            self.check_call(&bytes)?;
        }
        let base = crate::sys::module_base(self.module.as_deref()).ok_or_else(|| {
            Error::ModuleNotFound {
                name: self
                    .module
                    .clone()
                    .unwrap_or_else(|| "main module".to_owned()),
            }
        })?;

        let mut atoms = vec![Atom::Save(0)];
        atoms.extend(bytes.iter().map(|&(byte, _)| match byte {
            Some(byte) => Atom::Byte(byte),
            None => Atom::Skip(1),
        }));

        // SAFETY: `base` is a module the loader has mapped, and the caller keeps
        // it loaded while it's searched.
        let view = unsafe { PeView::module(base) };
        let scanner = view.scanner();
        let (mut first, mut matches) = (None, 0);
        for section in view.section_headers().iter() {
            if section.Characteristics & IMAGE_SCN_MEM_EXECUTE == 0 {
                continue;
            }
            let start = section.VirtualAddress;
            let size = section.VirtualSize.max(section.SizeOfRawData);
            let mut found = scanner.matches(&atoms, start..start + size);
            let mut save = [0; 1];
            while found.next(&mut save) {
                first.get_or_insert(save[0]);
                matches += 1;
            }
        }
        let rva = match (first, matches) {
            (Some(rva), 1) => rva,
            (None, _) => {
                return Err(Error::PatternNotFound {
                    pattern: self.pattern.clone(),
                });
            }
            _ => {
                return Err(Error::PatternNotUnique {
                    pattern: self.pattern.clone(),
                    matches,
                });
            }
        };

        let mut address = (base as usize + rva as usize).wrapping_add_signed(self.offset);
        if self.follow_call {
            // SAFETY: `check_call` made sure the match covers the whole call, so
            // its displacement is mapped code.
            let displacement = unsafe { ((address + 1) as *const i32).read_unaligned() };
            address = (address + 5).wrapping_add_signed(displacement as isize);
        }
        Ok(address as *const ())
    }

    /// Checks the pattern spells out a `call` or `jmp` (`E8` or `E9`) at the
    /// offset, with room for its 4-byte displacement.
    fn check_call(&self, bytes: &[(Option<u8>, usize)]) -> Result<()> {
        let opcode = usize::try_from(self.offset)
            .ok()
            .filter(|&at| at + 5 <= bytes.len());
        match opcode.map(|at| bytes[at]) {
            Some((Some(0xE8 | 0xE9), _)) => Ok(()),
            Some((_, position)) => Err(self.invalid_at(position)),
            None => Err(self.invalid_at(self.pattern.len())),
        }
    }

    fn invalid_at(&self, position: usize) -> Error {
        Error::InvalidPattern {
            pattern: self.pattern.clone(),
            position,
        }
    }
}

/// Parses a pattern into its bytes (`None` for a wildcard), each with the
/// position of its token in `pattern`.
fn parse(pattern: &str) -> Result<Vec<(Option<u8>, usize)>> {
    let invalid = |position| Error::InvalidPattern {
        pattern: pattern.to_owned(),
        position,
    };
    let mut bytes = Vec::new();
    for token in pattern.split_ascii_whitespace() {
        let position = token.as_ptr() as usize - pattern.as_ptr() as usize;
        let byte = match token {
            "?" | "??" => None,
            // from_str_radix alone would also take a sign, like "+1".
            _ if token.len() == 2 && token.bytes().all(|c| c.is_ascii_hexdigit()) => {
                Some(u8::from_str_radix(token, 16).map_err(|_| invalid(position))?)
            }
            _ => return Err(invalid(position)),
        };
        bytes.push((byte, position));
    }
    if bytes.iter().all(|(byte, _)| byte.is_none()) {
        return Err(invalid(0));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn position(pattern: &str) -> Option<usize> {
        match parse(pattern) {
            Err(Error::InvalidPattern { position, .. }) => Some(position),
            _ => None,
        }
    }

    #[test]
    fn parses_bytes_and_wildcards() {
        let bytes: Vec<_> = parse("48 ? 5c ??")
            .unwrap()
            .into_iter()
            .map(|(b, _)| b)
            .collect();
        assert_eq!(bytes, [Some(0x48), None, Some(0x5c), None]);
    }

    #[test]
    fn points_at_the_bad_token() {
        assert_eq!(position("48 8B ZZ"), Some(6));
        assert_eq!(position("48 8"), Some(3));
        assert_eq!(position("48  +1"), Some(4));
        assert_eq!(position("48 ???"), Some(3));
    }

    #[test]
    fn rejects_empty_and_all_wildcard_patterns() {
        assert_eq!(position(""), Some(0));
        assert_eq!(position("?? ??"), Some(0));
    }

    #[test]
    fn follow_call_needs_the_whole_call() {
        let check = |pattern: &str, offset| Search::new(pattern).offset(offset).follow_call();
        assert!(
            check("E8 ?? ?? ?? ??", 0)
                .check_call(&parse("E8 ?? ?? ?? ??").unwrap())
                .is_ok()
        );
        assert!(
            check("48 E9 ?? ?? ?? ??", 1)
                .check_call(&parse("48 E9 ?? ?? ?? ??").unwrap())
                .is_ok()
        );
        let short = check("E8 ?? ??", 0);
        assert!(matches!(
            short.check_call(&parse("E8 ?? ??").unwrap()),
            Err(Error::InvalidPattern { position: 8, .. })
        ));
        let wrong = check("48 8B ?? ?? ?? ??", 1);
        assert!(matches!(
            wrong.check_call(&parse("48 8B ?? ?? ?? ??").unwrap()),
            Err(Error::InvalidPattern { position: 3, .. })
        ));
    }
}
