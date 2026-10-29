//! Finds functions in this test executable by their own bytes, then hooks and
//! injects at what the scan finds.

use imping_hook::scan::{self, Pattern};
use imping_hook::{Error, Hook};

#[inline(never)]
extern "C" fn found(a: u64) -> u64 {
    std::hint::black_box(a).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0x0123_4567_89AB_CDEF
}

#[inline(never)]
extern "C" fn hooked(a: u64) -> u64 {
    std::hint::black_box(a).wrapping_mul(0xC2B2_AE3D_27D4_EB4F) ^ 0x1656_67B1_9E37_79F9
}

extern "C" fn replacement(a: u64) -> u64 {
    a + 1
}

#[inline(never)]
extern "C" fn callee(a: u64) -> u64 {
    std::hint::black_box(a).wrapping_mul(0x27D4_EB2F_1656_67C5) ^ 0x85EB_CA77_C2B2_AE63
}

#[inline(never)]
extern "C" fn caller(a: u64) -> u64 {
    callee(std::hint::black_box(a) ^ 0x7A3F_19C4_55E0_B2D1).wrapping_add(0x3C6E_F372)
}

fn hex(bytes: &[u8]) -> Vec<String> {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

/// Grows a pattern of the code at `at` until it matches exactly once.
fn unique_pattern(at: *const u8) -> String {
    for len in 8..=64 {
        // SAFETY: `at` is inside a function in this executable, followed by more
        // code.
        let bytes = unsafe { std::slice::from_raw_parts(at, len) };
        let pattern = hex(bytes).join(" ");
        if scan::find(&pattern).is_ok() {
            return pattern;
        }
    }
    panic!("no unique pattern at {at:p}");
}

#[test]
fn finds_a_function_by_its_bytes() {
    let pattern = unique_pattern(found as *const u8);
    assert_eq!(scan::find(&pattern), Ok(found as *const ()));
}

#[test]
fn wildcards_match_any_byte() {
    let pattern = unique_pattern(found as *const u8);
    let mut tokens: Vec<&str> = pattern.split(' ').collect();
    tokens[1] = "??";
    tokens[2] = "?";
    assert_eq!(scan::find(&tokens.join(" ")), Ok(found as *const ()));
}

#[test]
fn finds_in_a_named_module() {
    let exe = std::env::current_exe().unwrap();
    let name = exe.file_name().unwrap().to_str().unwrap();
    let pattern = unique_pattern(found as *const u8);
    assert_eq!(scan::find_in(name, &pattern), Ok(found as *const ()));
}

#[test]
fn a_common_pattern_is_not_unique() {
    // Every function ends in a `ret`.
    match scan::find("C3") {
        Err(Error::PatternNotUnique { pattern, matches }) => {
            assert_eq!(pattern, "C3");
            assert!(matches > 1, "{matches}");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_missing_pattern_is_not_found() {
    // `int1` is never emitted.
    let pattern = "F1 F1 F1 F1 F1 F1 F1 F1";
    assert_eq!(
        scan::find(pattern),
        Err(Error::PatternNotFound {
            pattern: pattern.to_owned()
        })
    );
}

#[test]
fn a_missing_module_is_reported() {
    assert_eq!(
        scan::find_in("imping-no-such-module.dll", "C3"),
        Err(Error::ModuleNotFound {
            name: "imping-no-such-module.dll".to_owned()
        })
    );
}

#[test]
fn an_invalid_pattern_names_the_position() {
    assert_eq!(
        scan::find("48 8B ZZ"),
        Err(Error::InvalidPattern {
            pattern: "48 8B ZZ".to_owned(),
            position: 6
        })
    );
}

#[test]
fn hooks_what_a_scan_finds_with_an_offset() {
    // The pattern starts inside the function, and the offset steps back to its
    // entry.
    // SAFETY: `hooked` is longer than four bytes.
    let pattern = unique_pattern(unsafe { (hooked as *const u8).add(4) });
    // SAFETY: the pattern finds `hooked`, four bytes before the match, and
    // `replacement` shares its signature.
    let hook = unsafe {
        Hook::scan(&pattern)
            .offset(-4)
            .redirect(replacement as extern "C" fn(u64) -> u64)
            .install()
            .unwrap()
    };
    let before = hooked(7);
    hook.enable().unwrap();
    assert_eq!(hooked(7), 8);
    hook.disable().unwrap();
    assert_eq!(hooked(7), before);
}

/// Finds `caller`'s call to `callee` and returns a pattern of the bytes just
/// before it, plus how far into the pattern the call is.
fn call_pattern() -> (String, usize) {
    let start = caller as *const u8;
    // SAFETY: `caller` is at least 128 bytes away from the end of the code.
    let code = unsafe { std::slice::from_raw_parts(start, 128) };
    let call = (0..code.len() - 5)
        .find(|&at| {
            let displacement = i32::from_le_bytes(code[at + 1..at + 5].try_into().unwrap());
            let target = (start as usize + at + 5).wrapping_add_signed(displacement as isize);
            code[at] == 0xE8 && target == callee as *const () as usize
        })
        .expect("`caller` calls `callee` directly");
    let mut pattern = None;
    for before in 4..=call {
        let mut tokens = hex(&code[call - before..=call]);
        tokens.extend(["??"; 4].map(String::from));
        let candidate = tokens.join(" ");
        if scan::find(&candidate).is_ok() {
            pattern = Some((candidate, before));
            break;
        }
    }
    pattern.expect("a unique pattern before the call")
}

#[test]
fn a_pattern_steps_from_its_match() {
    // SAFETY: `found` is longer than four bytes.
    let inner = unique_pattern(unsafe { (found as *const u8).add(4) });
    assert_eq!(
        Pattern::new(&inner).offset(-4).find(),
        Ok(found as *const ())
    );

    let (call, before) = call_pattern();
    let found = Pattern::new(&call)
        .offset(before as isize)
        .follow_call()
        .find();
    assert_eq!(found, Ok(callee as *const ()));
}

#[test]
fn follows_a_call_to_its_target() {
    let (pattern, before) = call_pattern();
    // SAFETY: the pattern's call goes to `callee`, which shares the
    // replacement's signature.
    let hook = unsafe {
        Hook::scan(&pattern)
            .offset(before as isize)
            .follow_call()
            .redirect(replacement as extern "C" fn(u64) -> u64)
            .install()
            .unwrap()
    };
    let before_hook = caller(5);
    hook.enable().unwrap();
    assert_eq!(caller(5), (5 ^ 0x7A3F_19C4_55E0_B2D1u64) + 1 + 0x3C6E_F372);
    hook.disable().unwrap();
    assert_eq!(caller(5), before_hook);
}

#[test]
fn follow_call_needs_the_call_in_the_pattern() {
    // SAFETY: the scan fails before anything is patched.
    let result = unsafe {
        Hook::scan("48 8B ?? ?? ??")
            .follow_call()
            .redirect(replacement as extern "C" fn(u64) -> u64)
            .install()
    };
    assert!(matches!(
        result,
        Err(Error::InvalidPattern { position: 0, .. })
    ));
}

#[cfg(target_arch = "x86_64")]
#[test]
fn injects_where_a_scan_matches() {
    use imping_hook::Injection;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[inline(never)]
    extern "C" fn injected(a: u64) -> u64 {
        std::hint::black_box(a).wrapping_mul(0x94D0_49BB_1331_11EB) ^ 0x2545_F491_4F6C_DD1D
    }
    static RUNS: AtomicUsize = AtomicUsize::new(0);

    let pattern = unique_pattern(injected as *const u8);
    // SAFETY: the pattern finds `injected`'s entry, and the callback only reads
    // registers.
    let injection = unsafe {
        Injection::scan(&pattern)
            .inspect(|_| {
                RUNS.fetch_add(1, Ordering::SeqCst);
            })
            .install()
            .unwrap()
    };
    injection.enable().unwrap();
    let result = injected(3);
    injection.disable().unwrap();
    assert_eq!(RUNS.load(Ordering::SeqCst), 1);
    assert_eq!(result, injected(3));
}
