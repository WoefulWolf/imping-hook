//! The CPU register context passed to register-context injections.

/// A captured x86-64 CPU context: the general-purpose registers, flags, the
/// instruction pointer, and the SSE registers, as seen at an injection site.
///
/// Passed to the closures of [`InjectionBuilder::inspect`](crate::InjectionBuilder::inspect)
/// (shared) and [`InjectionBuilder::modify`](crate::InjectionBuilder::modify)
/// (mutable). For `modify`, writing a field changes the corresponding register
/// before the original code resumes; see the field notes for `rsp`/`rip`.
///
/// The field order is the on-stack layout the injection stub reads and writes,
/// so it must not be reordered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Context {
    /// The `rflags` register.
    pub rflags: u64,
    /// The `rax` register.
    pub rax: u64,
    /// The `rbx` register.
    pub rbx: u64,
    /// The `rcx` register.
    pub rcx: u64,
    /// The `rdx` register.
    pub rdx: u64,
    /// The `rsi` register.
    pub rsi: u64,
    /// The `rdi` register.
    pub rdi: u64,
    /// The `rbp` register.
    pub rbp: u64,
    /// The stack pointer at the injection site.
    ///
    /// In `modify`, changing `rsp` only takes effect together with a changed
    /// [`rip`](Self::rip) (a redirect); otherwise the original code resumes on
    /// the original stack.
    pub rsp: u64,
    /// The `r8` register.
    pub r8: u64,
    /// The `r9` register.
    pub r9: u64,
    /// The `r10` register.
    pub r10: u64,
    /// The `r11` register.
    pub r11: u64,
    /// The `r12` register.
    pub r12: u64,
    /// The `r13` register.
    pub r13: u64,
    /// The `r14` register.
    pub r14: u64,
    /// The `r15` register.
    pub r15: u64,
    /// The address of the injection site (the instruction that was patched).
    ///
    /// In `modify`, leaving `rip` unchanged resumes the original code normally.
    /// Setting it to another address redirects execution there instead — the
    /// displaced original instructions are **not** run — using the (possibly
    /// changed) [`rsp`](Self::rsp).
    pub rip: u64,
    /// The SSE registers `xmm0`–`xmm15`.
    pub xmm: [Xmm; 16],
}

/// The 128-bit contents of one SSE (`xmm`) register, with helpers to read and
/// build the common lane layouts.
///
/// Stored as raw little-endian bytes, so no interpretation is imposed; the
/// accessors reinterpret those bytes as scalars or vectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Xmm(pub [u8; 16]);

impl Xmm {
    /// An all-zero register.
    pub const ZERO: Xmm = Xmm([0; 16]);

    /// The raw little-endian bytes.
    pub fn to_bytes(self) -> [u8; 16] {
        self.0
    }

    /// Builds a register from raw little-endian bytes.
    pub fn from_bytes(bytes: [u8; 16]) -> Xmm {
        Xmm(bytes)
    }

    /// The full 128 bits as an unsigned integer.
    pub fn u128(self) -> u128 {
        u128::from_le_bytes(self.0)
    }

    /// Builds a register from a 128-bit unsigned integer.
    pub fn from_u128(value: u128) -> Xmm {
        Xmm(value.to_le_bytes())
    }

    /// The low lane as an `f32` (a scalar single, as in `xmm0` after `movss`).
    pub fn f32(self) -> f32 {
        f32::from_le_bytes([self.0[0], self.0[1], self.0[2], self.0[3]])
    }

    /// The low lane as an `f64` (a scalar double, as in `xmm0` after `movsd`).
    pub fn f64(self) -> f64 {
        f64::from_le_bytes([
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5], self.0[6], self.0[7],
        ])
    }

    /// The four packed `f32` lanes.
    pub fn f32x4(self) -> [f32; 4] {
        let mut out = [0.0f32; 4];
        for (lane, value) in out.iter_mut().enumerate() {
            let base = lane * 4;
            *value = f32::from_le_bytes([
                self.0[base],
                self.0[base + 1],
                self.0[base + 2],
                self.0[base + 3],
            ]);
        }
        out
    }

    /// The two packed `f64` lanes.
    pub fn f64x2(self) -> [f64; 2] {
        let mut out = [0.0f64; 2];
        for (lane, value) in out.iter_mut().enumerate() {
            let base = lane * 8;
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&self.0[base..base + 8]);
            *value = f64::from_le_bytes(bytes);
        }
        out
    }

    /// The four packed `i32` lanes.
    pub fn i32x4(self) -> [i32; 4] {
        let mut out = [0i32; 4];
        for (lane, value) in out.iter_mut().enumerate() {
            let base = lane * 4;
            *value = i32::from_le_bytes([
                self.0[base],
                self.0[base + 1],
                self.0[base + 2],
                self.0[base + 3],
            ]);
        }
        out
    }

    /// The two packed `u64` lanes.
    pub fn u64x2(self) -> [u64; 2] {
        let mut out = [0u64; 2];
        for (lane, value) in out.iter_mut().enumerate() {
            let base = lane * 8;
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&self.0[base..base + 8]);
            *value = u64::from_le_bytes(bytes);
        }
        out
    }

    /// Sets the low `f32` lane, leaving the rest unchanged.
    pub fn set_f32(&mut self, value: f32) {
        self.0[0..4].copy_from_slice(&value.to_le_bytes());
    }

    /// Sets the low `f64` lane, leaving the rest unchanged.
    pub fn set_f64(&mut self, value: f64) {
        self.0[0..8].copy_from_slice(&value.to_le_bytes());
    }

    /// Builds a register whose low `f32` lane is `value` and whose other bytes
    /// are zero.
    pub fn from_f32(value: f32) -> Xmm {
        let mut xmm = Xmm::ZERO;
        xmm.set_f32(value);
        xmm
    }

    /// Builds a register whose low `f64` lane is `value` and whose other bytes
    /// are zero.
    pub fn from_f64(value: f64) -> Xmm {
        let mut xmm = Xmm::ZERO;
        xmm.set_f64(value);
        xmm
    }

    /// Builds a register from four packed `f32` lanes.
    pub fn from_f32x4(lanes: [f32; 4]) -> Xmm {
        let mut bytes = [0u8; 16];
        for (lane, value) in lanes.iter().enumerate() {
            bytes[lane * 4..lane * 4 + 4].copy_from_slice(&value.to_le_bytes());
        }
        Xmm(bytes)
    }

    /// Builds a register from two packed `f64` lanes.
    pub fn from_f64x2(lanes: [f64; 2]) -> Xmm {
        let mut bytes = [0u8; 16];
        for (lane, value) in lanes.iter().enumerate() {
            bytes[lane * 8..lane * 8 + 8].copy_from_slice(&value.to_le_bytes());
        }
        Xmm(bytes)
    }
}

impl Default for Xmm {
    fn default() -> Self {
        Xmm::ZERO
    }
}
