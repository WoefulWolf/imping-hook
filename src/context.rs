//! The CPU register context passed to register-context injections.

/// The x86-64 registers at an injection site: general-purpose registers,
/// flags, instruction pointer and SSE registers.
///
/// [`inspect`](crate::InjectionBuilder::inspect) callbacks read it;
/// [`modify`](crate::InjectionBuilder::modify) callbacks can also change it
/// before the original code resumes, and redirect with [`rip`](Self::rip).
// The stub reads and writes this layout on the stack; don't reorder fields.
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
    /// In `modify`, a changed `rsp` only takes effect along with a changed
    /// [`rip`](Self::rip); otherwise the original code resumes on its own stack.
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
    /// The address of the injection site, the patched instruction.
    ///
    /// In `modify`, setting it to another address jumps there with the (maybe
    /// changed) [`rsp`](Self::rsp), and the displaced instructions don't run.
    pub rip: u64,
    /// The SSE registers `xmm0`–`xmm15`.
    pub xmm: [Xmm; 16],
}

/// The 128 bits of one SSE (`xmm`) register.
///
/// Stored as raw little-endian bytes; the helpers read and build them as
/// scalars or packed lanes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Xmm(pub [u8; 16]);

impl Xmm {
    /// An all-zero register.
    pub const ZERO: Xmm = Xmm([0; 16]);

    /// Returns the raw little-endian bytes.
    pub fn to_bytes(self) -> [u8; 16] {
        self.0
    }

    /// Builds a register from raw little-endian bytes.
    pub fn from_bytes(bytes: [u8; 16]) -> Xmm {
        Xmm(bytes)
    }

    /// Returns all 128 bits as an unsigned integer.
    pub fn u128(self) -> u128 {
        u128::from_le_bytes(self.0)
    }

    /// Builds a register from a 128-bit unsigned integer.
    pub fn from_u128(value: u128) -> Xmm {
        Xmm(value.to_le_bytes())
    }

    /// Returns the low lane as an `f32`, a scalar single as after `movss`.
    pub fn f32(self) -> f32 {
        f32::from_le_bytes([self.0[0], self.0[1], self.0[2], self.0[3]])
    }

    /// Returns the low lane as an `f64`, a scalar double as after `movsd`.
    pub fn f64(self) -> f64 {
        f64::from_le_bytes([
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5], self.0[6], self.0[7],
        ])
    }

    /// Returns the four packed `f32` lanes.
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

    /// Returns the two packed `f64` lanes.
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

    /// Returns the four packed `i32` lanes.
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

    /// Returns the two packed `u64` lanes.
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

    /// Builds a register with `value` in the low `f32` lane and zeros elsewhere.
    pub fn from_f32(value: f32) -> Xmm {
        let mut xmm = Xmm::ZERO;
        xmm.set_f32(value);
        xmm
    }

    /// Builds a register with `value` in the low `f64` lane and zeros elsewhere.
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
