use crate::Register;

fn width_dec(input: u64) -> u64 {
    assert!(input < 128, "{input} out of range [0, 128)");
    if input == 0 { 128 } else { input }
}

fn width_enc(input: u64) -> u64 {
    assert!(input > 0 && input <= 128, "{input} out of range (0, 128]");
    if input == 128 { 0 } else { input }
}

/// Define the list of opcodes for the processors ISA.
#[macro_export]
macro_rules! define_op {
    (
        $inst_name:ident,
        $dispatch_name:ident,
        ($($reg_kind:ty,$num_reg:literal,$reg_prefix:ident),*),
        $([
            $op_code:literal
            $op_name:ident
            $((dst $dst_name:ident, $dst_type_id:tt, $dst_type:ty))*
            $((src $src_name:ident, $src_type_id:tt, $src_type:ty))*
            $((meta $meta_name:ident, $meta_width:literal, $meta_type:ty))*
            $((cmeta $cmeta_name:ident, $cmeta_width:literal, $cmeta_type:ty, $cmeta_dec:ident, $cmeta_enc:ident))*
        ]),* $(,)?
    ) => {
        paste::paste! {
            mod [<$inst_name:snake _internal>] {
                use $crate::{
                    Result, Error,
                    tomasulo::{
                        registers::{RegisterName, RegisterFile, RobEntryRef, RobId},
                        GetDeps,
                        ToDispatchedOp,
                        scoreboard::{
                            ScoreboardEntryRef,
                        },
                    }
                };

                use std::sync::mpsc::Receiver;
                use super::*;

                pub mod register_names {
                    use super::*;

                    $(
                        seq_macro::seq!(N in 0..$num_reg {
                            #(
                                #[doc = concat!("The `RegisterName` of ", stringify!($reg_prefix~N))]
                                pub const $reg_prefix ~N: $crate::tomasulo::registers::RegisterName<$reg_kind> = $crate::tomasulo::registers::RegisterName::new(N);
                            )*
                        });
                    )*
                }
                #[derive(Debug, Clone, Copy, PartialEq, Eq)]
                pub enum $inst_name {
                    $(
                        $op_name
                        (
                            $(RegisterName<$dst_type>,)*
                            $(RegisterName<$src_type>,)*
                            $($meta_type,)*
                            $($cmeta_type,)*
                        )
                    ),*
                }

                impl TryFrom<u64> for $inst_name {
                    type Error = Error;

                    fn try_from(value: u64) -> $crate::Result<Self> {
                        let reg_counts = [
                            $(($num_reg as u32).next_power_of_two().ilog2())*
                        ];

                        #[allow(unused_variables)]
                        Ok(match [<$inst_name OpCode>]::try_from((value & 0xFF) as u8)? {
                            $(
                                [<$inst_name OpCode>]::$op_name => {
                                    #[allow(unused)]
                                    let value = value >> 8;

                                    $(
                                        let $dst_name = RegisterName::new(value as usize & 0x1F);
                                        #[allow(unused)]
                                        let value = value >> reg_counts[$dst_type_id];
                                    )*

                                    $(
                                        let $src_name = RegisterName::new(value as usize & 0x1F);
                                        #[allow(unused)]
                                        let value = value >> reg_counts[$src_type_id];
                                    )*

                                    $(
                                        let mask = (0x1u64 << $meta_width) - 1;
                                        let $meta_name = (value & mask) as $meta_type;
                                        let value = value >> $meta_width;
                                    )*

                                    $(
                                        let mask = (0x1u64 << $cmeta_width) - 1;
                                        let $cmeta_name = $cmeta_dec((value & mask) as $cmeta_type as u64) as $cmeta_type;
                                        let value = value >> $cmeta_width;
                                    )*

                                    $inst_name :: $op_name(
                                        $($dst_name,)*
                                        $($src_name,)*
                                        $($meta_name,)*
                                        $($cmeta_name,)*
                                    )
                                }
                            )*
                        })
                    }
                }

                impl From<$inst_name> for u64 {
                    fn from(x: $inst_name) -> Self {
                        let mut encoded = x.op_code() as u64;
                        let mut shift = 8;

                        let reg_counts = [
                            $(($num_reg as u32).next_power_of_two().ilog2())*
                        ];

                        #[allow(unused_assignments)]
                        match x {
                            $(
                                $inst_name::$op_name (
                                    $($dst_name,)*
                                    $($src_name,)*
                                    $($meta_name,)*
                                    $($cmeta_name,)*
                                ) => {
                                    $(
                                        encoded |= ($dst_name.name as u64) << shift;
                                        shift += reg_counts[$dst_type_id];
                                    )*
                                    $(
                                        encoded |= ($src_name.name as u64) << shift;
                                        shift += reg_counts[$src_type_id];
                                    )*
                                    $(
                                        let encoded = encoded | ($meta_name as u64) << shift;
                                        shift += $meta_width;
                                    )*
                                    $(
                                        let encoded = encoded | $cmeta_enc($cmeta_name as u64) << shift;
                                        shift += $cmeta_width;
                                    )*

                                    encoded
                                }
                            )*
                        }
                    }
                }

                impl $inst_name {
                    pub fn validate(&self, inst_id: usize, pc: u32) -> Result<()> {
                        #[allow(unused)]
                        match self {
                            $(
                                Self::$op_name($($dst_name,)* $($src_name,)* $($meta_name,)* $($cmeta_name,)*) => {
                                    $(if !matches!($dst_name, _) {
                                        return Err(Error::IllegalOperands { inst_id, pc });
                                    })*
                                },
                            )*
                        }

                        Ok(())
                    }

                    pub fn op_code(&self) -> [<$inst_name OpCode>] {
                        match self {
                            $(
                                Self:: $op_name (
                                    $([<_ $dst_name>],)*
                                    $([<_ $src_name>],)*
                                    $([<_ $meta_name>],)*
                                    $([<_ $cmeta_name>],)*
                                ) => [<$inst_name OpCode>]::$op_name,
                            )*
                        }
                    }
                }

                impl<'a> GetDeps<'a> for $inst_name {
                    type DispatchedOp = $dispatch_name;
                    type RenameSet = ($(&'a RegisterFile<$reg_kind, $dispatch_name>,)*());

                    fn instruction_dep_idx(
                        &self,
                        rename_set: Self::RenameSet,
                        idx: usize,
                    ) -> Option<ScoreboardEntryRef<Self::DispatchedOp>> {
                        #[allow(unused)]
                        match self {
                            $(
                                Self::$op_name($($dst_name,)* $($src_name,)* $($meta_name,)* $($cmeta_name,)*) => {
                                    $(let $src_name = rename_set.$src_type_id.get_instruction(*$src_name);)*

                                    $crate::dep_idx! {idx, $($src_name)*}
                                },
                            )*
                        }
                    }

                    fn num_deps(
                        &self
                    ) -> usize {
                        #[allow(unused)]
                        match self {
                            $(
                                Self::$op_name($($dst_name,)* $($src_name,)* $($meta_name,)* $($cmeta_name,)*) => {
                                    $crate::rep_len!($($src_name)*)
                                }
                            )*
                        }
                    }
                }

                #[repr(u8)]
                #[derive(Debug, Clone, Copy, PartialEq, Eq)]
                pub enum [<$inst_name OpCode>] {
                    $($op_name = $op_code),*
                }

                impl TryFrom<u8> for [<$inst_name OpCode>] {
                    type Error = Error;

                    fn try_from(val: u8) -> $crate::Result<Self> {
                        Ok(match val {
                            $($op_code => Self::$op_name,)*
                            _ => return Err(Error::IllegalInstruction(0))
                        })
                    }
                }

                #[derive(Clone)]
                pub enum $dispatch_name {
                    $(
                        $op_name
                        (
                            $(RobEntryRef<$dst_type>,)*
                            $(RobEntryRef<$src_type>,)*
                            $($meta_type,)*
                            $($cmeta_type,)*
                        )
                    ),*
                }

                impl std::fmt::Debug for $dispatch_name {
                    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::result::Result<(), std::fmt::Error> {
                        match self {
                            $(Self:: $op_name(..) => write!(f, stringify!($op_name))),*
                        }
                    }
                }

                impl<'a> ToDispatchedOp<'a> for $inst_name {
                    type DispatchedOp = $dispatch_name;
                    type RobEntrySrcs = ($(&'a RegisterFile<$reg_kind, $dispatch_name>,)*());
                    type FreeLists = ($(&'a Receiver<RobId<$reg_kind>>,)*());

                    fn to_dispatched_op(
                        &self,
                        srcs: Self::RobEntrySrcs,
                        scoreboard_entry: ScoreboardEntryRef< $dispatch_name>,
                        instruction_id: usize,
                        pc: u32
                    ) -> $crate::error::Result<Self::DispatchedOp> {
                        let disp_op = match self {
                            $(
                                Self::$op_name($($dst_name,)* $($src_name,)* $($meta_name,)* $($cmeta_name,)*) => {
                                    // It's important we capture the srcs first, as they should not be renamed.
                                    $(let $src_name = srcs.$src_type_id.map_entry(*$src_name).map(|x| x.clone_immutable()).ok_or(Error::IllegalOperands { inst_id: instruction_id, pc })?;)*
                                    $(let $dst_name =
                                        srcs.$dst_type_id.rename(*$dst_name, Some(&scoreboard_entry));
                                    )*

                                    Self::DispatchedOp::$op_name($($dst_name,)* $($src_name,)* $($meta_name.clone(),)* $($cmeta_name.clone(),)*)
                                },
                            )*
                        };

                        Ok(disp_op)
                    }
                }

                #[cfg(test)]
                mod tests {
                    use super::*;

                    #[test]
                    fn can_roundtrip_opcode() {
                        for i in [
                            $(
                                [<$inst_name OpCode>]::$op_name,
                            )*
                        ] {
                            assert_eq!(i, [<$inst_name OpCode>]::try_from(i as u8).unwrap());
                        }
                    }

                    #[test]
                    fn can_roundtrip_instruction() {
                        for i in [
                            $(
                                $inst_name::$op_name(
                                    $(RegisterName::<$dst_type>::new(12),)*
                                    $(RegisterName::<$src_type>::new(12),)*
                                    $(1234 as $meta_type,)*
                                    $(4321 as $cmeta_type,)*
                                ),
                            )*
                        ] {
                            let as_u64 = i.into();
                            let actual = $inst_name::from(as_u64);

                            assert_eq!(i, actual);
                        }
                    }
                }
            }

            pub use [<$inst_name:snake _internal>]::*;
        }
    };
}

// CODESYNC: Ensure the opcodes in this table match those in
// tfhe-llvm/llvm/lib/Target/Parasol/ParasolInstrFormats.td.
define_op! {
    IsaOp,
    DispatchIsaOp,
    (Register, 64, X),

    // Load
    [0x02 Load (dst dst, 0, Register) (src src, 0, Register) (cmeta width, 7, u32, width_dec, width_enc)],

    // Load immediate
    [0x03 LoadI (dst dst, 0, Register) (meta imm, 32, u128) (cmeta width, 7, u32, width_dec, width_enc)],

    // Store
    [0x04 Store (src dst, 0, Register) (src src, 0, Register) (cmeta width, 7, u32, width_dec, width_enc)],

    // And
    [0x30 And (dst dst, 0, Register) (src a, 0, Register) (src b, 0, Register)],

    // Or
    [0x31 Or (dst dst, 0, Register) (src a, 0, Register) (src b, 0, Register)],

    // Multiply a * b and produce the low word of the product.
    [0x14 Mul (dst dst, 0, Register) (src a, 0, Register) (src b, 0, Register)],

    // Add
    [0x10 Add (dst dst, 0, Register) (src a, 0, Register) (src b, 0, Register)],

    // Not
    [0x33 Not (dst dst, 0, Register) (src src, 0, Register)],

    // Xor
    [0x32 Xor (dst dst, 0, Register) (src a, 0, Register) (src b, 0, Register)],

    // Bitshift right
    [0x22 Shr (dst dst, 0, Register) (src src, 0, Register) (src shift, 0, Register)],

    // Arithmetic shift right
    [0x24 Shra (dst dst, 0, Register) (src src, 0, Register) (src shift, 0, Register)],

    // Bitshift left
    [0x20 Shl (dst dst, 0, Register) (src src, 0, Register) (src shift, 0, Register)],

    // Rotate right
    [0x23 Rotr (dst dst, 0, Register) (src src, 0, Register) (src shift, 0, Register)],

    // Rotate left
    [0x21 Rotl (dst dst, 0, Register) (src src, 0, Register) (src shift, 0, Register)],

    // Add with carry
    [0x11 AddC (dst dst, 0, Register) (dst carry_out, 0, Register) (src a, 0, Register) (src b, 0, Register) (src carry_in, 0, Register)],

    // Subtract
    [0x12 Sub (dst dst, 0, Register) (src a, 0, Register) (src b, 0, Register)],

    // Subract and borrow
    [0x13 SubB (dst dst, 0, Register) (dst borrow_out, 0, Register) (src a, 0, Register) (src b, 0, Register) (src borrow_in, 0, Register)],

    // Negate
    [0x34 Neg (dst dst, 0, Register) (src src, 0, Register)],

    // Compare equal
    [0x44 CmpEq (dst dst, 0, Register) (src a, 0, Register) (src b, 0, Register)],

    // Compare greater than
    [0x40 CmpGt (dst dst, 0, Register) (src a, 0, Register) (src b, 0, Register)],

    // Compare greater than or equal
    [0x41 CmpGe (dst dst, 0, Register) (src a, 0, Register) (src b, 0, Register)],

    // Compare less than
    [0x42 CmpLt (dst dst, 0, Register) (src a, 0, Register) (src b, 0, Register)],

    // Compare less than or equal
    [0x43 CmpLe (dst dst, 0, Register) (src a, 0, Register) (src b, 0, Register)],

    // Compare greater than, signed
    [0x50 CmpGtS (dst dst, 0, Register) (src a, 0, Register) (src b, 0, Register)],

    // Compare greater than or equal, signed
    [0x51 CmpGeS (dst dst, 0, Register) (src a, 0, Register) (src b, 0, Register)],

    // Compare less than, signed
    [0x52 CmpLtS (dst dst, 0, Register) (src a, 0, Register) (src b, 0, Register)],

    // Compare less than or equal, signed
    [0x53 CmpLeS (dst dst, 0, Register) (src a, 0, Register) (src b, 0, Register)],

    // Casting operations
    [0x05 Zext (dst dst, 0, Register) (src src, 0, Register) (cmeta width, 7, u32, width_dec, width_enc)],
    [0x06 Trunc (dst dst, 0, Register) (src src, 0, Register) (cmeta width, 7, u32, width_dec, width_enc)],
    [0x07 Sext (dst dst, 0, Register) (src src, 0, Register) (cmeta width, 7, u32, width_dec, width_enc)],

    // Branch relative to the current PC if `src` is non-zero.
    [0x46 BranchNonZero (src cond, 0, Register) (meta pc_offset, 32, i32)],

    // Branch relative to the current PC if `src` is zero.
    [0x47 BranchZero (src cond, 0, Register) (meta pc_offset, 32, i32)],

    // Raw cmux
    [0x45 Cmux (dst dst, 0, Register) (src cond, 0, Register) (src a, 0, Register) (src b, 0, Register)],

    // Return
    [0xFE Ret]
}

pub mod register_names {
    use super::isa_op_internal::register_names;
    pub use super::isa_op_internal::register_names::*;

    macro_rules! def_alias {
        ($alias:ident,$id:ident,$doc:literal) => {
            #[doc = concat!($doc, " Alias of ", stringify!($id))]
            pub const $alias: crate::tomasulo::registers::RegisterName<super::Register> =
                register_names::$id;
        };
    }

    // Start filling out our RISC-V ISA aliases as we adopt their meaning.
    def_alias!(SP, X2, "Stack pointer.");
    def_alias!(T0, X5, "Temporary register.");
    def_alias!(T1, X6, "Temporary register.");
    def_alias!(T2, X7, "Temporary register.");
    def_alias!(A0, X10, "Function argument/return values.");
    def_alias!(A1, X11, "Function argument/return values.");
    def_alias!(A2, X12, "Function argument.");
    def_alias!(A3, X13, "Function argument.");
    def_alias!(A4, X14, "Function argument.");
    def_alias!(A5, X15, "Function argument.");
    def_alias!(A6, X16, "Function argument.");
    def_alias!(A7, X17, "Function argument.");
    def_alias!(T3, X28, "Temporary register.");
    def_alias!(T4, X29, "Temporary register.");
    def_alias!(T5, X30, "Temporary register.");
    def_alias!(T6, X31, "Temporary register.");
}
