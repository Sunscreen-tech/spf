use crate::Register;

fn width_dec(input: u64) -> u64 {
    assert!(input < 128, "{input} out of range [0, 128)");
    if input == 0 { 128 } else { input }
}

fn width_enc(input: u64) -> u64 {
    assert!(input > 0 && input <= 128, "{input} out of range (0, 128]");
    if input == 128 { 0 } else { input }
}

fn offset_dec(input: u64) -> u64 {
    input as u32 as i32 as u64
}

fn offset_enc(input: u64) -> u64 {
    input
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
            $((unused $unused_width:literal))*
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

                        let reg_masks = reg_counts.map(|x| (0x1 << x) - 1);

                        #[allow(unused_variables)]
                        Ok(match [<$inst_name OpCode>]::try_from((value & 0xFF) as u8)? {
                            $(
                                [<$inst_name OpCode>]::$op_name => {
                                    #[allow(unused)]
                                    let value = value >> 8;

                                    $(
                                        let $dst_name = RegisterName::new(value as usize & reg_masks[$dst_type_id]);
                                        let value = value >> reg_counts[$dst_type_id];
                                    )*

                                    $(
                                        let $src_name = RegisterName::new(value as usize & reg_masks[$src_type_id]);
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

                                    $(
                                        let value = value >> $unused_width;
                                    )*

                                    assert_eq!(value, 0);

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
                                        let mask = (0x1u64 << $meta_width) - 1;
                                        let bits = ($meta_name as u64) & mask;
                                        let encoded = encoded | bits << shift;
                                        shift += $meta_width;
                                    )*
                                    $(
                                        let mask = (0x1u64 << $cmeta_width) - 1;
                                        let bits = $cmeta_enc($cmeta_name as u64) & mask;
                                        let encoded = encoded | bits << shift;
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
                                    $(0xFFFFFF30u32 as $meta_type,)*
                                    $(4 as $cmeta_type,)*
                                ),
                            )*
                        ] {
                            let as_u64: u64 = i.into();
                            let actual = $inst_name::try_from(as_u64).unwrap();

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

    // Store
    [0x01 Store (src dst, 0, Register) (src src, 0, Register) (cmeta width, 7, u32, width_dec, width_enc) (cmeta offset, 32, i32, offset_dec, offset_enc)],

    // Load
    [0x09 Load (dst dst, 0, Register) (src src, 0, Register) (cmeta width, 7, u32, width_dec, width_enc) (cmeta offset, 32, i32, offset_dec, offset_enc)],

    // Load immediate
    [0x0A LoadI (dst dst, 0, Register) (meta imm, 32, u32) (cmeta width, 7, u32, width_dec, width_enc)],

    // Truncation
    [0x11 Trunc (dst dst, 0, Register) (src src, 0, Register) (cmeta width, 7, u32, width_dec, width_enc) (unused 7)],

    // Zero extension
    [0x15 Zext (dst dst, 0, Register) (src src, 0, Register) (cmeta width, 7, u32, width_dec, width_enc) (unused 7)],

    // Sign extension
    [0x16 Sext (dst dst, 0, Register) (src src, 0, Register) (cmeta width, 7, u32, width_dec, width_enc) (unused 7)],

    // Move
    [0x21 Move (dst dst, 0, Register) (src src, 0, Register)],

    // Not
    [0x31 Not (dst dst, 0, Register) (src src, 0, Register)],

    // And
    [0x32 And (dst dst, 0, Register) (src a, 0, Register) (src b, 0, Register)],

    // Or
    [0x33 Or (dst dst, 0, Register) (src a, 0, Register) (src b, 0, Register)],

    // Xor
    [0x34 Xor (dst dst, 0, Register) (src a, 0, Register) (src b, 0, Register)],

    // Add
    [0x41 Add (dst dst, 0, Register) (src a, 0, Register) (src b, 0, Register)],

    // Add with carry
    [0x42 AddC (dst dst, 0, Register) (dst carry_out, 0, Register) (src a, 0, Register) (src b, 0, Register) (src carry_in, 0, Register)],

    // Subtract
    [0x45 Sub (dst dst, 0, Register) (src a, 0, Register) (src b, 0, Register)],

    // Subtract and borrow
    [0x46 SubB (dst dst, 0, Register) (dst borrow_out, 0, Register) (src a, 0, Register) (src b, 0, Register) (src borrow_in, 0, Register)],

    // Negate
    [0x49 Neg (dst dst, 0, Register) (src src, 0, Register)],

    // Multiply a * b and produce the low word of the product.
    [0x51 Mul (dst dst, 0, Register) (src a, 0, Register) (src b, 0, Register)],

    // Rotate left
    [0x81 Rotl (dst dst, 0, Register) (src src, 0, Register) (src shift, 0, Register)],

    // Rotate right
    [0x82 Rotr (dst dst, 0, Register) (src src, 0, Register) (src shift, 0, Register)],

    // Bitshift left
    [0x85 Shl (dst dst, 0, Register) (src src, 0, Register) (src shift, 0, Register)],

    // Bitshift right
    [0x86 Shr (dst dst, 0, Register) (src src, 0, Register) (src shift, 0, Register)],

    // Arithmetic shift right
    [0x87 Shra (dst dst, 0, Register) (src src, 0, Register) (src shift, 0, Register)],

    // Compare equal
    [0x91 CmpEq (dst dst, 0, Register) (src a, 0, Register) (src b, 0, Register)],

    // Compare greater than
    [0x95 CmpGt (dst dst, 0, Register) (src a, 0, Register) (src b, 0, Register)],

    // Compare greater than, signed
    [0x96 CmpGtS (dst dst, 0, Register) (src a, 0, Register) (src b, 0, Register)],

    // Compare greater than or equal
    [0x97 CmpGe (dst dst, 0, Register) (src a, 0, Register) (src b, 0, Register)],

    // Compare greater than or equal, signed
    [0x98 CmpGeS (dst dst, 0, Register) (src a, 0, Register) (src b, 0, Register)],

    // Compare less than
    [0x99 CmpLt (dst dst, 0, Register) (src a, 0, Register) (src b, 0, Register)],

    // Compare less than, signed
    [0x9A CmpLtS (dst dst, 0, Register) (src a, 0, Register) (src b, 0, Register)],

    // Compare less than or equal
    [0x9B CmpLe (dst dst, 0, Register) (src a, 0, Register) (src b, 0, Register)],

    // Compare less than or equal, signed
    [0x9C CmpLeS (dst dst, 0, Register) (src a, 0, Register) (src b, 0, Register)],

    // Branch relative to the current PC if `src` is non-zero.
    [0xB1 BranchNonZero (src cond, 0, Register) (meta pc_offset, 32, i32)],

    // Branch relative to the current PC if `src` is zero.
    [0xB2 BranchZero (src cond, 0, Register) (meta pc_offset, 32, i32)],

    // Unconditionally branch relative to the current PC.
    [0xB5 Branch (meta pc_offset, 32, i32)],

    // Pseudo return with jump and link register
    [0xBA Ret (unused 44)],

    // Raw cmux
    [0xC1 Cmux (dst dst, 0, Register) (src cond, 0, Register) (src a, 0, Register) (src b, 0, Register)],

    // If the a debug handler with the given id is installed, call it passing the `src` register's value.
    [0xF0 Dbg (src src, 0, Register) (meta handler_id, 32, u32)]
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
    def_alias!(FP, X8, "Frame Pointer");
    def_alias!(RP, X10, "Return value pointer.");
    def_alias!(T3, X28, "Temporary register.");
    def_alias!(T4, X29, "Temporary register.");
    def_alias!(T5, X30, "Temporary register.");
    def_alias!(T6, X31, "Temporary register.");
}
