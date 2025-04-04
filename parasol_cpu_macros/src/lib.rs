#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
//! Derive macros used with the Parasol processor.

extern crate proc_macro;
use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{Data, DeriveInput, Fields, parse_macro_input};

#[proc_macro_derive(IntoBytes)]
/// Allows you to `#[derive(IntoBytes)]` on structures where each member impls
/// `IntoBytes`
pub fn derive_into_bytes(item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);

    derive_into_bytes_impl(input).into()
}

fn derive_into_bytes_impl(item: DeriveInput) -> TokenStream2 {
    let ident = item.ident;
    let data = item.data;

    let fields = match data {
        Data::Struct(x) => x.fields,
        _ => {
            return quote! {
                compile_error!("Only structs are supported for derive IntoBytes")
            };
        }
    };

    let field_idents = match &fields {
        Fields::Unnamed(x) => x
            .unnamed
            .iter()
            .enumerate()
            .map(|(i, _)| quote! { #i })
            .collect::<Vec<_>>(),
        Fields::Named(x) => x
            .named
            .iter()
            .map(|f| {
                let ident = f.ident.clone().unwrap();

                quote! { #ident }
            })
            .collect::<Vec<_>>(),
        Fields::Unit => {
            return quote! {
                compile_error("Structs must have at least one member.")
            };
        }
    };

    let field_types = fields.iter().cloned().map(|x| x.ty).collect::<Vec<_>>();

    let mut prev_field_size = vec![quote! { 0usize }];

    for f in field_types.iter().take(field_types.len() - 1) {
        prev_field_size.push(quote! {
            <#f as tfhe_cpu::IntoBytes>::size()
        })
    }

    let last_field_type = field_types.iter().last().unwrap();

    quote! {
        impl tfhe_cpu::IntoBytes for #ident {
            #[inline(always)]
            fn alignment() -> usize {
                let mut alignment = 0usize;

                #(alignment = alignment.max(<#field_types as tfhe_cpu::IntoBytes>::alignment());)*

                alignment
            }

            #[inline(always)]
            fn size() -> usize {
                let mut cur_offset = 0;

                #(
                    cur_offset += #prev_field_size;
                    cur_offset = cur_offset.next_multiple_of(<#field_types as tfhe_cpu::IntoBytes>::alignment());
                )*

                cur_offset += <#last_field_type as tfhe_cpu::IntoBytes>::size();

                cur_offset
            }

            fn try_into_bytes(&self, data: &mut [u8]) -> tfhe_cpu::Result<()> {
                if data.len() != Self::size() {
                    return Err(tfhe_cpu::Error::buffer_size_mismatch());
                }

                let mut cur_offset = 0;

                #(
                    cur_offset += #prev_field_size;
                    cur_offset = cur_offset.next_multiple_of(<#field_types as tfhe_cpu::IntoBytes>::alignment());

                    let byte_slice = &mut data[cur_offset..cur_offset + <#field_types as tfhe_cpu::IntoBytes>::size()];
                    <#field_types as tfhe_cpu::IntoBytes>::try_into_bytes(&self. #field_idents, byte_slice)?;
                )*

                Ok(())
            }

            fn try_from_bytes(data: &[u8]) -> tfhe_cpu::Result<Self> {
                if data.len() != Self::size() {
                    return Err(tfhe_cpu::Error::buffer_size_mismatch());
                }

                let mut cur_offset = 0;

                #(
                    cur_offset += #prev_field_size;
                    cur_offset = cur_offset.next_multiple_of(<#field_types as tfhe_cpu::IntoBytes>::alignment());

                    let byte_slice = &data[cur_offset..cur_offset + <#field_types as tfhe_cpu::IntoBytes>::size()];
                    let #field_idents = <#field_types as tfhe_cpu::IntoBytes>::try_from_bytes( byte_slice)?;
                )*


                Ok(Self {
                    #(#field_idents,)*
                })
            }
        }
    }
}
