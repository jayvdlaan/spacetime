use proc_macro::TokenStream;
use quote::quote;
use syn::parse::Parser;
use syn::{parse_macro_input, punctuated::Punctuated, Expr, ExprLit, ItemStruct, Lit, Meta, Token};

/// Attribute macro to generate lightweight Spacetime module descriptor constants.
///
/// Current minimal implementation ignores arguments and derives defaults:
/// - ST_NAME from the struct identifier
/// - ST_VERSION = 0.1.0
/// - ST_DEPS = &[]
#[proc_macro_attribute]
pub fn spacetime_module(args: TokenStream, input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as ItemStruct);
    let ident = &item.ident;

    // Defaults
    let mut name_val: Option<String> = None;
    let mut ver = (0u16, 1u16, 0u16);
    let mut deps: Vec<String> = Vec::new();

    let metas = parse_macro_input!(args with Punctuated<Meta, Token![,]>::parse_terminated);
    for m in metas.iter() {
        match m {
            Meta::NameValue(nv) => {
                if nv.path.is_ident("name") {
                    if let Expr::Lit(ExprLit {
                        lit: Lit::Str(s), ..
                    }) = &nv.value
                    {
                        name_val = Some(s.value());
                    }
                } else if nv.path.is_ident("version") {
                    if let Expr::Lit(ExprLit {
                        lit: Lit::Str(s), ..
                    }) = &nv.value
                    {
                        let v = s.value();
                        let parts: Vec<&str> = v.split('.').collect();
                        if parts.len() == 3 {
                            if let (Ok(a), Ok(b), Ok(c)) = (
                                parts[0].parse::<u16>(),
                                parts[1].parse::<u16>(),
                                parts[2].parse::<u16>(),
                            ) {
                                ver = (a, b, c);
                            }
                        }
                    }
                }
            }
            Meta::List(list) => {
                if list.path.is_ident("deps") {
                    // Parse list tokens as comma-separated string literals
                    let lit_parser = Punctuated::<Lit, Token![,]>::parse_terminated;
                    if let Ok(lits) = lit_parser.parse(list.tokens.clone().into()) {
                        for lit in lits.iter() {
                            if let Lit::Str(s) = lit {
                                deps.push(s.value());
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    let name_tokens = if let Some(n) = name_val {
        quote! { #n }
    } else {
        let s = ident.to_string();
        quote! { #s }
    };
    let (ma, mi, pa) = ver;
    let deps_tokens: Vec<proc_macro2::TokenStream> = deps
        .into_iter()
        .map(|d| {
            quote! { #d }
        })
        .collect();

    let expanded = quote! {
        #item

        impl #ident {
            pub const ST_NAME: &'static str = #name_tokens;
            pub const ST_VERSION: spacetime_module::core::Version = spacetime_module::core::Version { major: #ma, minor: #mi, patch: #pa };
            pub const ST_DEPS: &'static [&'static str] = &[ #( #deps_tokens ),* ];

            /// Helper to create a ModuleNode with the descriptor constants from this type.
            pub fn to_node(
                init: fn(&mut spacetime_module::core::InitCtx) -> Result<(), spacetime_module::core::InitError>,
            ) -> spacetime_module::ModuleNode {
                spacetime_module::ModuleNode {
                    descriptor: spacetime_module::ModuleDescriptor::new(Self::ST_NAME, Self::ST_VERSION),
                    init,
                    deps: Self::ST_DEPS,
                    start: None,
                }
            }

            /// Helper to create a ModuleNode with both init and start hooks.
            pub fn to_node_with_start(
                init: fn(&mut spacetime_module::core::InitCtx) -> Result<(), spacetime_module::core::InitError>,
                start: fn(&dyn spacetime_module::core::Runtime) -> Result<(), spacetime_module::core::StartError>,
            ) -> spacetime_module::ModuleNode {
                spacetime_module::ModuleNode {
                    descriptor: spacetime_module::ModuleDescriptor::new(Self::ST_NAME, Self::ST_VERSION),
                    init,
                    deps: Self::ST_DEPS,
                    start: Some(start),
                }
            }
        }
    };
    TokenStream::from(expanded)
}
