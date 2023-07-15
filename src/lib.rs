use proc_macro2::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Field, Fields, Type};
extern crate proc_macro;

#[proc_macro_derive(Serializer)]
pub fn derive_serializer(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input_ = input.into();
    let input = parse_macro_input!(input_ as DeriveInput);
    let ident = input.ident;

    if let Data::Struct(r#struct) = input.data {
        let fields = r#struct.fields;
        if matches!(&fields, Fields::Named(_)) {
            let builder_fields = TokenStream::from_iter(fields.iter().map(|field: &Field| {
                let name = field.clone().ident.unwrap();
                match &field.ty {
                    Type::Path(path)
                        if path
                            .path
                            .get_ident()
                            .is_some_and(|path| path == "u16" || path == "u32") =>
                    {
                        quote!(
                            self.#name.to_be_bytes().to_vec(),
                        )
                    }
                    _ => {
                        quote!(
                            self.#name.clone(),
                        )
                    }
                }
            }));
            return quote!(
                impl #ident {
                    pub fn to_bytes(&self) -> Vec<u8> {
                        [#builder_fields].concat()
                    }
                }
            )
            .into();
        }
    }
    quote!().into()
}

#[proc_macro_derive(Deserializer)]
pub fn derive_deserializer(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input_ = input.into();
    let input = parse_macro_input!(input_ as DeriveInput);
    let ident = input.ident;

    if let Data::Struct(r#struct) = input.data {
        let fields = r#struct.fields;
        if matches!(&fields, Fields::Named(_)) {
            let set_fields = TokenStream::from_iter(fields.iter().map(|field: &Field| {
                let name = field.clone().ident.unwrap();
                if name == "name" {
                    return quote!(
                        let #name = decode_name()
                    );
                }
                match &field.ty {
                    Type::Path(path) if path.path.get_ident().is_some_and(|path| path == "u16") => {
                        quote!(
                            let #name = u16::from_be_bytes(*decoded.next().unwrap());
                        )
                    }
                    Type::Path(path) if path.path.get_ident().is_some_and(|path| path == "u32") => {
                        quote!(
                            let #name = u32::from_be_bytes(*decoded.next().unwrap());
                        )
                    }
                    _ => {
                        quote!()
                    }
                }
            }));
            let build_fields = TokenStream::from_iter(fields.iter().map(|field: &Field| {
                let name = field.clone().ident.unwrap();
                quote!(
                    #name,
                )
            }));
            return quote!(
                impl #ident {
                    pub fn parse(reader: &mut DecodeHelper) -> #ident {
                        let mut decoded = reader.buffer[reader.pos..12 + reader.pos].array_chunks::<2>();
                        reader.pos += 12;
                        #set_fields
                        #ident {
                            #build_fields
                        }
                    }
                }
            ).into();
        }
    }
    quote!().into()
}

#[test]
fn test() {
    let tokens_input = quote!(
        struct DNSQuestion {
            name: Vec<u8>,
            type_: u16,
            class: u16,
        }
    )
    .into();
    let tokens = derive_serializer(tokens_input);
    // let a = quote!(/* */);
    eprintln!("{}", tokens);
}
