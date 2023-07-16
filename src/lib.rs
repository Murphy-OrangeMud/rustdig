use proc_macro2::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Field, Fields, Type};
extern crate proc_macro;
use syn::{GenericArgument, Path, PathArguments};

#[proc_macro_derive(Serializer)]
pub fn derive_serializer(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input_ = input.into();
    let input = parse_macro_input!(input_ as DeriveInput);
    let ident = input.ident;

    fn path_is_option(path: &Path) -> bool {
        path.leading_colon.is_none()
            && path.segments.len() == 1
            && path.segments.iter().next().unwrap().ident == "Option"
    }

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

                    Type::Path(typepath)
                        if typepath.qself.is_none() && path_is_option(&typepath.path) =>
                    {
                        let type_params = &typepath.path.segments.iter().next().unwrap().arguments;
                        // It should have only on angle-bracketed param ("<String>"):
                        let generic_arg = match type_params {
                            PathArguments::AngleBracketed(params) => {
                                params.args.iter().next().unwrap()
                            }
                            _ => unimplemented!(),
                        };
                        // This argument must be a type:
                        let type_ = match generic_arg {
                            GenericArgument::Type(ty) => ty,
                            _ => unimplemented!(),
                        };
                        match type_ {
                            Type::Path(path)
                                if path
                                    .path
                                    .get_ident()
                                    .is_some_and(|path| path == "u16" || path == "u32") =>
                            {
                                quote!(
                                    match self.#name {
                                        Some(len) => len.to_be_bytes().to_vec(),
                                        None => Vec::<u8>::new(),
                                    },
                                )
                            }
                            _ => {
                                quote!(
                                    self.#name.clone(),
                                )
                            }
                        }
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
                        let #name = reader.decode_name();
                    );
                }
                if name == "length" {
                    return quote!(
                        let #name = match dns_mode {
                            DnsMode::UDP => None,
                            DnsMode::TCP => Some(u16::from_be_bytes(*decoded.next().unwrap())),
                            _ => unimplemented!()
                        };
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
                    pub fn parse(reader: &mut DecodeHelper, dns_mode: DnsMode) -> #ident {
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
