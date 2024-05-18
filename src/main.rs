#![allow(unused)]

use clap::Parser;
use std::fs::File;
use std::io::*;
use xml::reader::{EventReader, XmlEvent};

/// Convert a ghidra .xml file to a list of address-name pair
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// XML file to read
    #[arg()]
    input: String,

    /// TXT file to write
    #[arg()]
    output: String,
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();

    let mut output = File::options().create(true).write(true).truncate(true).open(args.output)?;

    let file = File::open(args.input)?;
    let file = BufReader::new(file);
    let parser = EventReader::new(file);
    for e in parser {
        match e {
            Ok(XmlEvent::StartElement { name, attributes, .. }) => {
                let name = name.to_string().to_lowercase();
                match name.as_str() {
                    "program" => {
                        for attr in attributes {
                            if attr.name.local_name.to_lowercase() == "name" {
                                break;
                            }
                        }
                    },
                    "symbol" => {
                        let mut address = 0;
                        let mut name = String::new();

                        for attr in attributes {
                            let attr_name = attr.name.local_name.to_lowercase();
                            match attr_name.as_str() {
                                "name" => name = attr.value,
                                "address" => address = u32::from_str_radix(&attr.value, 16).unwrap(),
                                _ => {},
                            };
                        }

                        writeln!(output, "{:08X} {}", address, name);
                    },
                    "function" => {
                        let mut entry_point = 0;
                        let mut name = String::new();

                        for attr in attributes {
                            let attr_name = attr.name.local_name.to_lowercase();
                            match attr_name.as_str() {
                                "name" => name = attr.value,
                                "entry_point" => entry_point = u32::from_str_radix(&attr.value, 16).unwrap(),
                                _ => {},
                            };
                        }

                        writeln!(output, "{:08X} {}", entry_point, name);
                    },
                    _ => {},
                };
            }
            Err(e) => {
                eprintln!("Error: {e}");
                break;
            }
            _ => {}
        }
    }

    Ok(())
}
