use walkdir::WalkDir;
use clap::Parser;
use::std;
use std::path::{self, Path};
use std::fs::File;
use std::io::{self, Read}; // <- make sure Read is imported
use std::io::{BufWriter, Write};
use chrono::Local;
use sha1::{Sha1, Digest as Sha1Digest};
use sha2::{Sha256, Digest as Sha256Digest};
use hex_literal::hex;


fn main() -> std::io::Result<()>{


    //create if not exists config file
    let config_path = "config.txt";
    if !Path::new(config_path).exists() {
        let mut config_file = File::create(config_path)?;
        writeln!(config_file, "[Drives to scan]")?;
        writeln!(config_file, "C:\\")?;
        writeln!(config_file, "[File extensions]")?;
        writeln!(config_file, "pdf,doc,docx,xls,xlsx,ppt,pptx")?;
        writeln!(config_file, "[Keywords]")?;
        writeln!(config_file, "-")?;
        println!("Config file created at {}", config_path);
    } else {
        println!("Loading existing config file {}", config_path);
    }

    let timestamp = Local::now().format("%d-%m-%Y_%H-%M-%S");


    let mut targets:Vec<String> = Vec::new();
    targets.push("D:\\03_PROJETOS\\FORENSIC FILES TARGET".to_string());
    
    let file_extensions = ["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx"];

    let compressed_file_extensions = ["zip", "7z", "bz", "bz2", "gzip", "rar", "tar"];

    let mut result_number = 0;
    let mut compress_files_number = 0;

    let filename = format!("{}-report.txt", timestamp);
    let output_file = File::create(&filename)?;
    let mut writer = BufWriter::new(output_file);
    for target in targets{
        for entry in WalkDir::new(target).into_iter().filter_map(|e|e.ok()){
            if let Some(ext) = entry.path().extension(){

                if file_extensions.iter().any(|wanted|ext.eq_ignore_ascii_case(wanted)){
                    
                    let path = entry.path();
                    let mut entry_file = File::open(path)?;
                    result_number+=1;
                    writeln!(writer, "---")?; 


                    //check for keyword

                    
                    //Calculate hashes
                    // SHA-1
                    let mut sha1_hasher = Sha1::new();
                    // SHA-256
                    let mut sha256_hasher = Sha256::new();

                    let mut buffer = [0u8; 8192];
                    loop {
                        let n = entry_file.read(&mut buffer)?;
                        if n == 0 { break; }
                        sha1_hasher.update(&buffer[..n]);
                        sha256_hasher.update(&buffer[..n]);
                    }

                    let sha1_result = sha1_hasher.finalize();
                    let sha256_result = sha256_hasher.finalize();

                    // Write results to file
                    writeln!(writer, "{}", entry.path().display())?; 
                    writeln!(writer, "SHA-1   : {:x}", sha1_result)?;
                    writeln!(writer, "SHA-256 : {:x}", sha256_result)?;
                    writeln!(writer, "keyword snippet: ");
                    writeln!(writer, "---")?; 
                }

                if compressed_file_extensions.iter().any(|compressed|ext.eq_ignore_ascii_case(compressed)){
                    compressed_files_handler(entry.path());
                    compress_files_number+=1;
                }  
            }       
        }

    } 
    println!("Found {} files with the provided file extensions", result_number);
    println!("Found {} compressed files", compress_files_number);
    println!("File paths saved to output.txt");
    Ok(())
}




fn compressed_files_handler(path: &Path){
    println!("{}", path.display());
}