use walkdir::WalkDir;
use::std;
use std::path::{self, Path};
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::io::{Read}; // <- make sure Read is imported
use std::io::{BufWriter, Write};
use chrono::Local;
use sha1::{Sha1, Digest as Sha1Digest};
use sha2::{Sha256, Digest as Sha256Digest};
use std::collections::HashSet;


fn main() -> std::io::Result<()>{


    println!("Insert path to scan: ");
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Failed to read line");

    let path_to_scan = input.trim();
    println!("Scanning the following path, {}", path_to_scan);

    //create if not exists config file
    let config_path = "config.txt";
    if !Path::new(config_path).exists() {
        let mut config_file = File::create(config_path)?;
        writeln!(config_file, "[File extensions]")?;
        writeln!(config_file, "pdf,doc,docx,xls,xlsx,ppt,pptx")?;
        writeln!(config_file, "[Keywords]")?;
        writeln!(config_file, "One pear line")?;
        writeln!(config_file, "[Skip the following paths]")?;
        writeln!(config_file, "C:\\Windows")?;
        println!("Config file created at {}", config_path);
    } else {
        println!("Loading existing config file {}", config_path);
    }

    let timestamp = Local::now().format("%d-%m-%Y_%H-%M-%S");


    //let mut targets:Vec<String> = Vec::new();
    //targets.push(path);
    
    let file_extensions = ["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx"];

    let compressed_file_extensions = ["zip", "7z", "bz", "bz2", "gzip", "rar", "tar"];

    let mut result_number = 0;
    let mut compress_files_number = 0;

    //Initiate report
    let filename = format!("{}-report.txt", timestamp);
    let output_file = File::create(&filename)?;
    let mut writer = BufWriter::new(output_file);
    writeln!(writer, "Forensic file search report")?; 
    writeln!(writer, " ")?; 

    //for target in targets{
    for entry in WalkDir::new(path_to_scan).into_iter().filter_map(|e|e.ok()){
        if let Some(ext) = entry.path().extension(){

            if file_extensions.iter().any(|wanted|ext.eq_ignore_ascii_case(wanted)){
                
                let path = entry.path();
                let entry_file = File::open(path)?;
                let mut reader = BufReader::new(entry_file);
                
                //Prepare hashes
            
                let mut sha1_hasher = Sha1::new();
                let mut sha256_hasher = Sha256::new();

                //Prepare keywords
                let keywords: HashSet<&str> = ["anexo"].into_iter().collect();
                let mut keyword_results = Vec::new();

                //Check filename
                let filename = path.file_name().unwrap().to_string_lossy().to_lowercase();
                if keywords.iter().any(|k| filename.contains(k)) {
                    println!("Keyword found in file name: {}", path.display());
                }

                //Prepare buffer for reading
                let mut buf = Vec::new();
                while reader.read_until(b'\n', &mut buf)? != 0 {
                    // update hashers with raw bytes
                    sha1_hasher.update(&buf);
                    sha256_hasher.update(&buf);

                    // Convert buf to an owned String
                    let line_owned = match String::from_utf8(buf.clone()) {
                        Ok(s) => s,
                        Err(_) => {
                            buf.clear();
                            continue; // skip lines that are not valid UTF-8
                        }
                    };
                    
                    let line_clean = line_owned.clone();
                    for word in line_clean.trim_end().split(|c: char| !c.is_alphanumeric()) {
                        if keywords.contains(word) {
                                keyword_results.push((word.to_string(), line_clean.clone()));
                                result_number+=1;
                                //break;
                        }
                    }

                    buf.clear(); // reset buffer for next line

                }

                let sha1_result = sha1_hasher.finalize();
                let sha256_result = sha256_hasher.finalize();

                // Write results to file
                writeln!(writer, "Path: {}", entry.path().display())?; 
                writeln!(writer, "SHA-1   : {:x}", sha1_result)?;
                writeln!(writer, "SHA-256 : {:x}", sha256_result)?;

                for keyword_res in keyword_results{
                    writeln!(writer, "Keyword hit: '{}' in line: '{}'", keyword_res.0, keyword_res.1)?;
                }
                
                writeln!(writer, "---")?; 
            }

            if compressed_file_extensions.iter().any(|compressed|ext.eq_ignore_ascii_case(compressed)){
                compressed_files_handler(entry.path());
                compress_files_number+=1;
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