use walkdir::WalkDir;
use clap::Parser;
use::std;
use std::path::Path;
use std::fs::File;
use std::io::{BufWriter, Write};

/// Forensic File Searcher, a simple program to perform a forensic file search on a system drive(s)
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args{
    //drives to scan [default: C]
    #[arg(short, long)]
    drives: Option<String>,

    //file extensions [default: pdf,doc,docx,xls,xlsx]
    #[arg(short, long)]
    file_extensions: Option<String>,

    //keywords
    #[arg(short, long)]
    keywords: Option<String>,

    //enable filters
    #[arg(short, long)]
    enable_filters: Option<String>,
}

fn main() -> std::io::Result<()>{

    println!("Main");
    let args = Args::parse();

    let mut drives:Vec<String> = Vec::new();
    drives.push("C:\\".to_string());
    if !args.drives.is_none(){
        drives = args.drives.unwrap().split(',').map(|s| format!("{}{}", s, ":\\")) // append suffix to each
        .collect();
    }
    
    let mut file_extensions = ["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx"];
    if !args.file_extensions.is_none(){
        let mut file_extensions= args.file_extensions.unwrap().split(',');
    }

    
    let mut keywords = args.keywords;
    let mut enable_filters = args.enable_filters;

    let mut result_number = 0;
    let file = File::create("output.txt")?;
    let mut writer = BufWriter::new(file);
    for drive in drives{

        //ITERATE OVER ALL FILES IN ALL DRIVES
        for entry in WalkDir::new(drive).into_iter().filter_map(|e|e.ok()){
            for extension in file_extensions{
                if let Some(ext) = entry.path().extension(){
                    if ext == extension{
                        println!("{}", entry.path().display());
                        result_number+=1;
                        writeln!(writer, "{}", entry.path().display())?; // Write each path followed by newline
                        break;
                    }
                    
                }
            }
            
        }

    } 
    println!("Found {} files with the provided file extensions", result_number);
    println!("File paths saved to output.txt");
    Ok(())
}

