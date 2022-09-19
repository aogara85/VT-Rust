use serde_json::Value;
use std::env;
use std::io::BufReader;
use std::io::BufRead;
use std::fs::File;
use reqwest::header;
use std::path::Path;
use std::fs::OpenOptions;
use std::{io::Write};
use std::time::SystemTime;

static APIKEY:&str="APIKEY";

pub async fn vt_hash_scanner() -> Result<(), Box<dyn std::error::Error>>{
    let args:Vec<String> = env::args().collect();
    output_csv(format!("meaningful_name,detected,negative,positive,SHA256,MD5,SHA1\n")).expect("failed");
    if args[2].as_str()=="-l" || args[2].as_str()=="--list"{
        let file = File::open(args[3].as_str())?;
        let buffer = BufReader::new(file);
        for line in buffer.lines(){
                //let file_hash="ec8c89aa5e521572c74e2dd02a4daf78";
                //let url = format!("https://www.virustotal.com/vtapi/v2/file/report?apikey={}&resource={}",apikey,line?);
                //println!("{}/{}", resj["positives"],resj["total"]);
                let client = reqwest::Client::new();
                let mut headers = header::HeaderMap::new();
                headers.insert("x-apikey",APIKEY.parse()?);
                let url = format!("https://www.virustotal.com/api/v3/files/{}",line?);
                let res = client.get(&url).header("x-apikey",APIKEY).send().await?.text().await?;
                let resj:Value = serde_json::from_str(&res).unwrap();
                if resj.get("data") != None{
                let negative = resj["data"]["attributes"]["last_analysis_stats"]["malicious"].as_u64().unwrap()
                            + resj["data"]["attributes"]["last_analysis_stats"]["suspicious"].as_u64().unwrap();

                let positive = resj["data"]["attributes"]["last_analysis_stats"]["harmless"].as_u64().unwrap()
                            + resj["data"]["attributes"]["last_analysis_stats"]["undetected"].as_u64().unwrap();

                let total    = resj["data"]["attributes"]["last_analysis_stats"]["type-unsupported"].as_u64().unwrap()
                                + negative + positive;
                if resj["data"]["attributes"]["last_analysis_stats"]["malicious"].as_u64().unwrap() > 0 {
                    output_csv(format!("{},detected,{},{},{},{},{}\n",resj["data"]["attributes"]["meaningful_name"],negative,positive,resj["data"]["id"],resj["data"]["attributes"]["md5"],resj["data"]["attributes"]["sha1"]))
                    .expect("failed");
                    println!("{}:\x1b[31mnegative/total {}/{} positive {}\x1b[37m",resj["data"]["attributes"]["meaningful_name"],negative,total,positive)
                    //println!("{}\x1b[31m{}\x1b[m",resj["data"]["attributes"]["meaningful_name"],resj["data"]["attributes"]["last_analysis_stats"])
                }
                else if resj["data"]["attributes"]["last_analysis_stats"]["malicious"].as_u64().unwrap() == 0{
                    
                    output_csv(format!("{},safe,{},{},{},{},{}\n",resj["data"]["attributes"]["meaningful_name"],negative,positive,resj["data"]["id"],resj["data"]["attributes"]["md5"],resj["data"]["attributes"]["sha1"]))
                    .expect("failed"); 
                    println!("{}:\x1b[32mnegative/total {}/{} positive {}\x1b[37m",resj["data"]["attributes"]["meaningful_name"],negative,total,positive)
                    //println!("{}\x1b[32m{}\x1b[m",resj["data"]["attributes"]["meaningful_name"],resj["data"]["attributes"]["last_analysis_stats"])
                }
                }
                else {
                    output_csv(format!("{}",resj["error"]["message"])).expect("failed");
                    println!("{}",resj["error"]["message"])
                }                                    
        }
    }
    else if args[2].as_str()=="-s" || args[2].as_str()=="--single"{
        let client = reqwest::Client::new();
        let mut headers = header::HeaderMap::new();
        headers.insert("x-apikey",APIKEY.parse()?);
        let url = format!("https://www.virustotal.com/api/v3/files/{}",args[3].as_str());
        let res = client.get(&url).header("x-apikey",APIKEY).send().await?.text().await?;
        let resj:Value = serde_json::from_str(&res).unwrap();
        if resj.get("data") != None{
            let negative = resj["data"]["attributes"]["last_analysis_stats"]["malicious"].as_u64().unwrap()
                            + resj["data"]["attributes"]["last_analysis_stats"]["suspicious"].as_u64().unwrap();
            let positive = resj["data"]["attributes"]["last_analysis_stats"]["harmless"].as_u64().unwrap()
                            + resj["data"]["attributes"]["last_analysis_stats"]["undetected"].as_u64().unwrap();
            let total    = resj["data"]["attributes"]["last_analysis_stats"]["type-unsupported"].as_u64().unwrap()
                            + negative + positive;
            if resj["data"]["attributes"]["last_analysis_stats"]["malicious"].as_u64().unwrap() > 0 {
                 
                println!("{}:\x1b[31mnegative/total {}/{} positive {}\x1b[37m",resj["data"]["attributes"]["meaningful_name"],negative,total,positive)
                //println!("{}\x1b[31m{}\x1b[m",resj["data"]["attributes"]["meaningful_name"],resj["data"]["attributes"]["last_analysis_stats"])
            }
            else if resj["data"]["attributes"]["last_analysis_stats"]["malicious"].as_u64().unwrap() == 0{
                println!("{}:\x1b[32mnegative/total {}/{} positive {}\x1b[37m",resj["data"]["attributes"]["meaningful_name"],negative,total,positive)
                //println!("{}\x1b[32m{}\x1b[m",resj["data"]["attributes"]["meaningful_name"],resj["data"]["attributes"]["last_analysis_stats"])
            }    
        }
        else{
            println!("{}",resj["error"]["message"])
        }
        

    }
    else{
        println!("Virus Total Hash Scanner Usage:");
        println!("-s    --single    Query a single hash");
        println!("-l    --list      Specify the path of list file")
    }
    Ok(())
}

pub async fn vt_ip_scanner() -> Result<(), Box<dyn std::error::Error>>{
    let args:Vec<String> = env::args().collect();
    if args[2].as_str() == "-s" || args[2].as_str() == "--single"{
        let client = reqwest::Client::new();
        let mut headers = header::HeaderMap::new();
        headers.insert("x-apikey",APIKEY.parse()?);
        //println!("{:?}",args[3].as_str());
        let url = format!("https://www.virustotal.com/api/v3/ip_addresses/{}",args[3].as_str());
        let res = client.get(&url).header("x-apikey",APIKEY).send().await?.text().await?;
        let resj:Value = serde_json::from_str(&res).unwrap();
        println!("{}:{},Votes:{},Whois:{}",args[3],resj["data"]["attributes"]["last_analysis_stats"],resj["data"]["attributes"]["total_votes"],resj["data"]["attributes"]["whois"]);
    }
    else if args[2].as_str()=="-l" || args[2].as_str()=="--list"{
        let file = File::open(args[3].as_str())?;
        let buffer = BufReader::new(file);
        for line in buffer.lines(){
                let client = reqwest::Client::new();
                let mut headers = header::HeaderMap::new();
                headers.insert("x-apikey",APIKEY.parse()?);
                let url = format!("https://www.virustotal.com/api/v3/ip_addresses/{}",line?);
                let res = client.get(&url).header("x-apikey",APIKEY).send().await?.text().await?;
                let resj:Value = serde_json::from_str(&res).unwrap();
                if resj.get("data") != None{
                let negative = resj["data"]["attributes"]["last_analysis_stats"]["malicious"].as_u64().unwrap()
                            + resj["data"]["attributes"]["last_analysis_stats"]["suspicious"].as_u64().unwrap();

                let positive = resj["data"]["attributes"]["last_analysis_stats"]["harmless"].as_u64().unwrap()
                            + resj["data"]["attributes"]["last_analysis_stats"]["undetected"].as_u64().unwrap();

                let total    = negative + positive;
                if resj["data"]["attributes"]["last_analysis_stats"]["malicious"].as_u64().unwrap() > 0 { 
                    println!("{}:\x1b[31mnegative/total {}/{} positive {}\x1b[37m",resj["data"]["id"],negative,total,positive)
                    //println!("{}\x1b[31m{}\x1b[m",resj["data"]["attributes"]["meaningful_name"],resj["data"]["attributes"]["last_analysis_stats"])
                }
                else if resj["data"]["attributes"]["last_analysis_stats"]["malicious"].as_u64().unwrap() == 0{
                    println!("{}:\x1b[32mnegative/total {}/{} positive {}\x1b[37m",resj["data"]["id"],negative,total,positive)
                    //println!("{}\x1b[32m{}\x1b[m",resj["data"]["attributes"]["meaningful_name"],resj["data"]["attributes"]["last_analysis_stats"])
                }
                }
                else {
                    println!("{}",resj["error"]["message"])
                }                                    
        }
    }
    else{
        println!("Virus Total Hash Scanner Usage:");
        println!("-s    --single    Query a single IP");
        println!("-l    --list      Specify the path of list file")
    }

    Ok(())
}

pub fn output_csv(contents:String) -> Result<(),String>{
    let time = SystemTime::now();
    let filepath=format!("./{:?}.csv",time);
    let outpath:&Path=Path::new("./output/output.csv");
    let mut outfile = match OpenOptions::new()
   .create(true)
   .write(true)
   .append(true)
   .open(outpath)    {
       Err(why) => panic!("Couldn't open {}: {}", "file", why),
       Ok(file) => file,
   };
   match outfile.write_all(contents.as_bytes()) {
    Ok(_r) => {}, Err(_why) => return Err(format!("Could not to write file: {}", outpath.display()))
}
    Ok(())
}