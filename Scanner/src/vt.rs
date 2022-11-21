use serde_json::Value;
use std::env;
use std::io::BufReader;
use std::io::BufRead;
use std::fs::File;
use reqwest::header;
use std::path::Path;
use std::fs::OpenOptions;
use std::{io::Write};
use chrono::{DateTime, Local};
use sha256::digest;

static APIKEY:&str="APIKEY";

pub async fn vt_hash_scanner() -> Result<(), Box<dyn std::error::Error>>{
    let args:Vec<String> = env::args().collect();
    let dt: DateTime<Local> = Local::now();
    let timestamp: i64 = dt.timestamp();
    let filepath=format!("./output/Hashscan-{}.csv",timestamp);//ファイル名の生成（時間）
    output_csv(format!("meaningful_name,detected,negative,positive,SHA256,MD5,SHA1\n"),&filepath).expect("failed");//outputのフォーマット
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
                    output_csv(format!("{},detected,{},{},{},{},{}\n"
                    ,resj["data"]["attributes"]["meaningful_name"]
                    ,negative,positive,resj["data"]["id"]
                    ,resj["data"]["attributes"]["md5"],resj["data"]["attributes"]["sha1"])
                    ,&filepath)
                    .expect("failed");
                    println!("{}:\x1b[31mnegative/total {}/{} positive {}\x1b[37m",resj["data"]["attributes"]["meaningful_name"],negative,total,positive)
                    //println!("{}\x1b[31m{}\x1b[m",resj["data"]["attributes"]["meaningful_name"],resj["data"]["attributes"]["last_analysis_stats"])
                }
                else if resj["data"]["attributes"]["last_analysis_stats"]["malicious"].as_u64().unwrap() == 0{
                    
                    output_csv(format!("{},safe,{},{},{},{},{}\n"
                    ,resj["data"]["attributes"]["meaningful_name"]
                    ,negative
                    ,positive
                    ,resj["data"]["id"]
                    ,resj["data"]["attributes"]["md5"]
                    ,resj["data"]["attributes"]["sha1"])
                    ,&filepath)
                    .expect("failed"); 
                    println!("{}:\x1b[32mnegative/total {}/{} positive {}\x1b[37m",resj["data"]["attributes"]["meaningful_name"],negative,total,positive)
                    //println!("{}\x1b[32m{}\x1b[m",resj["data"]["attributes"]["meaningful_name"],resj["data"]["attributes"]["last_analysis_stats"])
                }
                }
                else {
                    output_csv(format!("{}",resj["error"]["message"]),&filepath).expect("failed");
                    println!("{}\n",resj["error"]["message"])
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
    let dt: DateTime<Local> = Local::now();
    let timestamp: i64 = dt.timestamp();
    let filepath=format!("./output/IPscan-{}.csv",timestamp);//ファイル名の生成（時間）
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
        output_csv(format!("ip,result,negative,positive,virustotal_link\n"),&filepath).expect("failed");//outputのフォーマット
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
                        output_csv(format!("{},detected,{},{},{},{}\n"
                        ,resj["data"]["id"]
                        ,negative
                        ,total
                        ,positive,resj["data"]["links"]["self"])
                        ,&filepath)
                        .expect("failed");
                        println!("{}:\x1b[31mnegative/total {}/{} positive {}\x1b[37m",resj["data"]["id"],negative,total,positive)
                        //println!("{}\x1b[31m{}\x1b[m",resj["data"]["attributes"]["meaningful_name"],resj["data"]["attributes"]["last_analysis_stats"])
                    }
                    else if resj["data"]["attributes"]["last_analysis_stats"]["malicious"].as_u64().unwrap() == 0{
                        output_csv(format!("{},safe,{},{},{},{}\n"
                        ,resj["data"]["id"]
                        ,negative
                        ,total
                        ,positive,resj["data"]["links"]["self"])
                        ,&filepath)
                        .expect("failed");
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
        println!("Virus Total IP Scanner Usage:");
        println!("-s    --single    Query a single IP");
        println!("-l    --list      Specify the path of list file")
    }

    Ok(())
}

pub async fn vt_url_scanner() -> Result<(), Box<dyn std::error::Error>>{
    let dt: DateTime<Local> = Local::now();
    let timestamp: i64 = dt.timestamp();
    let filepath=format!("./output/URLscan-{}.csv",timestamp);//ファイル名の生成（時間）
    let args:Vec<String> = env::args().collect();
    if args[2].as_str() == "-s" || args[2].as_str() == "--single"{
        let client = reqwest::Client::new();
        let mut headers = header::HeaderMap::new();
        headers.insert("x-apikey",APIKEY.parse()?);
        let url = format!("https://www.virustotal.com/api/v3/urls/{}",digest(args[3].as_str()));
        let res = client.get(&url).header("x-apikey",APIKEY).send().await?.text().await?;
        let resj:Value = serde_json::from_str(&res).unwrap();
        println!("{}:{},Votes:{},categpries:{}",resj["data"]["attributes"]["url"],resj["data"]["attributes"]["last_analysis_stats"],resj["data"]["attributes"]["total_votes"],resj["data"]["attributes"]["categories"]);
    }
    else if args[2].as_str()=="-l" || args[2].as_str()=="--list"{
        let file = File::open(args[3].as_str())?;
        let buffer = BufReader::new(file);
        output_csv(format!("url,result,negative,positive,virustotal_link\n"),&filepath).expect("failed");//outputのフォーマット
        for line in buffer.lines(){
                let client = reqwest::Client::new();
                let mut headers = header::HeaderMap::new();
                headers.insert("x-apikey",APIKEY.parse()?);
                let url = format!("https://www.virustotal.com/api/v3/urls/{}",digest(line?));
                let res = client.get(&url).header("x-apikey",APIKEY).send().await?.text().await?;
                let resj:Value = serde_json::from_str(&res).unwrap();
                if resj.get("data") != None{
                    let negative = resj["data"]["attributes"]["last_analysis_stats"]["malicious"].as_u64().unwrap()
                                + resj["data"]["attributes"]["last_analysis_stats"]["suspicious"].as_u64().unwrap();

                    let positive = resj["data"]["attributes"]["last_analysis_stats"]["harmless"].as_u64().unwrap()
                                + resj["data"]["attributes"]["last_analysis_stats"]["undetected"].as_u64().unwrap();

                    let total    = negative + positive;
                    if resj["data"]["attributes"]["last_analysis_stats"]["malicious"].as_u64().unwrap() > 0 {
                        output_csv(format!("{},detected,{},{},{},{}\n"
                        ,resj["data"]["attributes"]["url"]
                        ,negative
                        ,total
                        ,positive,resj["data"]["links"]["self"])
                        ,&filepath)
                        .expect("failed");
                        println!("{}:\x1b[31mnegative/total {}/{} positive {}\x1b[37m",resj["data"]["attributes"]["url"],negative,total,positive)
                        //println!("{}\x1b[31m{}\x1b[m",resj["data"]["attributes"]["meaningful_name"],resj["data"]["attributes"]["last_analysis_stats"])
                    }
                    else if resj["data"]["attributes"]["last_analysis_stats"]["malicious"].as_u64().unwrap() == 0{
                        output_csv(format!("{},safe,{},{},{},{}\n"
                        ,resj["data"]["attributes"]["url"]
                        ,negative
                        ,total
                        ,positive,resj["data"]["links"]["self"])
                        ,&filepath)
                        .expect("failed");
                        println!("{}:\x1b[32mnegative/total {}/{} positive {}\x1b[37m",resj["data"]["attributes"]["url"],negative,total,positive)
                        //println!("{}\x1b[32m{}\x1b[m",resj["data"]["attributes"]["meaningful_name"],resj["data"]["attributes"]["last_analysis_stats"])
                    }
                }
                else {
                    println!("{}\n",resj["error"]["message"])
                }                                    
        }
    }
    else{
        println!("Virus Total URL Scanner Usage:");
        println!("-s    --single    Query a single IP");
        println!("-l    --list      Specify the path of list file")
    }    

    Ok(())
}

pub async fn vt_domain_scanner()-> Result<(), Box<dyn std::error::Error>>{
    let args:Vec<String> = env::args().collect();
    let dt: DateTime<Local> = Local::now();
    let timestamp: i64 = dt.timestamp();
    let filepath=format!("./output/Domainscan-{}.csv",timestamp);//ファイル名の生成（時間）
    if args[2].as_str() == "-s" || args[2].as_str() == "--single"{
    let client = reqwest::Client::new();
    let mut headers = header::HeaderMap::new();
    headers.insert("x-apikey",APIKEY.parse()?);
    let url = format!("https://www.virustotal.com/api/v3/domains/{}",args[3].as_str());
    let res = client.get(&url).header("x-apikey",APIKEY).send().await?.text().await?;
    let resj:Value = serde_json::from_str(&res).unwrap();
    println!("{}:{},Votes:{},categpries:{}",resj["data"]["id"],resj["data"]["attributes"]["last_analysis_stats"],resj["data"]["attributes"]["total_votes"],resj["data"]["attributes"]["categories"]);
    }

    // for i in resj["data"].as_array(){
    //     for j in i{
    //             println!("{},{}",j["attributes"],j["attributes"]["type_description"]);
    //     }
    // }
    else if args[2].as_str()=="-l" || args[2].as_str()=="--list"{
        let file = File::open(args[3].as_str())?;
        let buffer = BufReader::new(file);
        output_csv(format!("domain,result,negative,positive,virustotal_link\n"),&filepath).expect("failed");//outputのフォーマット
        for line in buffer.lines(){
                let client = reqwest::Client::new();
                let mut headers = header::HeaderMap::new();
                headers.insert("x-apikey",APIKEY.parse()?);
                let url = format!("https://www.virustotal.com/api/v3/domains/{}",line?);
                let res = client.get(&url).header("x-apikey",APIKEY).send().await?.text().await?;
                let resj:Value = serde_json::from_str(&res).unwrap();
                if resj.get("data") != None{
                    let negative = resj["data"]["attributes"]["last_analysis_stats"]["malicious"].as_u64().unwrap()
                                + resj["data"]["attributes"]["last_analysis_stats"]["suspicious"].as_u64().unwrap();

                    let positive = resj["data"]["attributes"]["last_analysis_stats"]["harmless"].as_u64().unwrap()
                                + resj["data"]["attributes"]["last_analysis_stats"]["undetected"].as_u64().unwrap();

                    let total    = negative + positive;
                    if resj["data"]["attributes"]["last_analysis_stats"]["malicious"].as_u64().unwrap() > 0 {
                        output_csv(format!("{},detected,{},{},{},{}\n"
                        ,resj["data"]["id"]
                        ,negative
                        ,total
                        ,positive,resj["data"]["links"]["self"])
                        ,&filepath)
                        .expect("failed");
                        println!("{}:\x1b[31mnegative/total {}/{} positive {}\x1b[37m",resj["data"]["id"],negative,total,positive)
                        //println!("{}\x1b[31m{}\x1b[m",resj["data"]["attributes"]["meaningful_name"],resj["data"]["attributes"]["last_analysis_stats"])
                    }
                    else if resj["data"]["attributes"]["last_analysis_stats"]["malicious"].as_u64().unwrap() == 0{
                        output_csv(format!("{},safe,{},{},{},{}\n"
                        ,resj["data"]["id"]
                        ,negative
                        ,total
                        ,positive,resj["data"]["links"]["self"])
                        ,&filepath)
                        .expect("failed");
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
        println!("Virus Total IP Scanner Usage:");
        println!("-s    --single    Query a single IP");
        println!("-l    --list      Specify the path of list file")
    }    
    Ok(())
}

pub fn output_csv(contents:String,filepath:&str) -> Result<(),String>{
    let outpath:&Path=Path::new(&filepath);
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