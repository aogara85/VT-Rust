use std::env;
mod vt;
use serde_json::Value;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args:Vec<String> = env::args().collect();
    let apikey = "APIKEY";
    if args.len()<=1{
        println!("Usage :");
        println!("-D        Domain scan mode");
        println!("-F        File hash scan mode");
        println!("-I        IP scan mode");
        println!("-U        URL scan mode");
        
    }
    else{
        match args[1].as_str(){
            //参考              https://rustinpractice.org/rust-reqwest
            //Virustotal    v2  https://developers.virustotal.com/v2.0/reference/file-report
            //v2は全てurlにパラメータを入れて渡せるが、v3はヘッダー名x-apikeyにapikeyを設定しなければいけない
            //Virustotal    v3
            //Threatcrowd       https://github.com/AlienVault-OTX/ApiV2
            //Threatminer       https://www.threatminer.org/api.php
            "-D" => {
                        vt::vt_domain_scanner().await?;
                    },
            "-F" => {
                        vt::vt_hash_scanner().await?;
                    },
            "-I" => {
                        vt::vt_ip_scanner().await?;        
                    },
            "-U" => {
                        vt::vt_url_scanner().await?;
                    }
        ,
            _ => (),
        }
    }
    Ok(())
}