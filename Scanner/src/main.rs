use std::env;
use serde_json::Value;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args:Vec<String> = env::args().collect();
    let apikey = "APIKEY";
    if args.len()<=1{
        println!("Usage :");
        println!("-d    Domain scan");
        println!("-f    File hash scan");
        println!("-i    IP scan");
        println!("-u    URL scan")
    }
    else{
        match args[1].as_str(){
            //Virustotal    https://developers.virustotal.com/v2.0/reference/file-report
            //Threatcrowd   https://github.com/AlienVault-OTX/ApiV2
            //Threatminer   https://www.threatminer.org/api.php
            "-d" => {
                        let domain="google.com";
                        let url = format!("https://www.virustotal.com/vtapi/v2/domain/report?apikey={}&domain={}",apikey,domain);
                        let res = reqwest::get(&url).await?.text().await?;
                        let resj:Value = serde_json::from_str(&res).unwrap();
                        println!("{:?}", resj["detected_downloaded_samples"]);
                    },
            "-f" => {
                        let file_hash="ec8c89aa5e521572c74e2dd02a4daf78";
                        let url = format!("https://www.virustotal.com/vtapi/v2/file/report?apikey={}&resource={}",apikey,file_hash);
                        let res = reqwest::get(&url).await?.text().await?;
                        let resj:Value = serde_json::from_str(&res).unwrap();
                        println!("{}/{}", resj["positives"],resj["total"]);
                    },
            "-i" => {
                        let ip_address="104.21.66.123";
                        let url_vt = format!("https://www.virustotal.com/vtapi/v2/ip-address/report?apikey={}&ip={}",apikey,ip_address);
                        let url_tc = format!("https://www.threatcrowd.org/searchApi/v2/ip/report/?ip={}",ip_address);
                        let res = reqwest::get(&url_vt).await?.text().await?;
                        let res_tc = reqwest::get(&url_tc).await?.text().await?;
                        let resj:Value = serde_json::from_str(&res).unwrap();
                        let resj_tc:Value = serde_json::from_str(&res_tc).unwrap();
                        println!("{:?}", resj["detected_urls"]);
                        println!("{:?}", resj_tc);
                        
                    },
            "-u" => {
                        let scanned_url ="https://xn--shopnamla-8w7d.com/";
                        let url = format!("https://www.virustotal.com/vtapi/v2/url/report?apikey={}&resource={}",apikey,scanned_url);
                        let res = reqwest::get(&url).await?.text().await?;
                        let resj:Value = serde_json::from_str(&res).unwrap();
                        println!("{}/{}", resj["positives"],resj["total"]);
                    }   
        ,
            _ => (),
        }
    }
    Ok(())
}