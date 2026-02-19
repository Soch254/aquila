mod discovery;

use ipnet::IpNet;

use discovery::scanner::run_scanner;
use discovery::cidr::expand_cidr;



use std::net::IpAddr;
use std::env::args;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    let args: Vec<String> = args().collect();

    let subnet: &Vec<IpNet> =  &args[1]
        .parse::<IpNet>()               //convert into an IpNet type
        .map(|net| vec![net])          // transform it to a vec<>
        .unwrap_or_else(|_| vec![]);    // error case

    let aggrigated: Vec<IpNet> =  expand_cidr(&subnet);

    let ips: Vec<IpAddr> = aggrigated.iter()
        .flat_map(|net| net.hosts())
        .collect();

    let scan_id = 1;

    let results = run_scanner(ips, scan_id).await;

    for det in results {
        println!("{:#?}", det);
    }
    

    Ok(())
}
