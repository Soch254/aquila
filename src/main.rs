mod discovery;

use discovery::scanner::run_scanner;
// use discovery::model::Detection;

use std::net::IpAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ips: Vec<IpAddr> = vec![
            "192.168.1.1".parse().unwrap(),
            "192.168.1.10".parse().unwrap(),
    ];

    let scan_id = 1;

    let results = run_scanner(ips, scan_id).await;

    println!("{:#?}", results);

    Ok(())
}
