use super::probe::probe_execution;
use super::model::Detection;

use std::net::IpAddr;
use macaddr::MacAddr6;

//given a list of IP, we want to scan all of them

pub async fn run_scanner(ips: Vec<IpAddr>, scan_id: u32) -> Vec<Detection>  {
	//for storing the results after every scan
	let mut results = Vec::new();

	for ip in ips {
		match probe_execution(ip, scan_id).await {
			Ok(detection) => results.push(detection),
			Err(e) => {
				eprintln!("Probe failed for {} : {:?}", ip, e);
			}
		}
	}
	results
}