use super::probe::probe_execution;
use super::model::Detection;

use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use std::sync::Arc;
use std::net::IpAddr;
use macaddr::MacAddr6;

//given a list of IP, we want to scan all of them
// we have also to utilize the threads and cores of a machines cpu for fast scanning
pub async fn run_scanner(ips: Vec<IpAddr>, scan_id: u32) -> Vec<Detection>  {
	//for storing the results after every scan
	let mut set = JoinSet::new();
	let mut results = Vec::with_capacity(ips.len());

	//we limit the active probes to spawn
	let active_probes =  Arc::new(Semaphore::new(50));

	for ip in ips {
		let ticket = active_probes.clone().acquire_owned().await.unwrap();
		set.spawn(async move{
			let _ticket =  ticket;
			probe_execution(ip,scan_id).await
		});
		// match probe_execution(ip, scan_id).await {
		// 	Ok(detection) => results.push(detection),
		// 	Err(e) => {
		// 		eprintln!("Probe failed for {} : {:?}", ip, e);
		// 	}
		// }
	}
	//we collect the resulst as they finish

	while let Some(res) = set.join_next().await {
		if let Ok(Ok(result)) = res {
			results.push(result);
		}
	}

	//lets sort the list before returning it
	results.sort_by(|a, b| a.ipaddress.cmp(&b.ipaddress));

	results
}