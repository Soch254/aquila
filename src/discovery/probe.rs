use super::model::Detection;

use surge_ping::{Client, Config, PingIdentifier, PingSequence, SurgeError};
use netneighbours::get_table;

use std::collections::HashMap;
use std::net::IpAddr;
use macaddr::MacAddr6;
use std::time::{Duration, SystemTime};
use std::io::ErrorKind;

#[derive(Debug)]
pub enum ProbeError {
	PermissionDenied,
	SystemError(String),
	Other(String),
}

async fn icmp_ping(ipaddress: IpAddr) -> Result<(bool, Duration), ProbeError>{
	//ICMP client creation because we will ping many ips
	// creating a socket to send our pings
	let client = Client::new(&Config::default())
	.map_err(|e| ProbeError::Other(format!("Client creation failed {}", e)))?;

	//set up an echo ping for a specific IP
	// giving the socket an IP Adress and send a ping 
	let mut pinger = client.pinger(ipaddress, PingIdentifier(0)).await;
	// .map_err(|e| ProbeError::Other(format!("Pinger creation failed {}", e)))?;

	//timoeout the pinger/roundtrip time (50ms)
	pinger.timeout(Duration::from_secs(1));

	//sending the ping
	match pinger.ping(PingSequence(0), &[]).await {
		//ok reply
		Ok((_packet, duration))=> Ok((true, duration)),
		//timeout reply
		Err(SurgeError::Timeout{..}) => Ok((false, Duration::from_millis(1000))),
		//permission/networking error
		Err(SurgeError::IOError(io_error)) => {
			if io_error.kind() == ErrorKind::PermissionDenied{
				//Permission error
				Err(ProbeError::PermissionDenied)
			} else {
				//system/network error
				Err(ProbeError::SystemError(io_error.to_string()))
			}
		},
		//other errors
		Err(e) => Err(ProbeError::Other(e.to_string())),
	}

}

fn get_macaddress(ipaddress: IpAddr) -> Option<String> {
	// // get the table first
	// let mac_address = get_table()
	// .iter() //looks at the list
	// .find(|(entry_ip, _)| *entry_ip == ip) //find the tuple with the ip that matches
	// .map(|(_, mac)| *mac); // clone() because the .get() returns a &mac

	// the get_table returns a vec<>
	// we convert it to a hashmap for quicker lookup
	let arp_table: HashMap<IpAddr, MacAddr6> = get_table().into_iter().collect();

	arp_table.get(&ipaddress).map(|m| format!("{}", m))


}

pub async fn probe_execution(ipaddress: IpAddr, scan_id: u32) -> Result<Detection, ProbeError> {

	let timestamp = SystemTime::now();

	let (response, latency) = icmp_ping(ipaddress).await?;

	let mac_address = get_macaddress(ipaddress);

	let detection = Detection {
		ipaddress,
		mac_address,
		timestamp,
		response,
		latency,
		scan_id,
	};

	Ok(detection)

}