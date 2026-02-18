use std::net::IpAddr;
// use macaddr::MacAddr6;
use std::time::{SystemTime, Duration};

#[derive(Debug)]
pub struct Detection {
	pub ipaddress: IpAddr,
	pub mac_address: Option<String>,
	pub timestamp:SystemTime,
	pub response: bool,
	pub latency: Duration,
	pub scan_id: u32,
}