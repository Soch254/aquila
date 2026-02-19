use chrono::{ DateTime ,Utc};

use std::net::IpAddr;
use std::time::{Duration};

#[derive(Debug)]
pub struct Detection {
	pub ipaddress: IpAddr,
	pub mac_address: Option<String>,
	pub timestamp:DateTime<Utc>,
	pub response: bool,
	pub latency: Duration,
	pub scan_id: u32,
}