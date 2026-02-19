use ipnet::IpNet;



//We want to do net aggrigation
pub fn expand_cidr(cidr: &Vec<IpNet>) -> Vec<IpNet> {
	//aggrigate
	let ips = IpNet::aggregate(cidr);

	ips
}