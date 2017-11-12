extern crate trust_dns_resolver;
extern crate argparse;

use trust_dns_resolver::Resolver;
use trust_dns_resolver::config::*;
use trust_dns_resolver::system_conf::read_resolv_conf;

use argparse::{ArgumentParser, StoreTrue, Store};

use std::net::{SocketAddr,IpAddr};
use std::collections::HashMap;
use std::process::exit;

fn main() {
    let mut use_google_dns = false;
    let mut dns = String::new();

    {  // this block limits scope of borrows by ap.refer() method
        let mut ap = ArgumentParser::new();
        ap.set_description("This utility monitor a DNS record and if the IP changes it stops and prints the changes");
        ap.refer(&mut use_google_dns)
            .add_option(&["-g", "--google"], StoreTrue, "Use google dns");
        ap.refer(&mut dns)
            .add_argument("Domain", Store, "Name of domain")
            .required();
        ap.parse_args_or_exit();
    }

    if use_google_dns {
        println!("Use Google's DNS Server");
    }

    monitor_dns_record(dns.as_str(), use_google_dns);
}


fn monitor_dns_record(dns: &str, use_google_dns: bool) {
    let dns = format!("{}.", dns);

    let mut old_ips: HashMap<IpAddr, bool> = HashMap::new();;

    let mut resolver: Resolver;

    if use_google_dns {
        resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap();
    } else { // Use the same dns as the host system
        let resolv_conf = read_resolv_conf("/etc/resolv.conf");
        let resolv = resolv_conf.unwrap();

        for dns in resolv.0.name_servers() {
            match dns.socket_addr {
                SocketAddr::V4(addr) => println!("DNS Server (IPv4): {} - {}", addr, protocol(&dns.protocol)),
                SocketAddr::V6(addr) => println!("DNS Server (IPv6): {} - {}", addr, protocol(&dns.protocol)),
            }
        }

        resolver = Resolver::new(resolv.0, resolv.1).unwrap();
    }


    // Lookup the IP addresses associated with a name.
    // NOTE: do not forget the final dot, as the resolver does not yet support search paths.
    let response = resolver.lookup_ip(dns.as_str()).unwrap();
    if response.iter().count() == 0 {
        println!("No IPs was found connected to this domain");
        exit(0);
    }

    // Adds all the IPs as key in a hash-table for easy and fast lookup
    println!("Old IP(s):");
    for ip in response.iter() {
        println!(" - {}", ip);
        old_ips.insert(ip.clone(), false);
    }


    let mut new_ips: Vec<IpAddr> = Vec::new();
    let mut old_ips_clone = old_ips.clone();

    let mut run_loop = true;
    while run_loop {
        old_ips_clone = old_ips.clone();

        let response = resolver.lookup_ip(dns.as_str()).unwrap();
        for ip in response.iter() {
            match old_ips_clone.remove(ip) {
                Some(_) => {},
                None => {
                    run_loop = false;
                    new_ips.push(ip.clone());
                }
            }
        }
    }

    println!("New IP(s):");
    for ip in new_ips {
        println!(" - {}", ip);
    }

    println!("Removed IP(s):");
    for ip in old_ips_clone.keys() {
        println!(" - {}", ip);
    }

}

fn protocol<'a>(p: &'a Protocol) -> &'a str{
    match p {
        &Protocol::Udp => return "UDP",
        &Protocol::Tcp => return "TCP"
    }
}