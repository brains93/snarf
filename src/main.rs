extern crate pcap;
mod rule_parser;
use rule_parser::{parse_snort_rule, SnortRule};

mod network_capture;
use network_capture::get_traffic;
// use std::env;
use std::fs;



fn main() {
    let mut rules_list:  Vec<SnortRule> = Vec::new();
    // let snort_rules = vec![
    //     "alert tcp any any -> any any",
    //     "drop tcp any any -> any 80",
    // ];

    let file_content = fs::read_to_string("/Users/gmac/Code/snarf/src/snort_rules.txt")
        .expect("Failed to read the file");
    
    let snort_rules = file_content.lines().map(|line| line.trim()).collect::<Vec<&str>>();
    
   
    for rule_str in snort_rules {
        match parse_snort_rule(rule_str) {
            Ok(rule) => {
                // this will push any rules that match into a lisf of structs that can be looped through during packet capture
                println!("Parsed rule: {:?}", rule.dst_ip);
                rules_list.push(rule);
            }
            Err(err) => eprintln!("Error parsing rule: {}", err),
        }
    }
    for rule in &rules_list {
        println!("{}", rule.dst_ip);
    }
    
    get_traffic(&rules_list)

}