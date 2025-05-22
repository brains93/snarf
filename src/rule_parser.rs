// use std::collections::HashMap;
use regex::Regex;

#[derive(Debug)]
pub enum RuleAction {
    Alert,
    Pass,
    Drop,
}


#[derive(Debug)]
pub struct SnortRule {
    pub action: RuleAction,
    pub protocol: String,
    pub src_ip: String,
    pub src_port: String,
    pub direction: String,
    pub dst_ip: String,
    pub dst_port: String,
    pub msg: Option<String>,
    pub content: Option<String>,
}

pub fn parse_snort_rule(rule_str: &str) -> Result<SnortRule, &'static str> {
    let re = Regex::new(r"(?x)
        ^(?P<action>alert|pass|drop)\s+
        (?P<protocol>\w+)\s+
        (?P<src_ip>[^\s]+)\s+
        (?P<src_port>[^\s]+)\s+
        (?P<direction>-?>|<-?)\s+
        (?P<dst_ip>[^\s]+)\s+
        (?P<dst_port>[^\s]+)
        \s*\((?P<options>.*)\)\s*$      
    ").unwrap();

    let caps = re.captures(rule_str).ok_or("Invalid rule format")?;

    let action = match caps.name("action").unwrap().as_str() {
        "alert" => RuleAction::Alert,
        "pass" => RuleAction::Pass,
        "drop" => RuleAction::Drop,
        _ => return Err("Invalid rule action"),
    };

    let protocol = caps["protocol"].to_string();
    let src_ip = caps["src_ip"].to_string();
    let src_port = caps["src_port"].to_string();
    let direction = caps["direction"].to_string();
    let dst_ip = caps["dst_ip"].to_string();
    let dst_port = caps["dst_port"].to_string();

    // Extract msg and content from options
    let options = caps.name("options").map(|m| m.as_str()).unwrap_or("");
    let msg_re = Regex::new(r#"msg\s*:\s*"([^"]*)""#).unwrap();
    let content_re = Regex::new(r#"content\s*:\s*"([^"]*)""#).unwrap();

    let msg = msg_re.captures(options).and_then(|c| c.get(1)).map(|m| m.as_str().to_string());
    let content = content_re.captures(options).and_then(|c| c.get(1)).map(|m| m.as_str().to_string());



    Ok(SnortRule {
        action,
        protocol,
        src_ip,
        src_port,
        direction,
        dst_ip,
        dst_port,
        msg,
        content,
    })
}
