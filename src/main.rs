extern crate base64;
extern crate chrono;
extern crate json;

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fs::read_to_string;
use std::process::exit;

use base64::encode as base64_encode;
use chrono::prelude::*;
use curl::easy::Easy;
use dns_lookup::lookup_host;
use hmacsha1::hmac_sha1;
use json::JsonValue;
use rand::prelude::*;
use urlencoding::encode as url_encode;

use serde::Deserialize;
use core::panicking::panic;

struct Aliyun {
    api_id: String,
    api_key: String
}

impl Aliyun {

    fn get_signature(&self, method: &str, request_data: &HashMap<&str, String>) -> String {
        //对参数进行排序
        let mut sort_map = BTreeMap::new();

        for k in request_data.keys() {
            sort_map.insert(*k, request_data[*k].clone());
        }

        //生成要签名的字符串
        let mut sign_str = String::new();
        let mut append = false;

        for (k, v) in sort_map.iter() {
            if append {
                sign_str.push_str("&");
            }

            let vs = v.to_string();
            sign_str.push_str(&*format!("{}={}", k, Aliyun::ali_encode(&vs)));
            append = true;
        }

        let message = format!("{}&%2F&{}", method, Aliyun::ali_encode(&sign_str));

        //HMAC-Sha1 签名
        let mut akey = String::from(&self.api_key);
        akey.push_str("&");
        let code = hmac_sha1(akey.as_bytes(), message.as_bytes());

        base64_encode(code)
    }

    fn get_request_data<'a>(&self, data: &HashMap<&'a str, String>) -> HashMap<&'a str, String> {
        let mut request: HashMap<&str, String> = data.clone();

        // for (k, v) in data.iter() {
        //     request.insert(*k, *v);
        // }

        //加入公共参数
        let nonce = rand_str(16);
        let local: DateTime<Utc> = Utc::now();
        let timestamp = local.format("%Y-%m-%dT%H:%M:%SZ").to_string();

        request.insert("Format", "JSON".to_string());
        request.insert("Version", "2015-01-09".to_string());
        request.insert("AccessKeyId", String::from(&self.api_id));
        request.insert("SignatureMethod", "HMAC-SHA1".to_string());
        request.insert("Timestamp", timestamp);
        request.insert("SignatureVersion", "1.0".to_string());
        request.insert("SignatureNonce", nonce);

        request
    }

    fn get_query_str(&self, sign: &String, request_data: &mut HashMap<&str, String>) -> String {
        request_data.insert("Signature", sign.clone());

        //生成要签名的字符串
        let mut query_str = String::new();
        let mut append = false;

        for (k, v) in request_data.iter() {
            if append {
                query_str.push_str("&");
            }

            let vs = v.to_string();
            query_str.push_str(format!("{}={}", k, Aliyun::ali_encode(&vs)).as_str());
            append = true;
        }

        query_str
    }

    fn ali_encode(v: &String) -> String {
        let mut encode_val = url_encode(v);
        encode_val = encode_val.replace("+", "%20");
        encode_val = encode_val.replace("*", "%2A");
        encode_val.replace("%7E", "~")
    }

    fn get(&self, data: &HashMap<&str, String>) -> JsonValue {
        let mut request_data = self.get_request_data(&data);
        let sign = self.get_signature("GET", &request_data);
        let query_str = self.get_query_str(&sign, &mut request_data);

        let url = format!("https://alidns.aliyuncs.com/?{}", query_str);
        let resposne = fetch(&url);

        let ret = json::parse(&resposne).unwrap();
        if !ret["Code"].is_null() {
            panic!(format!("接口 {} 调用失败： {}, {}", data.get("Action").unwrap(), ret["Code"], ret["Message"]));
        }

        ret
    }

    pub fn get_record_id(&self, sub_domain: &String) -> JsonValue {
        let mut data: HashMap<&str, String> = HashMap::new();
        data.insert("Action", "DescribeSubDomainRecords".to_string());
        data.insert("SubDomain", sub_domain.clone());
        data.insert("Type", "A".to_string());
        self.get(&data)
    }

    pub fn add_record(&self, domain: &String, sub: &String, ip: &String, ttl: u32) -> JsonValue {
        let mut data: HashMap<&str, String> = HashMap::new();
        data.insert("Action", "AddDomainRecord".to_string());
        data.insert("DomainName", domain.clone());
        data.insert("RR", sub.clone());
        data.insert("Type", "A".to_string());
        data.insert("Value", ip.clone());
        data.insert("TTL", ttl.to_string());
        self.get(&data)
    }

    pub fn update_record(&self, domain: &String, sub: &String, ip: &String, ttl: u32) -> JsonValue {
        let mut data: HashMap<&str, String> = HashMap::new();
        data.insert("Action", "UpdateDomainRecord".to_string());
        data.insert("DomainName", domain.clone());
        data.insert("RR", sub.clone());
        data.insert("Type", "A".to_string());
        data.insert("Value", ip.clone());
        data.insert("TTL", ttl.to_string());
        self.get(&data)
    }

}

fn rand_str<'a>(len: usize) -> String {
    let mut rstr = String::new();
    let str_pool = vec!["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F", "a", "b", "c", "d", "e", "f"];
    let max = str_pool.len();
    let mut rng = rand::thread_rng();

    for _i in 0..len {
        let offset = rng.gen_range(0, max-1);
        rstr.push_str(str_pool[offset]);
    }

    rstr
}

fn fetch(url: &str) -> String {
    let mut easy = Easy::new();
    easy.url(url).unwrap();

    let mut data = Vec::new();

    {
        let mut transfer = easy.transfer();
        transfer.write_function(|new_data| {
            data.extend_from_slice(new_data);
            Ok(new_data.len())
        }).unwrap();

        transfer.perform().unwrap();
    }

    String::from_utf8(data).unwrap()
}

fn get_current_ip() -> String {
    let ip = fetch("http://members.3322.org/dyndns/getip");
    ip.trim().to_string()
}

#[derive(Deserialize)]
struct Config {
    access_key_id: String,
    access_key_secret: String,
    domain: String,
    domain_sub: String,
    ttl: Option<u32>
}

fn main() {
    let config: Config;

    {
        let config_content = read_to_string("config.toml");
        match config_content {
            Ok(toml) => {
                match toml::from_str(toml.as_str()) {
                    Ok(v) => config = v,
                    Err(e) => {
                        println!("配置解析失败： {}", e.to_string());
                        exit(1);
                    }
                }
            },
            Err(e) => {
                println!("读取配置文件失败： {}", e.to_string());
                exit(1);
            }
        };
    }

    let domain_full = format!("{}.{}", config.domain_sub, config.domain);
    let ttl = match config.ttl {
        Some(v) => v,
        None => 600
    };

    let current_ip = get_current_ip();
    println!("当前公网IP: {}", current_ip);
    // let current_ip_addr: Ipv4Addr = current_ip.parse().unwrap();

    //先解析看是否一致
    let resolve = lookup_host(&domain_full);

    match resolve {
        Ok(ips) => {
            let mut match_current = false;
            println!("{} 解析结果： {:?}", domain_full, ips);

            for ip in ips {
                if ip.to_string().eq(&current_ip) {
                    match_current = true;
                    break;
                }
            }

            if match_current {
                println!("域名解析一致，程序结束！");
                exit(0);
            }
        },
        Err(e) => println!("{}，继续..", e.to_string())
    }

    //解析不一致再查当前设置是否一致
    let ali = Aliyun {api_id: config.access_key_id, api_key: config.access_key_secret};
    let ret = ali.get_record_id(&domain_full);

    let total_count = ret["TotalCount"].as_usize().unwrap();

    let record_ret = if total_count > 0 {
        let record = &ret["DomainRecords"]["Record"][0];
        let setting_ip = record["Value"].to_string();
        // let current_setting: Ipv4Addr = setting_ip.parse().unwrap();

        if setting_ip.eq(&current_ip) {
            println!("当前 IP {} 解析设置一致，程序结束！", current_ip);
            exit(0);
        }

        println!("当前 IP {} 与解析设置 {} 不一致，需更新！", current_ip, setting_ip);
        ali.update_record(&config.domain, &config.domain_sub, &current_ip, ttl)

    } else {
        println!("没有找到 {} 的解析记录，添加新记录。", domain_full);
        ali.add_record(&config.domain, &config.domain_sub, &current_ip, ttl)
    };

    println!("解析成功，记录ID：{}。", record_ret["RecordId"]);

}
