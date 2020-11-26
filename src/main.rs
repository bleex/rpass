extern crate argparse;
extern crate keepass;
extern crate serde_yaml;
extern crate ssh;

use argparse::{ArgumentParser, StoreTrue, Store};
use keepass::{Database, Node, Result};
use std::fs;
use std::io::Read;
use serde::{Serialize, Deserialize};
use ssh::*;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all="camelCase")]
struct Svrpass {
    dbfile: String,
    oldentry: String,
    newentry: String,
    group: String,
    user: String,
    servers: Vec<String>
}


fn main() -> Result<()> {
    let mut verbose = false;
    let mut yamlfile = "test.yml".to_string();
    {
        let mut ap = ArgumentParser::new();
        ap.set_description("Change multiple passwords");
        ap.refer(&mut verbose).add_option(&["-v", "--verbose"], StoreTrue, "Be verbose");
        ap.refer(&mut yamlfile).add_option(&["-f", "--file", "--filename"], Store, "YAML file with options");
        ap.parse_args_or_exit();
    }
    let s: String = fs::read_to_string(yamlfile)?;
    let docs: Svrpass = serde_yaml::from_str(&s).unwrap();
    println!("{:?}", docs);
    // Open KeePass database
    let path = std::path::Path::new(&docs.dbfile);
    let db = Database::open(&mut std::fs::File::open(path)?, Some("sialababamak"), None)?;

    let mut oldpwd_str = "";
    let mut newpwd_str = "";
    if let Some(Node::Entry(e)) = db.root.get(&[&docs.group, &docs.oldentry]) {
        oldpwd_str = e.get_password().unwrap();
    }
    if let Some(Node::Entry(e)) = db.root.get(&[&docs.group, &docs.newentry]) {
        newpwd_str = e.get_password().unwrap();
    }
    println!("{:?}", oldpwd_str);
    println!("{:?}", newpwd_str);

    // Iterate over all Groups and Nodes
    for node in &db.root {
        match node {
            Node::Group(g) => {
                println!("Saw group '{0}'", g.name);
            },
            Node::Entry(e) => {
                let title = e.get_title().unwrap();
                let user = e.get_username().unwrap();
                let pass = e.get_password().unwrap();
                println!("Entry '{0}': '{1}' : '{2}'", title, user, pass);
            }
        }
    }

    let mut session=Session::new().unwrap();
    session.set_host("localhost").unwrap();
    session.set_username(&docs.user).unwrap();
    session.parse_config(None).unwrap();
    session.connect().unwrap();
    session.userauth_password(oldpwd_str).unwrap();
    {
        let mut s=session.channel_new().unwrap();
        s.open_session().unwrap();
        s.request_exec(b"id").unwrap();
        s.send_eof().unwrap();
        let mut buf=Vec::new();
        s.stdout().read_to_end(&mut buf).unwrap();
        println!("{:?}",std::str::from_utf8(&buf).unwrap());
    }


    Ok(())
}
