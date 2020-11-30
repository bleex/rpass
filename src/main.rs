use argparse::{ArgumentParser, StoreTrue, Store};
use keepass::{Database, Node, Result};
use std::fs;
use std::io::Read;
use std::process::exit;
use libc::{c_void};
use serde::{Serialize, Deserialize};
use blxlibssh::*;
use std::ffi::CStr;
use std::ffi::CString;

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
//    let mut verbose = false;
//    let mut yamlfile = "test.yml".to_string();
//    {
//        let mut ap = ArgumentParser::new();
//        ap.set_description("Change multiple passwords");
//        ap.refer(&mut verbose).add_option(&["-v", "--verbose"], StoreTrue, "Be verbose");
//        ap.refer(&mut yamlfile).add_option(&["-f", "--file", "--filename"], Store, "YAML file with options");
//        ap.parse_args_or_exit();
//    }
//    let s: String = fs::read_to_string(yamlfile)?;
//    let docs: Svrpass = serde_yaml::from_str(&s).unwrap();
//    println!("{:?}", docs);
//    // Open KeePass database
//    let path = std::path::Path::new(&docs.dbfile);
//    let db = Database::open(&mut std::fs::File::open(path)?, Some("sialababamak"), None)?;
//
//    let mut oldpwd_str = "";
//    let mut newpwd_str = "";
//    if let Some(Node::Entry(e)) = db.root.get(&[&docs.group, &docs.oldentry]) {
//        oldpwd_str = e.get_password().unwrap();
//    }
//    if let Some(Node::Entry(e)) = db.root.get(&[&docs.group, &docs.newentry]) {
//        newpwd_str = e.get_password().unwrap();
//    }
//    println!("{:?}", oldpwd_str);
//    println!("{:?}", newpwd_str);
//
//    // Iterate over all Groups and Nodes
//    for node in &db.root {
//        match node {
//            Node::Group(g) => {
//                println!("Saw group '{0}'", g.name);
//            },
//            Node::Entry(e) => {
//                let title = e.get_title().unwrap();
//                let user = e.get_username().unwrap();
//                let pass = e.get_password().unwrap();
//                println!("Entry '{0}': '{1}' : '{2}'", title, user, pass);
//            }
//        }
//    }
    let mut session: ssh_session;
    let rc: i32;

    session = unsafe { ssh_new() };
    if std::ptr::null() == session {
        println!("No session");
        exit(-1);
    }

    let mut host = CString::new("localhost").unwrap();
    unsafe { ssh_options_set(session, SSH_OPTIONS_HOST, host.as_ptr() as *const c_void) };
    rc = unsafe { ssh_connect(session) };

    if rc != SSH_OK {
        println!("SSH Error {:?}", rc);
        let session_ptr: *mut c_void = &mut session as *mut _ as *mut c_void; 
        let msg_ptr =  unsafe { ssh_get_error(session_ptr) };
        let c_str = unsafe { CStr::from_ptr(msg_ptr) };
        println!("{:?}", c_str.to_str());
        exit(-1);
    }
    unsafe { ssh_disconnect(session) };
    unsafe { ssh_free(session) };

    Ok(())
}
