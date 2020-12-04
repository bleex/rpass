use argparse::{ArgumentParser, StoreTrue, Store};
use keepass::{Database, Node, Result};
use std::fs;
use std::io::Read;
use std::process::exit;
use libc::{c_void,c_char,size_t};
use serde::{Serialize, Deserialize};
use blxlibssh::*;
use std::ffi::{CStr, CString};

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
    let mut rc: i32;

    session = unsafe { ssh_new() };
    if std::ptr::null() == session {
        println!("No session");
        exit(-1);
    }

    let mut host = CString::new("localhost").unwrap();
    let mut user = CString::new("a").unwrap();
    unsafe { ssh_options_set(session, SSH_OPTIONS_HOST, host.as_ptr() as *const c_void) };
    unsafe { ssh_options_set(session, SSH_OPTIONS_USER, user.as_ptr() as *const c_void) };
    rc = unsafe { ssh_connect(session) };

    if rc != SSH_OK {
        println!("1. SSH Error {:?}", rc);
        let c_str = unsafe { CStr::from_ptr(ssh_get_error(session as *mut c_void)).to_string_lossy().into_owned() };
        println!("{:?}", c_str);
        exit(-1);
    }
    let mut pass = CString::new("q").unwrap();
    rc = unsafe { ssh_userauth_password(session, std::ptr::null(), pass.as_ptr() as *const c_char) };

    if rc != SSH_OK {
        println!("2. SSH Error {:?}", rc);
        let c_str = unsafe { CStr::from_ptr(ssh_get_error(session as *mut c_void)).to_string_lossy().into_owned() };
        println!("{:?}", c_str);
        exit(-1);
    }

    let mut channel = unsafe { ssh_channel_new(session) };
    if std::ptr::null() == channel {
        println!("No channel");
        exit(-1);
    }
    rc = unsafe { ssh_channel_open_session(channel) };
    if rc != SSH_OK {
        println!("3. SSH Error {:?}", rc);
        let c_str = unsafe { CStr::from_ptr(ssh_get_error(session as *mut c_void)).to_string_lossy().into_owned() };
        println!("{:?}", c_str);
        exit(-1);
    }
    rc = unsafe { ssh_channel_request_pty(channel) };
    if rc != SSH_OK {
        println!("4. SSH Error {:?}", rc);
        let c_str = unsafe { CStr::from_ptr(ssh_get_error(session as *mut c_void)).to_string_lossy().into_owned() };
        println!("{:?}", c_str);
        exit(-1);
    }
    rc = unsafe { ssh_channel_change_pty_size(channel, 80, 25) };
    if rc != SSH_OK {
        println!("5. SSH Error {:?}", rc);
        let c_str = unsafe { CStr::from_ptr(ssh_get_error(session as *mut c_void)).to_string_lossy().into_owned() };
        println!("{:?}", c_str);
        exit(-1);
    }
    rc = unsafe { ssh_channel_request_shell(channel) };
    if rc != SSH_OK {
        println!("6. SSH Error {:?}", rc);
        let c_str = unsafe { CStr::from_ptr(ssh_get_error(session as *mut c_void)).to_string_lossy().into_owned() };
        println!("{:?}", c_str);
        exit(-1);
    }

    while 0 == unsafe { ssh_channel_is_open(channel) } &&
        0 != unsafe { ssh_channel_is_eof(channel) } {
        let mut buf: [u8; 1024] = [0; 1024];
        rc = unsafe { ssh_channel_read(channel, buf.as_mut_ptr() as *mut c_void, buf.len() as u32, 1) };

        if rc != SSH_OK {
            println!("7. SSH Error {:?}", rc);
            let c_str = unsafe { CStr::from_ptr(ssh_get_error(session as *mut c_void)).to_string_lossy().into_owned() };
            println!("{:?}", c_str);
            exit(-1);
        }

    }
    unsafe { ssh_disconnect(session) };
    unsafe { ssh_free(session) };

    Ok(())
}
