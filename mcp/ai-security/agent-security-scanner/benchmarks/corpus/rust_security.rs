//! Benchmark corpus: Rust security patterns.
//! Tests detection of unsafe code, injection, secrets, and crypto issues.

use std::fs;
use std::io::{self, Read, BufRead};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command;

// ---------------------------------------------------------------------------
// Unsafe blocks with raw pointer dereference
// ---------------------------------------------------------------------------

// VULN: rust.lang.security.unsafe-raw-pointer
unsafe fn read_arbitrary(ptr: *const u8, len: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(len);
    for i in 0..len {
        buf.push(*ptr.add(i));
    }
    buf
}

// VULN: rust.lang.security.unsafe-raw-pointer
fn cast_and_deref(data: &[u8]) -> u64 {
    unsafe {
        let ptr = data.as_ptr() as *const u64;
        *ptr
    }
}

// SAFE: rust.lang.security.unsafe-raw-pointer
fn safe_read(data: &[u8]) -> Option<u64> {
    if data.len() < 8 {
        return None;
    }
    let bytes: [u8; 8] = data[..8].try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

// ---------------------------------------------------------------------------
// Command Injection
// ---------------------------------------------------------------------------

// VULN: rust.lang.security.command-injection
fn ping_host(host: &str) {
    Command::new("sh")
        .arg("-c")
        .arg(format!("ping -c 1 {}", host))
        .status()
        .expect("failed to execute");
}

// VULN: rust.lang.security.command-injection
fn run_script(user_input: &str) {
    Command::new("bash")
        .arg("-c")
        .arg(user_input)
        .output()
        .unwrap();
}

// SAFE: rust.lang.security.command-injection
fn ping_host_safe(host: &str) {
    Command::new("ping")
        .arg("-c")
        .arg("1")
        .arg(host)
        .status()
        .expect("failed to execute");
}

// ---------------------------------------------------------------------------
// SQL Injection (via string formatting)
// ---------------------------------------------------------------------------

// VULN: rust.lang.security.sql-injection
fn find_user(conn: &Connection, username: &str) -> Result<Vec<Row>, Error> {
    let query = format!("SELECT * FROM users WHERE name = '{}'", username);
    conn.query(&query, &[])
}

// VULN: rust.lang.security.sql-injection
fn delete_record(conn: &Connection, id: &str) {
    let stmt = String::from("DELETE FROM records WHERE id = ") + id;
    conn.execute(&stmt, &[]).unwrap();
}

// SAFE: rust.lang.security.sql-injection
fn find_user_safe(conn: &Connection, username: &str) -> Result<Vec<Row>, Error> {
    conn.query("SELECT * FROM users WHERE name = $1", &[&username])
}

// ---------------------------------------------------------------------------
// Hardcoded Secrets
// ---------------------------------------------------------------------------

// VULN: rust.lang.security.hardcoded-secret
const DATABASE_PASSWORD: &str = "p@ssw0rd_pr0duction_2024!";

// VULN: rust.lang.security.hardcoded-secret
const AWS_SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

// SAFE: rust.lang.security.hardcoded-secret
fn get_db_password() -> String {
    std::env::var("DATABASE_PASSWORD").expect("DATABASE_PASSWORD must be set")
}

// ---------------------------------------------------------------------------
// unwrap() on network / user input
// ---------------------------------------------------------------------------

// VULN: rust.lang.security.unwrap-on-input
fn read_request(stream: &mut TcpStream) -> String {
    let mut buf = String::new();
    stream.read_to_string(&mut buf).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&buf).unwrap();
    parsed["name"].as_str().unwrap().to_string()
}

// SAFE: rust.lang.security.unwrap-on-input
fn read_request_safe(stream: &mut TcpStream) -> Result<String, Box<dyn std::error::Error>> {
    let mut buf = String::new();
    stream.read_to_string(&mut buf)?;
    let parsed: serde_json::Value = serde_json::from_str(&buf)?;
    let name = parsed["name"]
        .as_str()
        .ok_or("missing name field")?
        .to_string();
    Ok(name)
}

// ---------------------------------------------------------------------------
// Path Traversal
// ---------------------------------------------------------------------------

// VULN: rust.lang.security.path-traversal
fn serve_file(user_path: &str) -> io::Result<Vec<u8>> {
    let full = format!("/var/www/static/{}", user_path);
    fs::read(&full)
}

// SAFE: rust.lang.security.path-traversal
fn serve_file_safe(user_path: &str) -> io::Result<Vec<u8>> {
    let base = Path::new("/var/www/static");
    let requested = base.join(user_path);
    let canonical = requested.canonicalize()?;
    if !canonical.starts_with(base) {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "path traversal blocked"));
    }
    fs::read(&canonical)
}

// ---------------------------------------------------------------------------
// Weak Cryptography
// ---------------------------------------------------------------------------

// VULN: rust.lang.security.weak-crypto
fn hash_password_md5(password: &str) -> String {
    use md5;
    format!("{:x}", md5::compute(password))
}

// SAFE: rust.lang.security.weak-crypto
fn hash_password_safe(password: &str) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    format!("{:x}", hasher.finalize())
}

// ---------------------------------------------------------------------------
// Main (placeholder)
// ---------------------------------------------------------------------------

fn main() {
    println!("Rust security benchmark corpus");
}
