use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    os::unix::net::UnixListener,
};

fn main() {
    let mut bootstrap = String::new();
    std::io::stdin().read_to_string(&mut bootstrap).unwrap();
    let (_, suffix) = bootstrap.split_once("\"appSocket\":\"").unwrap();
    let (socket, _) = suffix.split_once('"').unwrap();
    let listener = UnixListener::bind(socket).unwrap();
    fs::write("app-pid", std::process::id().to_string()).unwrap();
    for connection in listener.incoming() {
        let mut stream = connection.unwrap();
        let mut input = BufReader::new(&stream);
        let mut line = String::new();
        input.read_line(&mut line).unwrap();
        let health = line.starts_with("GET /app/v1/health ");
        loop {
            line.clear();
            if input.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                break;
            }
        }
        let body = if health {
            r#"{"healthy":true}"#
        } else {
            r#"{"ready":true,"protocolVersion":"1.0.0","providers":[]}"#
        };
        write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
    }
}
