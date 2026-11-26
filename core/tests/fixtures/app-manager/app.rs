use std::{
    fs,
    io::{BufRead, BufReader, ErrorKind, Read, Write},
    os::unix::net::UnixListener,
    thread,
    time::Duration,
};

fn main() {
    let mut bootstrap = String::new();
    std::io::stdin().read_to_string(&mut bootstrap).unwrap();
    let (_, suffix) = bootstrap.split_once("\"appSocket\":\"").unwrap();
    let (socket, _) = suffix.split_once('"').unwrap();
    let listener = UnixListener::bind(socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    fs::write("app-pid", std::process::id().to_string()).unwrap();
    loop {
        if fs::remove_file("fixture-exit").is_ok() {
            std::process::exit(1);
        }
        let mut stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(error) => panic!("{error}"),
        };
        let mut input = BufReader::new(&stream);
        let mut line = String::new();
        input.read_line(&mut line).unwrap();
        let health = line.starts_with("GET /app/v1/health ");
        let provider = line.starts_with("POST /app/v1/providers/fixture-monitor ");
        let mut length = 0;
        loop {
            line.clear();
            if input.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                break;
            }
            if let Some((name, value)) = line.split_once(':')
                && name.eq_ignore_ascii_case("content-length")
            {
                length = value.trim().parse().unwrap();
            }
        }
        // Read a provider invocation completely before answering it.
        let mut request = vec![0; length];
        input.read_exact(&mut request).unwrap();
        let body = if health {
            r#"{"healthy":true}"#
        } else if provider {
            r#"{"profile":"monitoring","payload":{"samples":[]}}"#
        } else {
            r#"{"ready":true,"protocolVersion":"1.0.0","providers":[{"id":"fixture-monitor","profile":"monitoring","version":"1.0.0"}]}"#
        };
        write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
    }
}
