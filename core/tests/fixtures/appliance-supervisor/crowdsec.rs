use std::{
    io::{self, BufRead, BufReader, Write},
    net::TcpListener,
};

fn main() -> io::Result<()> {
    let server = TcpListener::bind(("127.0.0.1", 18080))?;
    let mut line = Vec::new();
    for client in server.incoming() {
        let mut client = BufReader::new(client?);
        loop {
            line.clear();
            if client.read_until(b'\n', &mut line)? == 0 || line == b"\r\n" {
                break;
            }
        }
        client
            .get_mut()
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")?;
    }
    Ok(())
}
