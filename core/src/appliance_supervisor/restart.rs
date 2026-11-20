use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use std::io;

fn reserve(now: u64, previous: &[u64]) -> io::Result<Vec<u64>> {
    if previous.len() > 3
        || previous.windows(2).any(|pair| pair[0] > pair[1])
        || previous.last().is_some_and(|last| *last > now)
    {
        return Err(io::Error::other("Invalid web restart history"));
    }
    let mut recent: Vec<_> = previous
        .iter()
        .copied()
        .filter(|attempt| now - attempt < 300)
        .collect();
    if recent.len() == 3 {
        return Err(io::Error::other("Web restart budget exhausted"));
    }
    recent.push(now);
    Ok(recent)
}

pub(super) fn run(args: &[String]) -> io::Result<()> {
    let values = args
        .iter()
        .map(|value| value.parse::<u64>().map_err(io::Error::other))
        .collect::<io::Result<Vec<_>>>()?;
    let (now, previous) = values
        .split_first()
        .ok_or_else(|| io::Error::other("Missing web restart clock"))?;
    let recent = reserve(*now, previous)?;
    let mut jitter = [0; 2];
    SystemRandom::new()
        .fill(&mut jitter)
        .map_err(|_| io::Error::other("Random source unavailable"))?;
    let seconds = 1 << (recent.len() - 1);
    let millis = u16::from_be_bytes(jitter) % 250;
    let attempts = recent
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    println!("{seconds}.{millis:03} {attempts}");
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/private/appliance_supervisor_restart.rs"]
mod tests;
