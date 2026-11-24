//! TCP peer-UID verification (REQUIREMENTS.md §11.2/§11.3; M1.1 findings H1/H2).
//!
//! Every accepted loopback connection is attributed to the Linux user that owns the *client*
//! socket, by finding the client's end of the connection in `/proc/net/tcp` (and `/proc/net/tcp6`
//! for dual-stack clients): the row whose local address is the client's address and whose remote
//! address is ours. The connection is served only if that user is the daemon's effective UID, so a
//! sign-in link or session token leaked to another local user is useless to them. The check runs
//! once per connection (HTTP keep-alive requests on it inherit the result) and fails closed: no
//! row, several rows with different owners, or an unreadable table all mean "reject".

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

/// The kernel's TCP socket tables for the daemon's network namespace.
pub const PROC_NET_TCP: [&str; 2] = ["/proc/net/tcp", "/proc/net/tcp6"];
/// `st` column value of TIME_WAIT rows (their uid column is always 0).
const TCP_TIME_WAIT: &str = "06";

/// `(client address, server address) -> owner UID of the client socket`, if found.
pub type PeerUidLookup =
    Arc<dyn Fn(SocketAddr, SocketAddr) -> io::Result<Option<u32>> + Send + Sync>;

/// The production lookup: read the procfs tables (a missing `tcp6` table means no IPv6).
pub fn procfs_lookup() -> PeerUidLookup {
    Arc::new(|client, server| {
        let mut uids = Vec::new();
        for path in PROC_NET_TCP {
            match std::fs::read_to_string(path) {
                Ok(table) => uids.extend(matching_uids(&table, client, server)),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        Ok(single_uid(uids))
    })
}

/// Why a connection is or is not served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allowed,
    OtherUser(u32),
    NotFound,
    LookupFailed,
}

pub fn decide(lookup: &io::Result<Option<u32>>, daemon_uid: u32) -> Verdict {
    match lookup {
        Ok(Some(uid)) if *uid == daemon_uid => Verdict::Allowed,
        Ok(Some(uid)) => Verdict::OtherUser(*uid),
        Ok(None) => Verdict::NotFound,
        Err(_) => Verdict::LookupFailed,
    }
}

/// Owner UIDs of the rows describing the client's end of `client -> server` in one table.
pub fn matching_uids(table: &str, client: SocketAddr, server: SocketAddr) -> Vec<u32> {
    let (client, server) = (canonical(client), canonical(server));
    table
        .lines()
        .filter_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            // sl local_address rem_address st tx:rx tr:when retrnsmt uid ...
            if cols.len() < 8 || cols[0] == "sl" || cols[3] == TCP_TIME_WAIT {
                return None;
            }
            let local = parse_endpoint(cols[1])?;
            let remote = parse_endpoint(cols[2])?;
            (local == client && remote == server)
                .then(|| cols[7].parse::<u32>().ok())
                .flatten()
        })
        .collect()
}

/// Exactly one distinct owner, or nothing (ambiguity fails closed).
pub fn single_uid(mut uids: Vec<u32>) -> Option<u32> {
    uids.sort_unstable();
    uids.dedup();
    match uids.as_slice() {
        [uid] => Some(*uid),
        _ => None,
    }
}

/// IPv4-mapped IPv6 addresses compare equal to their IPv4 form.
fn canonical(addr: SocketAddr) -> SocketAddr {
    match addr.ip() {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), addr.port()),
            None => addr,
        },
        IpAddr::V4(_) => addr,
    }
}

/// `0100007F:1F90` (IPv4) or 32 hex digits `:port` (IPv6). The kernel prints each 32-bit word of
/// the network-order address as a native-endian integer, so `to_ne_bytes` restores the bytes.
fn parse_endpoint(s: &str) -> Option<SocketAddr> {
    let (addr, port) = s.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let word = |hex: &str| u32::from_str_radix(hex, 16).ok().map(u32::to_ne_bytes);
    let ip = match addr.len() {
        8 => IpAddr::V4(Ipv4Addr::from(word(addr)?)),
        32 => {
            let mut bytes = [0u8; 16];
            for (i, chunk) in bytes.chunks_mut(4).enumerate() {
                chunk.copy_from_slice(&word(addr.get(i * 8..i * 8 + 8)?)?);
            }
            IpAddr::V6(Ipv6Addr::from(bytes))
        }
        _ => return None,
    };
    Some(canonical(SocketAddr::new(ip, port)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";

    /// Format an IPv4 endpoint the way the kernel does on this host.
    fn v4(ip: [u8; 4], port: u16) -> String {
        format!("{:08X}:{port:04X}", u32::from_ne_bytes(ip))
    }

    fn v6(ip: Ipv6Addr, port: u16) -> String {
        let o = ip.octets();
        let words: String = o
            .chunks(4)
            .map(|c| format!("{:08X}", u32::from_ne_bytes([c[0], c[1], c[2], c[3]])))
            .collect();
        format!("{words}:{port:04X}")
    }

    fn row(local: &str, remote: &str, st: &str, uid: u32) -> String {
        format!("   0: {local} {remote} {st} 00000000:00000000 00:00000000 00000000  {uid}        0 4242 1 0000000000000000 20 4 30 10 -1")
    }

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn parses_kernel_formatted_endpoints() {
        assert_eq!(
            parse_endpoint(&v4([127, 0, 0, 1], 8765)),
            Some(addr("127.0.0.1:8765"))
        );
        let mapped: Ipv6Addr = "::ffff:127.0.0.1".parse().unwrap();
        assert_eq!(
            parse_endpoint(&v6(mapped, 40000)),
            Some(addr("127.0.0.1:40000")),
            "v4-mapped addresses are canonicalized"
        );
        assert_eq!(
            parse_endpoint(&v6(Ipv6Addr::LOCALHOST, 1)),
            Some(addr("[::1]:1"))
        );
        for bad in [
            "",
            "zz:00",
            "0100007F",
            "0100007F:XYZ",
            "0100:0001",
            "0100007F:10000",
        ] {
            assert_eq!(parse_endpoint(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn finds_the_owner_of_the_client_end_only() {
        let (client, server) = (addr("127.0.0.1:50000"), addr("127.0.0.1:8765"));
        let lo = [127, 0, 0, 1];
        let table = [
            HEADER.to_string(),
            row(&v4(lo, 8765), &v4([0, 0, 0, 0], 0), "0A", 1000), // our listener
            row(&v4(lo, 8765), &v4(lo, 50000), "01", 1000),       // our accepted end
            row(&v4(lo, 50000), &v4(lo, 8765), "01", 1001),       // the client's end
            row(&v4(lo, 50001), &v4(lo, 8765), "01", 1000),       // another client
        ]
        .join("\n");
        assert_eq!(matching_uids(&table, client, server), vec![1001]);
        assert_eq!(
            single_uid(matching_uids(&table, client, server)),
            Some(1001)
        );
        assert!(matching_uids(&table, addr("127.0.0.1:50002"), server).is_empty());
    }

    #[test]
    fn dual_stack_clients_are_found_in_tcp6_and_time_wait_rows_are_ignored() {
        let (client, server) = (addr("127.0.0.1:50000"), addr("127.0.0.1:8765"));
        let mapped = |p| v6("::ffff:127.0.0.1".parse().unwrap(), p);
        let table6 = [
            HEADER.to_string(),
            row(&mapped(50000), &mapped(8765), "01", 1002),
        ]
        .join("\n");
        assert_eq!(matching_uids(&table6, client, server), vec![1002]);
        let tw = [
            HEADER.to_string(),
            row(&mapped(50000), &mapped(8765), TCP_TIME_WAIT, 0),
        ]
        .join("\n");
        assert!(matching_uids(&tw, client, server).is_empty());
    }

    #[test]
    fn ambiguity_and_garbage_fail_closed() {
        assert_eq!(single_uid(vec![]), None);
        assert_eq!(single_uid(vec![5, 5]), Some(5));
        assert_eq!(single_uid(vec![5, 6]), None);
        assert!(
            matching_uids("garbage\n\n   0: x y", addr("1.2.3.4:1"), addr("1.2.3.4:2")).is_empty()
        );
    }

    #[test]
    fn decision_requires_the_daemon_uid() {
        assert_eq!(decide(&Ok(Some(1000)), 1000), Verdict::Allowed);
        assert_eq!(decide(&Ok(Some(1001)), 1000), Verdict::OtherUser(1001));
        assert_eq!(decide(&Ok(Some(0)), 1000), Verdict::OtherUser(0));
        assert_eq!(decide(&Ok(None), 1000), Verdict::NotFound);
        assert_eq!(
            decide(&Err(io::Error::other("x")), 1000),
            Verdict::LookupFailed
        );
    }

    #[test]
    fn the_real_procfs_lookup_finds_our_own_connection() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let server = listener.local_addr().unwrap();
        let client = std::net::TcpStream::connect(server).unwrap();
        let (_accepted, remote) = listener.accept().unwrap();
        assert_eq!(remote, client.local_addr().unwrap());
        let me = nix::unistd::geteuid().as_raw();
        assert_eq!(procfs_lookup()(remote, server).unwrap(), Some(me));
        // A port pair that does not exist is not found.
        let bogus = SocketAddr::new(remote.ip(), remote.port().wrapping_add(1).max(1));
        assert_eq!(procfs_lookup()(bogus, addr("127.0.0.1:1")).unwrap(), None);
    }
}
