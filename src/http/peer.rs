//! TCP peer-UID verification (REQUIREMENTS.md §11.2/§11.3; M1.1 findings H1/H2).
//!
//! Every accepted loopback connection is attributed to the Linux user that owns the *client*
//! socket: the socket whose local address is the client's address and whose remote address is
//! ours. The connection is served only if that user is the daemon's effective UID, so a sign-in
//! link or session token leaked to another local user is useless to them. The check runs once per
//! connection (HTTP keep-alive requests on it inherit the result) and fails closed.
//!
//! Two lookups find that socket (M4):
//! - **`sock_diag`** (preferred): one exact `SOCK_DIAG_BY_FAMILY` request over a `NETLINK_SOCK_DIAG`
//!   socket for the client's 4-tuple; the kernel answers with that one socket (or `ENOENT`). No
//!   table is scanned. The reply must describe exactly the requested 4-tuple in a state other than
//!   `LISTEN`/`TIME_WAIT`, else "not found". The netlink socket ([`SockDiag`]) is opened **once**,
//!   before the seccomp filter, and reused for every lookup, so the filter needs no exception for
//!   it (v0.1.0 fix pass).
//! - **procfs** (fallback when `sock_diag` is unusable, decided once at startup by
//!   [`select_lookup`]): the matching row of `/proc/net/tcp` (and `/proc/net/tcp6` for
//!   dual-stack clients). No row or several rows with different owners mean "not found".
//!
//! Either way, "not found", an error or another owner all mean "reject".

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::{Arc, Mutex};

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

/// Which lookup the daemon uses (reported in `service.status` as `peer_lookup`).
pub const METHOD_SOCK_DIAG: &str = "sock_diag";
pub const METHOD_PROCFS: &str = "procfs";

/// The production lookup: `sock_diag` if a self-test over a real loopback connection finds this
/// process's own socket, else procfs. Must run before the seccomp filter and the Landlock rules
/// exist (it opens the netlink socket every later lookup reuses, and binds an ephemeral loopback
/// port), i.e. single-threaded at the start of `serve`.
pub fn select_lookup() -> (PeerUidLookup, &'static str) {
    match SockDiag::open().and_then(|diag| diag.self_test().map(|()| diag)) {
        Ok(diag) => (
            Arc::new(move |client, server| diag.query(client, server)),
            METHOD_SOCK_DIAG,
        ),
        Err(_) => (procfs_lookup(), METHOD_PROCFS),
    }
}

// ---- sock_diag (netlink) --------------------------------------------------------------------

const NLMSG_HDR: usize = 16;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 1;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const IPPROTO_TCP: u8 = 6;
const TCP_STATE_TIME_WAIT: u8 = 6;
const TCP_STATE_LISTEN: u8 = 10;
/// `inet_diag_sockid`: sport, dport (big endian), src[16], dst[16], interface, cookie[2].
const SOCKID_LEN: usize = 48;
/// `inet_diag_req_v2`: family, protocol, ext, pad, states, sockid.
const REQ_LEN: usize = 8 + SOCKID_LEN;
/// `inet_diag_msg`: family, state, timer, retrans, sockid, expires, rqueue, wqueue, uid, inode.
const MSG_LEN: usize = 4 + SOCKID_LEN + 20;
const MSG_UID_OFFSET: usize = 4 + SOCKID_LEN + 12;
/// How long one lookup waits for the kernel's reply (it normally arrives during the send).
const REPLY_TIMEOUT_SECS: i64 = 2;
/// Datagrams answering earlier requests that one lookup skips before it gives up.
const MAX_STALE_REPLIES: usize = 8;

/// The one `NETLINK_SOCK_DIAG` socket of the process. The daemon opens it before the seccomp
/// filter ([`crate::sandbox::deny_new_sockets`]) and keeps it: the filter then denies `socket()`
/// for every family, netlink included. Lookups are serialized (one short request/reply exchange
/// with the kernel each) and numbered, so a reply left behind by a lookup that failed between
/// its send and its receive is never taken for the answer to a later one.
pub struct SockDiag {
    /// The socket and the sequence number of the last request.
    state: Mutex<(OwnedFd, u32)>,
}

impl SockDiag {
    pub fn open() -> io::Result<Self> {
        use nix::sys::socket::{self, AddressFamily, SockFlag, SockProtocol, SockType};
        let fd = socket::socket(
            AddressFamily::Netlink,
            SockType::Datagram,
            SockFlag::SOCK_CLOEXEC,
            SockProtocol::NetlinkSockDiag,
        )?;
        socket::setsockopt(
            &fd,
            socket::sockopt::ReceiveTimeout,
            &nix::sys::time::TimeVal::new(REPLY_TIMEOUT_SECS, 0),
        )?;
        Ok(Self {
            state: Mutex::new((fd, 0)),
        })
    }

    /// One exact lookup of the socket whose local end is `client` and remote end is `server`:
    /// its owner, `None` if the kernel has no such socket.
    pub fn query(&self, client: SocketAddr, server: SocketAddr) -> io::Result<Option<u32>> {
        use nix::sys::socket::{self, MsgFlags, NetlinkAddr};
        let (client, server) = (canonical(client), canonical(server));
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("the sock_diag socket's lock is poisoned"))?;
        let (fd, last_seq) = &mut *state;
        let seq = last_seq.wrapping_add(1);
        *last_seq = seq;
        let Some(request) = diag_request(seq, client, server) else {
            return Ok(None);
        };
        socket::sendto(
            fd.as_raw_fd(),
            &request,
            &NetlinkAddr::new(0, 0),
            MsgFlags::empty(),
        )?;
        let mut buf = vec![0u8; 8192];
        for _ in 0..=MAX_STALE_REPLIES {
            let n = socket::recv(fd.as_raw_fd(), &mut buf, MsgFlags::empty())?;
            if let DiagReply::Answer(owner) = parse_diag_reply(&buf[..n], seq, client, server)? {
                return Ok(owner);
            }
        }
        Err(io::Error::other("sock_diag: no reply to this request"))
    }

    /// Look up our own connection to our own listener; `Ok` only if it names our effective UID.
    pub fn self_test(&self) -> io::Result<()> {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let server = listener.local_addr()?;
        let client = std::net::TcpStream::connect(server)?;
        let (_accepted, remote) = listener.accept()?;
        let me = nix::unistd::geteuid().as_raw();
        debug_assert_eq!(remote, client.local_addr()?);
        match self.query(remote, server)? {
            Some(uid) if uid == me => Ok(()),
            other => Err(io::Error::other(format!(
                "sock_diag self-test returned {other:?}"
            ))),
        }
    }
}

/// The address bytes of a `sockid` field (IPv4 in the first 4 bytes).
fn diag_addr(ip: IpAddr) -> [u8; 16] {
    let mut out = [0u8; 16];
    match ip {
        IpAddr::V4(v4) => out[..4].copy_from_slice(&v4.octets()),
        IpAddr::V6(v6) => out.copy_from_slice(&v6.octets()),
    }
    out
}

fn family(addr: SocketAddr) -> u8 {
    let f = match addr {
        SocketAddr::V4(_) => nix::libc::AF_INET,
        SocketAddr::V6(_) => nix::libc::AF_INET6,
    };
    u8::try_from(f).unwrap_or(0)
}

fn sockid(local: SocketAddr, remote: SocketAddr) -> [u8; SOCKID_LEN] {
    let mut id = [0u8; SOCKID_LEN];
    id[0..2].copy_from_slice(&local.port().to_be_bytes());
    id[2..4].copy_from_slice(&remote.port().to_be_bytes());
    id[4..20].copy_from_slice(&diag_addr(local.ip()));
    id[20..36].copy_from_slice(&diag_addr(remote.ip()));
    // interface 0 (any); cookie INET_DIAG_NOCOOKIE
    id[40..48].copy_from_slice(&[0xff; 8]);
    id
}

/// The netlink request number `seq` for the socket `client -> server` (`None` if the families
/// differ, which no loopback connection to our IPv4 listener can produce).
pub fn diag_request(seq: u32, client: SocketAddr, server: SocketAddr) -> Option<Vec<u8>> {
    if family(client) != family(server) {
        return None;
    }
    let len = u32::try_from(NLMSG_HDR + REQ_LEN).ok()?;
    let mut m = Vec::with_capacity(NLMSG_HDR + REQ_LEN);
    m.extend_from_slice(&len.to_ne_bytes());
    m.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    m.extend_from_slice(&NLM_F_REQUEST.to_ne_bytes());
    m.extend_from_slice(&seq.to_ne_bytes());
    m.extend_from_slice(&0u32.to_ne_bytes()); // port id: the kernel fills it in
    m.extend_from_slice(&[family(client), IPPROTO_TCP, 0, 0]);
    m.extend_from_slice(&u32::MAX.to_ne_bytes()); // every state; checked in the reply
    m.extend_from_slice(&sockid(client, server));
    Some(m)
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn malformed() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "malformed sock_diag reply")
}

/// What one datagram read from the `sock_diag` socket says about request `seq`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagReply {
    /// The kernel's answer: the owner of the socket, or `None` (no such socket, not exactly the
    /// socket asked for, or several owners).
    Answer(Option<u32>),
    /// Nothing in it belongs to this request (the reply to an earlier one): read the next.
    Stale,
}

/// The owner of the socket in a `sock_diag` reply to request `seq`, if it describes exactly
/// `client -> server` in an established-like state; `ENOENT` means not found; other errors are
/// errors. Messages of other requests are ignored.
pub fn parse_diag_reply(
    buf: &[u8],
    seq: u32,
    client: SocketAddr,
    server: SocketAddr,
) -> io::Result<DiagReply> {
    let want = sockid(client, server);
    let mut found: Vec<u32> = Vec::new();
    let mut answered = false;
    let mut at = 0;
    while at + NLMSG_HDR <= buf.len() {
        let len = u32_at(buf, at).ok_or_else(malformed)? as usize;
        let kind = u16_at(buf, at + 4).ok_or_else(malformed)?;
        let msg_seq = u32_at(buf, at + 8).ok_or_else(malformed)?;
        if len < NLMSG_HDR || at + len > buf.len() {
            return Err(malformed());
        }
        let body = &buf[at + NLMSG_HDR..at + len];
        match kind {
            _ if msg_seq != seq => {}
            NLMSG_ERROR => {
                answered = true;
                let code = u32_at(body, 0).ok_or_else(malformed)? as i32;
                match -code {
                    0 => {}
                    e if e == nix::libc::ENOENT => return Ok(DiagReply::Answer(None)),
                    e => return Err(io::Error::from_raw_os_error(e)),
                }
            }
            NLMSG_DONE => break,
            SOCK_DIAG_BY_FAMILY => {
                answered = true;
                if body.len() < MSG_LEN {
                    return Err(malformed());
                }
                let state = body[1];
                // The kernel echoes the cookie it found, so compare addresses and ports only.
                let same = body[0] == family(client) && body[4..4 + 40] == want[..40];
                if same && state != TCP_STATE_LISTEN && state != TCP_STATE_TIME_WAIT {
                    found.push(u32_at(body, MSG_UID_OFFSET).ok_or_else(malformed)?);
                }
            }
            _ => {}
        }
        // Messages are aligned to 4 bytes.
        at += (len + 3) & !3;
    }
    Ok(if answered {
        DiagReply::Answer(single_uid(found))
    } else {
        DiagReply::Stale
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

    /// A reply message the way the kernel builds it for `local -> remote`.
    fn diag_msg(local: SocketAddr, remote: SocketAddr, state: u8, uid: u32, seq: u32) -> Vec<u8> {
        let mut body = vec![family(local), state, 0, 0];
        let mut id = sockid(local, remote);
        id[40..48].copy_from_slice(&[7; 8]); // a real cookie, not NOCOOKIE
        body.extend_from_slice(&id);
        body.extend_from_slice(&[0u8; 12]); // expires, rqueue, wqueue
        body.extend_from_slice(&uid.to_ne_bytes());
        body.extend_from_slice(&4242u32.to_ne_bytes()); // inode
        nl(SOCK_DIAG_BY_FAMILY, seq, &body)
    }

    fn nl(kind: u16, seq: u32, body: &[u8]) -> Vec<u8> {
        let len = u32::try_from(NLMSG_HDR + body.len()).unwrap();
        let mut m = len.to_ne_bytes().to_vec();
        m.extend_from_slice(&kind.to_ne_bytes());
        m.extend_from_slice(&0u16.to_ne_bytes());
        m.extend_from_slice(&seq.to_ne_bytes());
        m.extend_from_slice(&0u32.to_ne_bytes());
        m.extend_from_slice(body);
        while m.len() % 4 != 0 {
            m.push(0);
        }
        m
    }

    /// The sequence number of the request the hand-built replies below answer.
    const SEQ: u32 = 7;

    fn nl_error(errno: i32, seq: u32) -> Vec<u8> {
        let mut body = (-errno).to_ne_bytes().to_vec();
        body.extend_from_slice(&[0u8; 16]); // the echoed request header
        nl(NLMSG_ERROR, seq, &body)
    }

    #[test]
    fn the_diag_request_describes_the_client_end_of_the_connection() {
        let (client, server) = (addr("127.0.0.1:50000"), addr("127.0.0.1:8765"));
        let r = diag_request(SEQ, client, server).unwrap();
        assert_eq!(r.len(), 72);
        assert_eq!(
            u32_at(&r, 8),
            Some(SEQ),
            "numbered, so replies can be matched"
        );
        assert_eq!(u32_at(&r, 0), Some(72));
        assert_eq!(u16_at(&r, 4), Some(SOCK_DIAG_BY_FAMILY));
        assert_eq!(
            u16_at(&r, 6),
            Some(NLM_F_REQUEST),
            "an exact lookup, not a dump"
        );
        assert_eq!(r[16], family(client));
        assert_eq!(r[17], IPPROTO_TCP);
        let id = &r[24..];
        assert_eq!(&id[0..2], &50000u16.to_be_bytes(), "source = the client");
        assert_eq!(&id[2..4], &8765u16.to_be_bytes(), "destination = us");
        assert_eq!(&id[4..8], &[127, 0, 0, 1]);
        assert_eq!(&id[20..24], &[127, 0, 0, 1]);
        assert_eq!(&id[40..48], &[0xff; 8], "no cookie");
        let mapped = addr("[::ffff:127.0.0.1]:50000");
        assert_eq!(
            diag_request(SEQ, canonical(mapped), server),
            Some(r),
            "v4-mapped clients are looked up as IPv4"
        );
        assert_eq!(diag_request(SEQ, addr("[::1]:1"), server), None);
    }

    #[test]
    fn the_diag_reply_must_name_exactly_the_requested_socket() {
        let (client, server) = (addr("127.0.0.1:50000"), addr("127.0.0.1:8765"));
        let parse = |reply: &[u8]| parse_diag_reply(reply, SEQ, client, server);
        let ok = diag_msg(client, server, 1, 1001, SEQ);
        assert_eq!(parse(&ok).unwrap(), DiagReply::Answer(Some(1001)));
        let done = nl(NLMSG_DONE, SEQ, &[0; 4]);
        assert_eq!(
            parse(&[ok.clone(), done].concat()).unwrap(),
            DiagReply::Answer(Some(1001))
        );
        for (what, reply) in [
            (
                "our own accepted end",
                diag_msg(server, client, 1, 1000, SEQ),
            ),
            (
                "another port",
                diag_msg(addr("127.0.0.1:50001"), server, 1, 1000, SEQ),
            ),
            (
                "TIME_WAIT",
                diag_msg(client, server, TCP_STATE_TIME_WAIT, 0, SEQ),
            ),
            (
                "LISTEN",
                diag_msg(client, server, TCP_STATE_LISTEN, 1000, SEQ),
            ),
            ("not found", nl_error(nix::libc::ENOENT, SEQ)),
        ] {
            assert_eq!(parse(&reply).unwrap(), DiagReply::Answer(None), "{what}");
        }
        let two = [ok.clone(), diag_msg(client, server, 1, 1002, SEQ)].concat();
        assert_eq!(parse(&two).unwrap(), DiagReply::Answer(None), "ambiguous");
        let same_twice = [ok.clone(), ok.clone()].concat();
        assert_eq!(parse(&same_twice).unwrap(), DiagReply::Answer(Some(1001)));
        assert_eq!(
            parse(&nl_error(nix::libc::ENOMEM, SEQ))
                .unwrap_err()
                .raw_os_error(),
            Some(nix::libc::ENOMEM)
        );
        for broken in [ok[..20].to_vec(), ok[..ok.len() - 8].to_vec(), {
            let mut b = ok.clone();
            b[0..4].copy_from_slice(&8u32.to_ne_bytes());
            b
        }] {
            assert!(parse(&broken).is_err());
        }
    }

    /// The socket is reused: what an earlier request left behind is never this request's answer,
    /// whatever it says (v0.1.0 fix pass).
    #[test]
    fn replies_to_other_requests_are_stale_never_an_answer() {
        let (client, server) = (addr("127.0.0.1:50000"), addr("127.0.0.1:8765"));
        let parse = |reply: &[u8]| parse_diag_reply(reply, SEQ, client, server);
        for (what, reply) in [
            (
                "an owner for another request",
                diag_msg(client, server, 1, 1000, SEQ - 1),
            ),
            (
                "'not found' for another request",
                nl_error(nix::libc::ENOENT, SEQ - 1),
            ),
            (
                "an error for another request",
                nl_error(nix::libc::ENOMEM, SEQ + 1),
            ),
            ("nothing", Vec::new()),
        ] {
            assert_eq!(parse(&reply).unwrap(), DiagReply::Stale, "{what}");
        }
        // Mixed into one datagram, only this request's message counts.
        let mixed = [
            diag_msg(client, server, 1, 1000, SEQ - 1),
            diag_msg(client, server, 1, 1001, SEQ),
        ]
        .concat();
        assert_eq!(parse(&mixed).unwrap(), DiagReply::Answer(Some(1001)));
    }

    #[test]
    fn sock_diag_finds_our_own_connection_like_procfs_and_nothing_else() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let server = listener.local_addr().unwrap();
        let client = std::net::TcpStream::connect(server).unwrap();
        let (_accepted, remote) = listener.accept().unwrap();
        assert_eq!(remote, client.local_addr().unwrap());
        let me = nix::unistd::geteuid().as_raw();
        // One socket for every lookup, as in the daemon.
        let diag = SockDiag::open().unwrap();
        assert_eq!(diag.query(remote, server).unwrap(), Some(me));
        assert_eq!(
            diag.query(remote, server).unwrap(),
            procfs_lookup()(remote, server).unwrap()
        );
        // The server's own end is not the client's.
        assert_eq!(diag.query(server, remote).unwrap(), Some(me));
        let bogus = SocketAddr::new(remote.ip(), remote.port().wrapping_add(1).max(1));
        assert_eq!(diag.query(bogus, server).unwrap(), None);
        // "Not found" leaves nothing behind that the next lookup could mistake for its answer.
        assert_eq!(diag.query(remote, server).unwrap(), Some(me));
        // A closed connection is gone (or in TIME_WAIT): never attributed.
        drop(client);
        drop(_accepted);
        assert_ne!(diag.query(remote, server).unwrap(), Some(me));
        diag.self_test().unwrap();
        assert_eq!(select_lookup().1, METHOD_SOCK_DIAG);
    }

    #[test]
    fn concurrent_lookups_share_the_socket_and_each_gets_its_own_answer() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let server = listener.local_addr().unwrap();
        let client = std::net::TcpStream::connect(server).unwrap();
        let (_accepted, remote) = listener.accept().unwrap();
        let me = nix::unistd::geteuid().as_raw();
        let bogus = SocketAddr::new(remote.ip(), remote.port().wrapping_add(1).max(1));
        let diag = Arc::new(SockDiag::open().unwrap());
        let threads: Vec<_> = (0..8)
            .map(|i| {
                let diag = Arc::clone(&diag);
                std::thread::spawn(move || {
                    for _ in 0..200 {
                        if i % 2 == 0 {
                            assert_eq!(diag.query(remote, server).unwrap(), Some(me));
                        } else {
                            assert_eq!(diag.query(bogus, server).unwrap(), None);
                        }
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        drop(client);
    }
}
