//! FUSE / cloud-sync mount detection from `/proc/self/mountinfo` (std only).

use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    pub mount_point: PathBuf,
    pub fs_type: String,
}

/// Decode the octal escapes (`\040` space, `\011` tab, `\012` newline, `\134` backslash) used in mountinfo.
fn unescape(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 3 < bytes.len()
            && bytes[i + 1..=i + 3]
                .iter()
                .all(|b| (b'0'..=b'7').contains(b))
        {
            let v = (u32::from(bytes[i + 1] - b'0') << 6)
                | (u32::from(bytes[i + 2] - b'0') << 3)
                | u32::from(bytes[i + 3] - b'0');
            out.push(u8::try_from(v & 0xff).unwrap_or(b'?'));
            i += 4;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn parse_mountinfo(text: &str) -> Vec<Mount> {
    text.lines()
        .filter_map(|line| {
            let (before, after) = line.split_once(" - ")?;
            let mount_point = unescape(before.split(' ').nth(4)?);
            let fs_type = after.split(' ').next()?.to_string();
            Some(Mount {
                mount_point: PathBuf::from(mount_point),
                fs_type,
            })
        })
        .collect()
}

pub fn fuse_mount_points(mounts: &[Mount]) -> Vec<PathBuf> {
    mounts
        .iter()
        .filter(|m| m.fs_type == "fuse" || m.fs_type.starts_with("fuse."))
        .map(|m| m.mount_point.clone())
        .collect()
}

/// FUSE mount points of the running system; empty if `/proc/self/mountinfo` is unreadable.
pub fn current_fuse_mount_points() -> Vec<PathBuf> {
    std::fs::read_to_string("/proc/self/mountinfo")
        .map(|t| fuse_mount_points(&parse_mountinfo(&t)))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
22 28 0:21 / /sys rw,nosuid shared:7 - sysfs sysfs rw
36 35 98:0 /mnt1 /mnt/with\\040space rw,noatime master:1 - ext3 /dev/root rw,errors=continue
50 28 0:45 / /home/u/gdrive rw,nosuid,nodev,relatime shared:99 - fuse.google-drive-ocamlfuse gdrive rw,user_id=1000
51 28 0:46 / /home/u/crypt rw - fuse encfs rw
52 28 0:47 / /home/u/odd\\134name rw - fuse.sshfs u@h:/ rw
garbage line without separator
";

    #[test]
    fn parses_mount_points_and_types() {
        let m = parse_mountinfo(SAMPLE);
        assert_eq!(m.len(), 5);
        assert_eq!(
            m[0],
            Mount {
                mount_point: "/sys".into(),
                fs_type: "sysfs".into()
            }
        );
        assert_eq!(m[1].mount_point, PathBuf::from("/mnt/with space"));
    }

    #[test]
    fn selects_only_fuse_mounts() {
        let pts = fuse_mount_points(&parse_mountinfo(SAMPLE));
        assert_eq!(
            pts,
            vec![
                PathBuf::from("/home/u/gdrive"),
                PathBuf::from("/home/u/crypt"),
                PathBuf::from("/home/u/odd\\name")
            ]
        );
    }

    #[test]
    fn unescape_handles_edge_cases() {
        assert_eq!(unescape("a\\040b"), "a b");
        assert_eq!(unescape("trailing\\"), "trailing\\");
        assert_eq!(unescape("\\04"), "\\04");
        assert_eq!(unescape("\\999"), "\\999");
    }

    #[test]
    fn real_mountinfo_parses_without_panicking() {
        let _ = current_fuse_mount_points();
    }
}
