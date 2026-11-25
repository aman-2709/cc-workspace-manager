//! Project discovery: session cwds resolved to project roots ([`resolve`], the primary source
//! since M3) and the `CLAUDE.md` marker walk ([`walk`]).

pub mod dirfd;
pub mod exclusions;
pub mod mounts;
pub mod resolve;
pub mod status;
pub mod walk;
