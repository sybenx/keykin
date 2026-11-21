//! Being a Keykin device from Rust (Keykin SPEC 8d): the device core lifted from Marble on Mac, and what the
//! `keykin` command needs around it: a chip to seal the piece (`chip`), the file it lives in (`store`), the
//! sign-in through the account page (`signin`) and events in words for the Touch ID prompt (`kinds`).

pub mod chip;
pub mod core;
pub mod kinds;
pub mod signin;
pub mod store;
