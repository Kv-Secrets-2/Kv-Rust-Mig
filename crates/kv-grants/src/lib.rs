//! Run grants and capability tokens (`kv/grants.py`, `kv/capabilities.py`):
//! the owner-signed records that let one exact run receive secrets or a
//! brokered capability, and the short-lived tokens minted at admission.

pub mod ledger;
pub mod normalize;
pub mod store;
