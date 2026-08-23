//! Format v1: chunked AEAD framing, footer, metadata, and DEK wrap.
//!
//! See docs/ARCHITECTURE.md "Cryptographic design (format v1)".

mod footer;
mod frame;
mod meta;
mod multipart;
mod wrap;

pub use footer::{Footer, TRAILER_LEN};
pub use frame::{
    ciphertext_len, decrypt_all, encrypt_all, n_chunks, open_frame, plaintext_len, plan_range,
    seal_frame, Alg, Decryptor, Encryptor, RangePlan, TAG_LEN,
};
pub use meta::{
    open_emd5, seal_emd5, Kek, ObjectMeta, KEY_ALG, KEY_CHUNK, KEY_DEK, KEY_EMD5, KEY_KEK, KEY_KID,
    KEY_MP, KEY_VERSION, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE,
};
pub use multipart::{part_layout, plan_multipart_range, PartSpan};
pub use wrap::{path_binding, MasterKey, RsaKek};
