//! Abstraction on the AES-CBC mode

use cipher::{
    block::{BlockModeDecBackend, BlockModeDecrypt, BlockModeEncBackend, BlockModeEncrypt},
    Block, BlockModeDecClosure, BlockModeEncClosure, InOut, InOutBuf, ParBlocks, ParBlocksSizeUser,
};
use common::{
    typenum::Unsigned,
    typenum::{U125, U16},
    BlockSizeUser, InnerIvInit, InnerUser, Iv, IvSizeUser,
};
use zeroize::Zeroizing;

use crate::symmetric;

type BlockSize = U16;

/// Limit of the number of bytes that can be processed by YubiHSM.
/// No limit is documented, but the [reference implementation] limits it to
/// 2010 bytes (iv_len = 16 bytes)
///
/// [reference implementation]: <https://github.com/Yubico/yubihsm-shell/blob/e95bfbfa8c58fb1695265a11a2021e70662a8b5d/lib/yubihsm.c#L4601>
type ParBlocksSize = U125;

macro_rules! impl_mode {
    (
        $(#[$attr:meta])*
        $v:vis struct $name:ident ($backend:ident)
    ) => {
        $(#[$attr])*
        $v struct $name {
            /// Inner key
            hsm_key: symmetric::HsmKey,

            iv: Iv<Self>,
        }

        impl IvSizeUser for $name {
            type IvSize = U16;
        }

        impl InnerUser for $name {
            type Inner = symmetric::HsmKey;
        }

        impl InnerIvInit for $name {
            fn inner_iv_init(hsm_key: Self::Inner, iv: &Iv<Self>) -> Self {
                // TODO: Should we issue a dummy CBC encryption/decryption to check permissions?
                Self {
                    hsm_key,
                    iv: iv.clone(),
                }
            }
        }

        impl BlockSizeUser for $name {
            type BlockSize = U16;
        }

        struct $backend<'i> {
            inner: &'i mut $name,
        }

        impl BlockSizeUser for $backend<'_> {
            type BlockSize = BlockSize;
        }

        impl ParBlocksSizeUser for $backend<'_> {
            type ParBlocksSize = ParBlocksSize;
        }
    };
}

impl_mode!(
    /// Encryptor for CBC on the YubiHSM
    pub struct Encryptor(EncryptorBackend)
);
impl_mode!(
    /// Decryptor for CBC on the YubiHSM
    pub struct Decryptor(DecryptorBackend)
);

impl BlockModeEncrypt for Encryptor {
    fn encrypt_with_backend(&mut self, f: impl BlockModeEncClosure<BlockSize = Self::BlockSize>) {
        f.call(&mut EncryptorBackend { inner: self });
    }
}

impl BlockModeDecrypt for Decryptor {
    fn decrypt_with_backend(&mut self, f: impl BlockModeDecClosure<BlockSize = Self::BlockSize>) {
        f.call(&mut DecryptorBackend { inner: self });
    }
}

impl BlockModeEncBackend for EncryptorBackend<'_> {
    /// Encrypt a single block with the HSM.
    fn encrypt_block(&mut self, mut block: InOut<'_, '_, Block<Self>>) {
        let input = block.get_in();
        let mut payload = Zeroizing::new(Vec::with_capacity(self.inner.iv.len() + input.len()));

        payload.extend_from_slice(&self.inner.iv);
        payload.extend_from_slice(input);

        let resp = self
            .inner
            .hsm_key
            .client
            .send_command(symmetric::commands::EncryptAesCbc {
                key_id: self.inner.hsm_key.cipher_key_id,
                payload: payload,
            })
            .expect("HSM failed to encrypt");

        block.get_out().copy_from_slice(&resp.0);
        self.inner.iv.copy_from_slice(&resp.0);
    }

    fn encrypt_par_blocks(&mut self, mut blocks: InOut<'_, '_, ParBlocks<Self>>) {
        const PAYLOAD_LEN: usize = ParBlocksSize::USIZE * BlockSize::USIZE;

        let mut payload = Zeroizing::new(Vec::with_capacity(self.inner.iv.len() + PAYLOAD_LEN));
        let n = blocks.get_in().len();

        payload.extend_from_slice(&self.inner.iv);
        for block in blocks.get_in() {
            payload.extend_from_slice(&block);
        }

        let resp = self
            .inner
            .hsm_key
            .client
            .send_command(symmetric::commands::EncryptAesCbc {
                key_id: self.inner.hsm_key.cipher_key_id,
                payload: payload,
            })
            .expect("HSM failed to encrypt");

        assert_eq!(
            resp.0.len(),
            PAYLOAD_LEN,
            "Encrypted payload length isn't the expected size"
        );

        blocks.get_out().as_flattened_mut().copy_from_slice(&resp.0);
        self.inner.iv.copy_from_slice(&blocks.get_out()[n - 1])
    }

    fn encrypt_tail_blocks(&mut self, mut blocks: InOutBuf<'_, '_, Block<Self>>) {
        if blocks.is_empty() {
            // Nothing to encrypt
            return;
        }

        let mut payload = Zeroizing::new(Vec::with_capacity(self.inner.iv.len() + blocks.len()));

        payload.extend_from_slice(&self.inner.iv);
        for block in blocks.get_in() {
            payload.extend_from_slice(&block);
        }

        let resp = self
            .inner
            .hsm_key
            .client
            .send_command(symmetric::commands::EncryptAesCbc {
                key_id: self.inner.hsm_key.cipher_key_id,
                payload: payload,
            })
            .expect("HSM failed to encrypt");

        assert_eq!(
            resp.0.len(),
            (blocks.len() * BlockSize::USIZE),
            "Encrypted payload length isn't the expected size"
        );

        let (chunks, tail) = resp.0.as_chunks::<{ BlockSize::USIZE }>();
        assert!(
            tail.is_empty(),
            "invariant violation: the response is expected to be same as the input"
        );

        for (chunk, block) in chunks.into_iter().zip(blocks.get_out()) {
            block.copy_from_slice(chunk);
        }

        let last_block = blocks.len();
        self.inner
            .iv
            .copy_from_slice(&blocks.get_out()[last_block - 1]);
    }
}

impl BlockModeDecBackend for DecryptorBackend<'_> {
    /// Decrypt a single block with the HSM.
    fn decrypt_block(&mut self, mut block: InOut<'_, '_, Block<Self>>) {
        let input = block.get_in();
        let mut payload = Zeroizing::new(Vec::with_capacity(self.inner.iv.len() + input.len()));

        payload.extend_from_slice(&self.inner.iv);
        payload.extend_from_slice(input);
        let next_iv = Iv::<Decryptor>::from(*block.get_in());

        let resp = self
            .inner
            .hsm_key
            .client
            .send_command(symmetric::commands::DecryptAesCbc {
                key_id: self.inner.hsm_key.cipher_key_id,
                payload: payload,
            })
            .expect("HSM failed to encrypt");

        block.get_out().copy_from_slice(&resp.0);
        self.inner.iv = next_iv;
    }

    fn decrypt_par_blocks(&mut self, mut blocks: InOut<'_, '_, ParBlocks<Self>>) {
        const PAYLOAD_LEN: usize = ParBlocksSize::USIZE * BlockSize::USIZE;

        let mut payload = Zeroizing::new(Vec::with_capacity(self.inner.iv.len() + PAYLOAD_LEN));
        let n = blocks.get_in().len();

        payload.extend_from_slice(&self.inner.iv);
        for block in blocks.get_in() {
            payload.extend_from_slice(&block);
        }

        let next_iv = Iv::<Decryptor>::from(blocks.get_in()[n - 1]);

        let resp = self
            .inner
            .hsm_key
            .client
            .send_command(symmetric::commands::DecryptAesCbc {
                key_id: self.inner.hsm_key.cipher_key_id,
                payload: payload,
            })
            .expect("HSM failed to encrypt");

        assert_eq!(
            resp.0.len(),
            PAYLOAD_LEN,
            "Encrypted payload length isn't the expected size"
        );

        blocks.get_out().as_flattened_mut().copy_from_slice(&resp.0);
        self.inner.iv = next_iv;
    }

    fn decrypt_tail_blocks(&mut self, mut blocks: InOutBuf<'_, '_, Block<Self>>) {
        if blocks.is_empty() {
            // Nothing to decrypt
            return;
        }

        let mut payload = Zeroizing::new(Vec::with_capacity(self.inner.iv.len() + blocks.len()));

        payload.extend_from_slice(&self.inner.iv);
        for block in blocks.get_in() {
            payload.extend_from_slice(&block);
        }

        let n = blocks.len();
        let next_iv = Iv::<Decryptor>::from(blocks.get_in()[n - 1]);

        let resp = self
            .inner
            .hsm_key
            .client
            .send_command(symmetric::commands::DecryptAesCbc {
                key_id: self.inner.hsm_key.cipher_key_id,
                payload: payload,
            })
            .expect("HSM failed to encrypt");

        assert_eq!(
            resp.0.len(),
            (blocks.len() * BlockSize::USIZE),
            "Encrypted payload length isn't the expected size"
        );

        let (chunks, tail) = resp.0.as_chunks::<{ BlockSize::USIZE }>();
        assert!(
            tail.is_empty(),
            "invariant violation: the response is expected to be same as the input"
        );

        for (chunk, block) in chunks.into_iter().zip(blocks.get_out()) {
            block.copy_from_slice(chunk);
        }

        self.inner.iv = next_iv;
    }
}
