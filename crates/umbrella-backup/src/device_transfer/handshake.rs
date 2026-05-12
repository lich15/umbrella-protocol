//! Noise_IK handshake обёртка вокруг crate `snow` для Secret device-transfer.
//! Noise_IK handshake wrapper around the `snow` crate for Secret device-transfer.
//!
//! Ciphersuite: `Noise_IK_25519_ChaChaPoly_SHA512`. Обоснование выбора — в
//! ADR-007 §4 (Noise_IK vs KK vs XX) и §5 (snow vs ручная реализация).
//!
//! Протокол IK:
//!
//! ```text
//! -> e, es, s, ss
//! <- e, ee, se
//! ```
//!
//! Initiator (новое устройство) заранее знает responder's static public key
//! (из QR-кода). Responder (старое устройство) узнаёт initiator's static во
//! время handshake и обязан верифицировать что он в KT под тем же аккаунтом
//! (см. [`crate::device_transfer::identity_verify`]).
//!
//! Ciphersuite: `Noise_IK_25519_ChaChaPoly_SHA512`. Initiator (new device)
//! pre-knows responder's static public key (from the QR). Responder (old
//! device) learns initiator's static during handshake and must verify it in
//! KT under the same account.

use snow::{Builder, HandshakeState, TransportState};

use crate::error::BackupError;

use super::qr::{DevicePairingQr, PAIRING_CHALLENGE_LEN, PUBKEY_LEN};

/// Спецификация Noise-pattern для device-transfer.
/// Noise pattern specification used for device-transfer.
pub const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_SHA512";

/// Domain separator mix-in в Noise handshake hash (prologue).
/// Domain separator mixed into Noise handshake hash (prologue).
pub const HANDSHAKE_PROLOGUE_DOMAIN: &[u8] = b"umbrellax-device-transfer-handshake-v1";

/// Wire version mixed into prologue после domain separator.
/// Wire version byte mixed into prologue after the domain separator.
pub const HANDSHAKE_WIRE_VERSION: u8 = 0x01;

/// Длина handshake hash (SHA-512 усечённый snow'ом до 32/64 в зависимости от hash).
/// Handshake hash length (returned by `snow::TransportState::get_handshake_hash`).
///
/// Для SHA-512 ciphersuite snow возвращает 64 байта. Мы используем все 64
/// для максимальной binding strength при post-handshake identity-подписи.
///
/// For SHA-512 ciphersuite, snow returns 64 bytes. We use all 64 for maximum
/// binding strength in post-handshake identity signatures.
pub const HANDSHAKE_HASH_LEN: usize = 64;

/// Максимум байт одного noise handshake message. 65535 — верхний лимит по Noise spec.
pub const MAX_HANDSHAKE_MSG_LEN: usize = 65535;

/// Построить prologue для handshake: domain_separator || wire_version || pairing_challenge.
fn build_prologue(pairing_challenge: &[u8; PAIRING_CHALLENGE_LEN]) -> Vec<u8> {
    let mut p = Vec::with_capacity(HANDSHAKE_PROLOGUE_DOMAIN.len() + 1 + PAIRING_CHALLENGE_LEN);
    p.extend_from_slice(HANDSHAKE_PROLOGUE_DOMAIN);
    p.push(HANDSHAKE_WIRE_VERSION);
    p.extend_from_slice(pairing_challenge);
    p
}

/// Initiator handshake state. New device, который сканирует QR.
/// Initiator handshake state. New device scanning the QR.
pub struct PairingInitiator {
    state: HandshakeState,
}

impl PairingInitiator {
    /// Создать initiator из QR и собственного X25519 static ключа.
    /// Create initiator from QR and own X25519 static key.
    ///
    /// `local_static_private` — 32-байтовый X25519 secret (не clamped;
    /// snow применит clamp внутри). Обычно получается через
    /// `x25519_dalek::StaticSecret::random_from_rng()` + `.to_bytes()`.
    ///
    /// # Errors
    /// - [`BackupError::HandshakeFailed`] если snow не смог собрать state
    ///   (невалидные параметры, bad key length).
    pub fn new(
        qr: &DevicePairingQr,
        local_static_private: &[u8; PUBKEY_LEN],
    ) -> Result<Self, BackupError> {
        let prologue = build_prologue(&qr.pairing_challenge);
        let params = NOISE_PATTERN
            .parse()
            .map_err(|_| BackupError::HandshakeFailed("noise params parse"))?;
        let state = Builder::new(params)
            .prologue(&prologue)
            .map_err(|_| BackupError::HandshakeFailed("initiator prologue"))?
            .local_private_key(local_static_private)
            .map_err(|_| BackupError::HandshakeFailed("initiator local key"))?
            .remote_public_key(&qr.responder_ephemeral_static)
            .map_err(|_| BackupError::HandshakeFailed("initiator remote key"))?
            .build_initiator()
            .map_err(|_| BackupError::HandshakeFailed("initiator build"))?;
        Ok(Self { state })
    }

    /// Сгенерировать первое handshake message (`-> e, es, s, ss`).
    /// Write first handshake message (`-> e, es, s, ss`).
    ///
    /// # Errors
    /// - [`BackupError::HandshakeFailed`] если snow'овый write не прошёл.
    pub fn write_message_1(&mut self) -> Result<Vec<u8>, BackupError> {
        let mut buf = vec![0u8; MAX_HANDSHAKE_MSG_LEN];
        let n = self
            .state
            .write_message(&[], &mut buf)
            .map_err(|_| BackupError::HandshakeFailed("initiator msg 1 write"))?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Применить ответное message 2 (`<- e, ee, se`). Завершает handshake.
    /// Consume message 2 (`<- e, ee, se`). Completes handshake.
    ///
    /// # Errors
    /// - [`BackupError::HandshakeFailed`] если snow read или transition failed.
    pub fn read_message_2_and_finalize(
        mut self,
        msg2: &[u8],
    ) -> Result<TransferHandshakeResult, BackupError> {
        let mut payload = vec![0u8; MAX_HANDSHAKE_MSG_LEN];
        self.state
            .read_message(msg2, &mut payload)
            .map_err(|_| BackupError::HandshakeFailed("initiator msg 2 read"))?;
        let handshake_hash = extract_handshake_hash_from_state(&self.state);
        let transport = self
            .state
            .into_transport_mode()
            .map_err(|_| BackupError::HandshakeFailed("initiator transport"))?;
        Ok(TransferHandshakeResult {
            transport,
            handshake_hash,
        })
    }
}

/// Responder handshake state. Старое устройство, показавшее QR.
/// Responder handshake state. Old device that displayed the QR.
pub struct PairingResponder {
    state: HandshakeState,
}

impl PairingResponder {
    /// Создать responder из эфемерного static private ключа (отвечает public
    /// ключу в QR) и pairing_challenge (то же значение что в QR).
    ///
    /// Create responder from the ephemeral static private key (which
    /// corresponds to the public key in the QR) and pairing_challenge (same
    /// as in the QR).
    ///
    /// # Errors
    /// - [`BackupError::HandshakeFailed`] если snow не смог собрать state.
    pub fn new(
        local_ephemeral_static_private: &[u8; PUBKEY_LEN],
        pairing_challenge: &[u8; PAIRING_CHALLENGE_LEN],
    ) -> Result<Self, BackupError> {
        let prologue = build_prologue(pairing_challenge);
        let params = NOISE_PATTERN
            .parse()
            .map_err(|_| BackupError::HandshakeFailed("noise params parse"))?;
        let state = Builder::new(params)
            .prologue(&prologue)
            .map_err(|_| BackupError::HandshakeFailed("responder prologue"))?
            .local_private_key(local_ephemeral_static_private)
            .map_err(|_| BackupError::HandshakeFailed("responder local key"))?
            .build_responder()
            .map_err(|_| BackupError::HandshakeFailed("responder build"))?;
        Ok(Self { state })
    }

    /// Принять initiator's первое message, сохранить state.
    /// Consume the initiator's first message, mutate state.
    ///
    /// # Errors
    /// - [`BackupError::HandshakeFailed`] если snow read не прошёл.
    pub fn read_message_1(&mut self, msg1: &[u8]) -> Result<(), BackupError> {
        let mut payload = vec![0u8; MAX_HANDSHAKE_MSG_LEN];
        self.state
            .read_message(msg1, &mut payload)
            .map_err(|_| BackupError::HandshakeFailed("responder msg 1 read"))?;
        Ok(())
    }

    /// Сгенерировать второе handshake message (`<- e, ee, se`). Завершает handshake.
    /// Write the second handshake message (`<- e, ee, se`). Completes handshake.
    ///
    /// # Errors
    /// - [`BackupError::HandshakeFailed`] если snow write или transition failed.
    pub fn write_message_2_and_finalize(
        mut self,
    ) -> Result<(Vec<u8>, TransferHandshakeResult), BackupError> {
        let mut buf = vec![0u8; MAX_HANDSHAKE_MSG_LEN];
        let n = self
            .state
            .write_message(&[], &mut buf)
            .map_err(|_| BackupError::HandshakeFailed("responder msg 2 write"))?;
        buf.truncate(n);
        let handshake_hash = extract_handshake_hash_from_state(&self.state);
        let transport = self
            .state
            .into_transport_mode()
            .map_err(|_| BackupError::HandshakeFailed("responder transport"))?;
        Ok((
            buf,
            TransferHandshakeResult {
                transport,
                handshake_hash,
            },
        ))
    }

    /// Возвращает initiator'с static public key (доступен после `read_message_1`).
    /// Returns the initiator's static public key (available after `read_message_1`).
    ///
    /// Используется responder'ом чтобы verify'ить identity через KT lookup.
    #[must_use]
    pub fn remote_static(&self) -> Option<Vec<u8>> {
        self.state.get_remote_static().map(|s| s.to_vec())
    }
}

/// Результат завершения handshake: transport state + handshake hash.
/// Handshake completion result: transport state + handshake hash.
pub struct TransferHandshakeResult {
    /// Noise transport state для чтения/записи зашифрованных frame'ов.
    /// Noise transport state for reading/writing encrypted frames.
    pub transport: TransportState,
    /// Handshake hash (64 байт), binding для post-handshake identity-подписи.
    /// Handshake hash (64 bytes), binds post-handshake identity signature.
    pub handshake_hash: [u8; HANDSHAKE_HASH_LEN],
}

fn extract_handshake_hash_from_state(state: &HandshakeState) -> [u8; HANDSHAKE_HASH_LEN] {
    let hh = state.get_handshake_hash();
    // snow гарантирует длину hash == размер hash-функции ciphersuite (SHA-512 → 64).
    let mut out = [0u8; HANDSHAKE_HASH_LEN];
    let n = hh.len().min(HANDSHAKE_HASH_LEN);
    out[..n].copy_from_slice(&hh[..n]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::{OsRng, RngCore};
    use x25519_dalek::{PublicKey as XPub, StaticSecret as XStatic};

    use crate::device_transfer::qr::{build_signed_qr, PAIRING_CHALLENGE_LEN};

    fn make_ed_keypair() -> (SigningKey, ed25519_dalek::VerifyingKey) {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let sk = SigningKey::from_bytes(&seed);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    fn make_x25519_pair() -> (XStatic, [u8; 32]) {
        let secret = XStatic::random_from_rng(OsRng);
        let public = XPub::from(&secret);
        (secret, public.to_bytes())
    }

    #[test]
    fn handshake_ik_two_message_happy_path() {
        // Setup responder identity + ephemeral static.
        let (resp_sk, resp_vk) = make_ed_keypair();
        let (resp_eph_secret, resp_eph_pub) = make_x25519_pair();

        // Generate QR with responder's signed identity.
        let mut chal = [0u8; PAIRING_CHALLENGE_LEN];
        OsRng.fill_bytes(&mut chal);
        let qr = build_signed_qr(
            resp_vk.to_bytes(),
            resp_eph_pub,
            chal,
            u64::MAX / 2, // far in future
            |payload| Ok(resp_sk.sign(payload).to_bytes()),
        )
        .unwrap();

        // Initiator generates own X25519 static.
        let (init_secret, init_pub) = make_x25519_pair();

        let mut initiator = PairingInitiator::new(&qr, &init_secret.to_bytes()).unwrap();
        let mut responder =
            PairingResponder::new(&resp_eph_secret.to_bytes(), &qr.pairing_challenge).unwrap();

        // Message 1: initiator → responder
        let msg1 = initiator.write_message_1().unwrap();
        responder.read_message_1(&msg1).unwrap();

        // Responder теперь должен знать initiator's static public.
        let rs = responder.remote_static().unwrap();
        assert_eq!(rs.as_slice(), &init_pub);

        // Message 2: responder → initiator
        let (msg2, resp_result) = responder.write_message_2_and_finalize().unwrap();

        let init_result = initiator.read_message_2_and_finalize(&msg2).unwrap();

        // Handshake hashes должны совпасть между сторонами.
        assert_eq!(init_result.handshake_hash, resp_result.handshake_hash);
        // Non-zero
        assert_ne!(init_result.handshake_hash, [0u8; HANDSHAKE_HASH_LEN]);
    }

    #[test]
    fn handshake_fails_when_responder_ephemeral_static_mismatch() {
        let (resp_sk, resp_vk) = make_ed_keypair();
        let (_resp_eph_secret, resp_eph_pub) = make_x25519_pair();
        // Совсем другой секрет у responder'а (не соответствует pub в QR).
        let (wrong_secret, _) = make_x25519_pair();

        let mut chal = [0u8; PAIRING_CHALLENGE_LEN];
        OsRng.fill_bytes(&mut chal);
        let qr = build_signed_qr(
            resp_vk.to_bytes(),
            resp_eph_pub,
            chal,
            u64::MAX / 2,
            |payload| Ok(resp_sk.sign(payload).to_bytes()),
        )
        .unwrap();

        let (init_secret, _init_pub) = make_x25519_pair();
        let mut initiator = PairingInitiator::new(&qr, &init_secret.to_bytes()).unwrap();
        let mut responder =
            PairingResponder::new(&wrong_secret.to_bytes(), &qr.pairing_challenge).unwrap();

        let msg1 = initiator.write_message_1().unwrap();
        // IK ожидает что responder decrypt сможет DH(initiator_e, responder_static).
        // Если responder static не тот, decrypt fails.
        let err = responder.read_message_1(&msg1).unwrap_err();
        assert!(matches!(err, BackupError::HandshakeFailed(_)));
    }

    #[test]
    fn handshake_fails_on_mismatched_prologue() {
        // Разные pairing_challenge → разные prologue → handshake расходится.
        let (resp_sk, resp_vk) = make_ed_keypair();
        let (resp_eph_secret, resp_eph_pub) = make_x25519_pair();
        let mut chal_a = [0u8; PAIRING_CHALLENGE_LEN];
        OsRng.fill_bytes(&mut chal_a);
        let mut chal_b = [0u8; PAIRING_CHALLENGE_LEN];
        OsRng.fill_bytes(&mut chal_b);
        assert_ne!(chal_a, chal_b);

        let qr = build_signed_qr(
            resp_vk.to_bytes(),
            resp_eph_pub,
            chal_a,
            u64::MAX / 2,
            |payload| Ok(resp_sk.sign(payload).to_bytes()),
        )
        .unwrap();

        let (init_secret, _init_pub) = make_x25519_pair();
        let mut initiator = PairingInitiator::new(&qr, &init_secret.to_bytes()).unwrap();
        // Responder с ДРУГИМ challenge — prologue разойдётся.
        let mut responder = PairingResponder::new(&resp_eph_secret.to_bytes(), &chal_b).unwrap();

        let msg1 = initiator.write_message_1().unwrap();
        let err = responder.read_message_1(&msg1).unwrap_err();
        assert!(matches!(err, BackupError::HandshakeFailed(_)));
    }

    #[test]
    fn handshake_hash_is_non_trivial_and_varies_by_challenge() {
        let (resp_sk, resp_vk) = make_ed_keypair();
        let (resp_eph_secret, resp_eph_pub) = make_x25519_pair();

        let run_with_challenge = |chal: [u8; PAIRING_CHALLENGE_LEN]| {
            let qr = build_signed_qr(
                resp_vk.to_bytes(),
                resp_eph_pub,
                chal,
                u64::MAX / 2,
                |payload| Ok(resp_sk.sign(payload).to_bytes()),
            )
            .unwrap();
            let (init_secret, _) = make_x25519_pair();
            let mut initiator = PairingInitiator::new(&qr, &init_secret.to_bytes()).unwrap();
            let mut responder =
                PairingResponder::new(&resp_eph_secret.to_bytes(), &qr.pairing_challenge).unwrap();
            let msg1 = initiator.write_message_1().unwrap();
            responder.read_message_1(&msg1).unwrap();
            let (msg2, r) = responder.write_message_2_and_finalize().unwrap();
            let i = initiator.read_message_2_and_finalize(&msg2).unwrap();
            assert_eq!(i.handshake_hash, r.handshake_hash);
            i.handshake_hash
        };

        let mut c1 = [0u8; PAIRING_CHALLENGE_LEN];
        OsRng.fill_bytes(&mut c1);
        let mut c2 = [0u8; PAIRING_CHALLENGE_LEN];
        OsRng.fill_bytes(&mut c2);
        let hh1 = run_with_challenge(c1);
        let hh2 = run_with_challenge(c2);
        assert_ne!(
            hh1, hh2,
            "different challenges must produce different handshake hashes"
        );
        assert_ne!(hh1, [0u8; HANDSHAKE_HASH_LEN]);
    }

    #[test]
    fn handshake_transport_can_encrypt_and_decrypt_payload() {
        let (resp_sk, resp_vk) = make_ed_keypair();
        let (resp_eph_secret, resp_eph_pub) = make_x25519_pair();
        let mut chal = [0u8; PAIRING_CHALLENGE_LEN];
        OsRng.fill_bytes(&mut chal);

        let qr = build_signed_qr(
            resp_vk.to_bytes(),
            resp_eph_pub,
            chal,
            u64::MAX / 2,
            |payload| Ok(resp_sk.sign(payload).to_bytes()),
        )
        .unwrap();

        let (init_secret, _) = make_x25519_pair();
        let mut initiator = PairingInitiator::new(&qr, &init_secret.to_bytes()).unwrap();
        let mut responder =
            PairingResponder::new(&resp_eph_secret.to_bytes(), &qr.pairing_challenge).unwrap();

        let msg1 = initiator.write_message_1().unwrap();
        responder.read_message_1(&msg1).unwrap();
        let (msg2, mut resp_state) = responder.write_message_2_and_finalize().unwrap();
        let mut init_state = initiator.read_message_2_and_finalize(&msg2).unwrap();

        // Responder шлёт payload.
        let plaintext = b"hello, initiator";
        let mut enc_buf = vec![0u8; plaintext.len() + 16];
        let n = resp_state
            .transport
            .write_message(plaintext, &mut enc_buf)
            .unwrap();
        enc_buf.truncate(n);

        let mut dec_buf = vec![0u8; enc_buf.len()];
        let m = init_state
            .transport
            .read_message(&enc_buf, &mut dec_buf)
            .unwrap();
        dec_buf.truncate(m);
        assert_eq!(dec_buf, plaintext);
    }
}
