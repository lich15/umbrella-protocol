//! Snapshot payload: MLS group state + local DB ciphertext.
//! Snapshot payload: MLS group state + local DB ciphertext.
//!
//! Responder собирает snapshot своей истории в одном байтовом payload и
//! передаёт через [`crate::device_transfer::stream::TransferSession`] как
//! serie frames. Payload не зашифрован отдельно — encryption обеспечивается
//! Noise transport cipher уровнем ниже. Структура payload фиксирована для
//! cross-version совместимости.
//!
//! Responder assembles a snapshot of their history into one byte payload and
//! transmits via `TransferSession` as a series of frames. Payload is not
//! separately encrypted — encryption is handled at the Noise transport
//! cipher layer. Structure is fixed for cross-version compatibility.

use core::convert::TryInto;

use crate::error::BackupError;

/// Версия snapshot wire-format. Snapshot wire-format version.
pub const SNAPSHOT_VERSION: u8 = 0x01;

/// Длина MLS group_id. MLS group_id length.
pub const MLS_GROUP_ID_LEN: usize = 16;

/// Специальный маркер конца snapshot'а.
/// Special snapshot-end marker.
pub const SNAPSHOT_EOF_MARKER: &[u8; 4] = b"EOFD";

/// Максимальное количество MLS-групп в одном snapshot. Защита от
/// DoS-амплификации (F-76 block 10.27c session #59 retroactive surface sweep):
/// 5 wire-байт (`version || count_u32_be`) могли бы запросить
/// `Vec::with_capacity(u32::MAX)` ≈ 160 GiB виртуальной памяти на
/// `mls_groups` Vec до того как `take()` bound-check отвергнет input. На
/// мобильной ОС (iOS/Android) — OOM kill процесса. Mitigation: ранняя
/// проверка `count <= MAX_SNAPSHOT_GROUPS` ДО `Vec::with_capacity(count)`.
/// Параллель `MAX_FRAME_PAYLOAD = 1 MiB` в `stream.rs`. Значение 4096
/// поддерживает power-user'ов (типичный пользователь ≤100 групп; даже
/// crypto-power-user редко >1000) при capacity allocation ≈ 4096 × 64 байт
/// ≈ 256 KiB ≪ безопасный bound.
///
/// Maximum number of MLS groups in a single snapshot. Defence against
/// DoS amplification (F-76 block 10.27c session #59 retroactive surface
/// sweep): 5 wire bytes (`version || count_u32_be`) could request
/// `Vec::with_capacity(u32::MAX)` ≈ 160 GiB virtual memory for the
/// `mls_groups` Vec before `take()` bound-check rejects input. On mobile
/// OS (iOS/Android) → OOM kill of the process. Mitigation: early check
/// `count <= MAX_SNAPSHOT_GROUPS` before `Vec::with_capacity(count)`.
/// Mirrors `MAX_FRAME_PAYLOAD = 1 MiB` in `stream.rs`. Value 4096 supports
/// power users (typical user ≤100 groups; even crypto-power-users rarely
/// exceed 1000) with capacity allocation ≈ 4096 × 64 bytes ≈ 256 KiB ≪
/// safe bound.
pub const MAX_SNAPSHOT_GROUPS: u32 = 4096;

/// MLS group state — непрозрачные байты tls_codec-serialized openmls
/// `MlsGroup`.
///
/// MLS group state — opaque tls_codec-serialized openmls `MlsGroup` bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlsGroupState {
    /// Идентификатор группы. Group identifier.
    pub group_id: [u8; MLS_GROUP_ID_LEN],
    /// Serialized state bytes. Serialized state bytes.
    pub state_bytes: Vec<u8>,
}

/// Полный snapshot — groups + encrypted local DB blob + EOF marker.
/// Full snapshot — groups + encrypted local DB blob + EOF marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// Версия. Version.
    pub version: u8,
    /// MLS groups active на responder'е.
    /// MLS groups active on responder.
    pub mls_groups: Vec<MlsGroupState>,
    /// Encrypted local DB ciphertext (encryption — ответственность caller'а,
    /// обычно симметричный ключ выведенный из identity master; в крейте
    /// принимаем opaque bytes).
    ///
    /// Encrypted local DB ciphertext (encryption is caller's responsibility,
    /// typically a symmetric key derived from identity master; opaque here).
    pub local_db_ciphertext: Vec<u8>,
}

impl Snapshot {
    /// Сериализация в payload.
    /// Serialize to payload.
    ///
    /// # Errors
    /// - [`BackupError::WireBufferOverflow`] если `local_db_ciphertext` overflow'ит
    ///   u64 (не должно случаться на реальных данных).
    pub fn to_bytes(&self) -> Result<Vec<u8>, BackupError> {
        let mut out = Vec::new();
        out.push(self.version);
        let count: u32 = self
            .mls_groups
            .len()
            .try_into()
            .map_err(|_| BackupError::WireBufferOverflow)?;
        out.extend_from_slice(&count.to_be_bytes());
        for g in &self.mls_groups {
            out.extend_from_slice(&g.group_id);
            let state_len: u32 = g
                .state_bytes
                .len()
                .try_into()
                .map_err(|_| BackupError::WireBufferOverflow)?;
            out.extend_from_slice(&state_len.to_be_bytes());
            out.extend_from_slice(&g.state_bytes);
        }
        let db_len: u64 = self
            .local_db_ciphertext
            .len()
            .try_into()
            .map_err(|_| BackupError::WireBufferOverflow)?;
        out.extend_from_slice(&db_len.to_be_bytes());
        out.extend_from_slice(&self.local_db_ciphertext);
        out.extend_from_slice(SNAPSHOT_EOF_MARKER);
        Ok(out)
    }

    /// Десериализация из payload.
    /// Deserialize from payload.
    ///
    /// # Errors
    /// - [`BackupError::SnapshotDecodeFailed`] если формат невалиден.
    pub fn from_bytes(data: &[u8]) -> Result<Self, BackupError> {
        let mut cursor = 0usize;
        let take = |n: usize, cursor: &mut usize| -> Result<&[u8], BackupError> {
            if data.len() < *cursor + n {
                return Err(BackupError::SnapshotDecodeFailed);
            }
            let s = &data[*cursor..*cursor + n];
            *cursor += n;
            Ok(s)
        };

        let version = take(1, &mut cursor)?[0];
        if version != SNAPSHOT_VERSION {
            return Err(BackupError::SnapshotDecodeFailed);
        }

        let count_bytes: [u8; 4] = take(4, &mut cursor)?
            .try_into()
            .map_err(|_| BackupError::SnapshotDecodeFailed)?;
        let count_u32 = u32::from_be_bytes(count_bytes);

        // F-76 block 10.27c session #59 (retroactive surface sweep): защита от
        // DoS-амплификации через `Vec::with_capacity(u32::MAX as usize)` ≈ 160 GiB
        // запроса виртуальной памяти. Без этой ранней проверки `take()` line 124
        // отвергнет input ПОСЛЕ Vec allocation — на мобильной ОС OOM kill случается
        // раньше чем bound-check срабатывает. См. doc-comment к MAX_SNAPSHOT_GROUPS.
        //
        // F-76 block 10.27c session #59 (retroactive surface sweep): defence against
        // DoS amplification via `Vec::with_capacity(u32::MAX as usize)` ≈ 160 GiB
        // virtual memory request. Without this early check `take()` line 124 rejects
        // input AFTER the Vec allocation — on mobile OS the OOM kill occurs before
        // the bound-check fires. See doc-comment for MAX_SNAPSHOT_GROUPS.
        if count_u32 > MAX_SNAPSHOT_GROUPS {
            return Err(BackupError::SnapshotDecodeFailed);
        }
        let count = count_u32 as usize;

        let mut groups = Vec::with_capacity(count);
        for _ in 0..count {
            let gid: [u8; MLS_GROUP_ID_LEN] = take(MLS_GROUP_ID_LEN, &mut cursor)?
                .try_into()
                .map_err(|_| BackupError::SnapshotDecodeFailed)?;
            let state_len_bytes: [u8; 4] = take(4, &mut cursor)?
                .try_into()
                .map_err(|_| BackupError::SnapshotDecodeFailed)?;
            let state_len = u32::from_be_bytes(state_len_bytes) as usize;
            let state_bytes = take(state_len, &mut cursor)?.to_vec();
            groups.push(MlsGroupState {
                group_id: gid,
                state_bytes,
            });
        }

        let db_len_bytes: [u8; 8] = take(8, &mut cursor)?
            .try_into()
            .map_err(|_| BackupError::SnapshotDecodeFailed)?;
        let db_len = u64::from_be_bytes(db_len_bytes) as usize;
        let local_db_ciphertext = take(db_len, &mut cursor)?.to_vec();

        let eof = take(4, &mut cursor)?;
        if eof != SNAPSHOT_EOF_MARKER {
            return Err(BackupError::SnapshotDecodeFailed);
        }

        if cursor != data.len() {
            return Err(BackupError::SnapshotDecodeFailed);
        }

        Ok(Self {
            version,
            mls_groups: groups,
            local_db_ciphertext,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_snapshot(groups: usize, db_len: usize) -> Snapshot {
        let mut mls_groups = Vec::with_capacity(groups);
        for i in 0..groups {
            let mut gid = [0u8; MLS_GROUP_ID_LEN];
            gid[0] = i as u8;
            let state_bytes = vec![0xA0u8 + (i as u8); 100 + i * 50];
            mls_groups.push(MlsGroupState {
                group_id: gid,
                state_bytes,
            });
        }
        let local_db_ciphertext = vec![0x11u8; db_len];
        Snapshot {
            version: SNAPSHOT_VERSION,
            mls_groups,
            local_db_ciphertext,
        }
    }

    #[test]
    fn snapshot_roundtrip_empty() {
        let s = sample_snapshot(0, 0);
        let bytes = s.to_bytes().unwrap();
        let parsed = Snapshot::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, s);
    }

    #[test]
    fn snapshot_roundtrip_one_group() {
        let s = sample_snapshot(1, 64);
        let bytes = s.to_bytes().unwrap();
        let parsed = Snapshot::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, s);
    }

    #[test]
    fn snapshot_roundtrip_multiple_groups() {
        let s = sample_snapshot(5, 8192);
        let bytes = s.to_bytes().unwrap();
        let parsed = Snapshot::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, s);
    }

    #[test]
    fn snapshot_rejects_wrong_version() {
        let s = sample_snapshot(1, 32);
        let mut bytes = s.to_bytes().unwrap();
        bytes[0] = 0x02;
        let err = Snapshot::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, BackupError::SnapshotDecodeFailed));
    }

    #[test]
    fn snapshot_rejects_wrong_eof() {
        let s = sample_snapshot(1, 32);
        let mut bytes = s.to_bytes().unwrap();
        let eof_off = bytes.len() - 4;
        bytes[eof_off] = b'X';
        let err = Snapshot::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, BackupError::SnapshotDecodeFailed));
    }

    #[test]
    fn snapshot_rejects_truncated() {
        let s = sample_snapshot(2, 64);
        let bytes = s.to_bytes().unwrap();
        let truncated = &bytes[..bytes.len() - 10];
        let err = Snapshot::from_bytes(truncated).unwrap_err();
        assert!(matches!(err, BackupError::SnapshotDecodeFailed));
    }

    #[test]
    fn snapshot_rejects_trailing_garbage() {
        let s = sample_snapshot(1, 16);
        let mut bytes = s.to_bytes().unwrap();
        bytes.push(0xFF);
        let err = Snapshot::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, BackupError::SnapshotDecodeFailed));
    }

    #[test]
    fn snapshot_rejects_inconsistent_group_length() {
        let s = sample_snapshot(1, 0);
        let mut bytes = s.to_bytes().unwrap();
        // Inflate group state_len field to point past end.
        // Layout: version(1) + count(4) + group_id(16) + state_len(4) + ...
        let state_len_off = 1 + 4 + MLS_GROUP_ID_LEN;
        bytes[state_len_off..state_len_off + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        let err = Snapshot::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, BackupError::SnapshotDecodeFailed));
    }
}
