//! PACE with ECDH generic mapping and AES-CBC-CMAC-256.

use aes::Aes256;
use bp384::{
    BrainpoolP384r1,
    elliptic_curve::{
        FieldBytes, ProjectivePoint, PublicKey, SecretKey, group::Group, point::AffineCoordinates,
        sec1::ToSec1Point,
    },
};
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::NoPadding};
use cmac::{Cmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::invalid;

const PACE_OID: &[u8] = &[0x04, 0x00, 0x7f, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x04];
const AES_BLOCK: usize = 16;
const POINT_SIZE: usize = 48;

#[derive(Clone, Copy)]
enum Credential {
    Mrz = 1,
    Can = 2,
    Pin = 3,
    Puk = 4,
}

impl Credential {
    fn from_text(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "mrz" => Some(Self::Mrz),
            "can" => Some(Self::Can),
            "pin" => Some(Self::Pin),
            "puk" => Some(Self::Puk),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage {
    SetAt,
    Nonce,
    Mapping,
    Ephemeral,
    Token,
    Ready,
}

pub struct Session {
    credential: Credential,
    password_key: [u8; 32],
    stage: Stage,
    mapping_secret: SecretKey<BrainpoolP384r1>,
    ephemeral_secret: SecretKey<BrainpoolP384r1>,
    nonce: [u8; AES_BLOCK],
    ephemeral_public: Vec<u8>,
    encryption_key: [u8; 32],
    authentication_key: [u8; 32],
    sequence: [u8; AES_BLOCK],
}

impl mlua::UserData for Session {}

impl Session {
    pub fn new(
        credential: &str,
        secret: &[u8],
        mapping_scalar: Option<&[u8]>,
        ephemeral_scalar: Option<&[u8]>,
    ) -> Result<Self, crate::RuntimeError> {
        let credential = Credential::from_text(credential)
            .ok_or_else(|| invalid("PACE credential must be mrz, can, pin, or puk"))?;
        if secret.is_empty() {
            return Err(invalid("PACE credential is empty"));
        }
        let mapping_secret = match mapping_scalar {
            Some(bytes) => decode_secret(bytes)?,
            None => random_secret()?,
        };
        let ephemeral_secret = match ephemeral_scalar {
            Some(bytes) => decode_secret(bytes)?,
            None => random_secret()?,
        };
        Ok(Self {
            credential,
            password_key: derive(secret, 3),
            stage: Stage::SetAt,
            mapping_secret,
            ephemeral_secret,
            nonce: [0; AES_BLOCK],
            ephemeral_public: Vec::new(),
            encryption_key: [0; 32],
            authentication_key: [0; 32],
            sequence: [0; AES_BLOCK],
        })
    }

    pub fn handshake(
        &mut self,
        response: Option<(Vec<u8>, u16)>,
    ) -> Result<Option<Vec<u8>>, crate::RuntimeError> {
        if self.stage == Stage::Ready {
            return Err(invalid("PACE authentication is already complete"));
        }
        if self.stage == Stage::SetAt && response.is_none() {
            return Ok(Some(self.set_at_command()));
        }
        let (data, status) = response.ok_or_else(|| invalid("PACE card response is missing"))?;
        if status != 0x9000 {
            return Err(invalid(format!(
                "PACE command failed with status {status:04X}"
            )));
        }
        match self.stage {
            Stage::SetAt => {
                if !data.is_empty() {
                    return Err(invalid("MSE:Set AT returned unexpected data"));
                }
                self.stage = Stage::Nonce;
                Ok(Some(general_authenticate(&tlv(0x7c, &[]), true)))
            }
            Stage::Nonce => {
                let encrypted_nonce = authentication_object(&data, 0x80)?;
                if encrypted_nonce.len() != AES_BLOCK {
                    return Err(invalid("PACE encrypted nonce must contain 16 bytes"));
                }
                let nonce = aes_cbc(false, &self.password_key, &[0; AES_BLOCK], &encrypted_nonce);
                self.nonce.copy_from_slice(&nonce);
                self.sequence = self.nonce;
                let mapping_public = public_bytes(&self.mapping_secret);
                self.stage = Stage::Mapping;
                Ok(Some(general_authenticate(
                    &tlv(0x7c, &tlv(0x81, &mapping_public)),
                    true,
                )))
            }
            Stage::Mapping => {
                let card_mapping_bytes = authentication_object(&data, 0x82)?;
                let card_mapping = decode_public(&card_mapping_bytes)?;
                let mapped_generator =
                    map_generator(&self.mapping_secret, &card_mapping, &self.nonce)?;
                let ephemeral_point = mapped_generator * *self.ephemeral_secret.to_nonzero_scalar();
                if bool::from(ephemeral_point.is_identity()) {
                    return Err(invalid("PACE ephemeral public key is the identity"));
                }
                self.ephemeral_public = ephemeral_point
                    .to_affine()
                    .to_sec1_point(false)
                    .as_bytes()
                    .to_vec();
                self.stage = Stage::Ephemeral;
                Ok(Some(general_authenticate(
                    &tlv(0x7c, &tlv(0x83, &self.ephemeral_public)),
                    true,
                )))
            }
            Stage::Ephemeral => {
                let card_ephemeral_bytes = authentication_object(&data, 0x84)?;
                let card_ephemeral = decode_public(&card_ephemeral_bytes)?;
                if self.ephemeral_public == card_ephemeral_bytes {
                    return Err(invalid("PACE ephemeral keys must differ"));
                }
                let shared_point =
                    card_ephemeral.to_projective() * *self.ephemeral_secret.to_nonzero_scalar();
                if bool::from(shared_point.is_identity()) {
                    return Err(invalid("PACE shared point is the identity"));
                }
                let x = shared_point.to_affine().x();
                let mut shared = [0_u8; POINT_SIZE];
                shared.copy_from_slice(x.as_slice());
                self.encryption_key = derive(&shared, 1);
                self.authentication_key = derive(&shared, 2);
                let token = authentication_token(&self.authentication_key, &card_ephemeral_bytes);
                self.stage = Stage::Token;
                Ok(Some(general_authenticate(
                    &tlv(0x7c, &tlv(0x85, &token)),
                    false,
                )))
            }
            Stage::Token => {
                let card_token = authentication_object(&data, 0x86)?;
                let expected =
                    authentication_token(&self.authentication_key, &self.ephemeral_public);
                if !bool::from(card_token.as_slice().ct_eq(&expected)) {
                    return Err(invalid("PACE authentication token is invalid"));
                }
                self.stage = Stage::Ready;
                self.sequence = self.nonce;
                Ok(None)
            }
            Stage::Ready => unreachable!("ready state is rejected above"),
        }
    }

    fn set_at_command(&self) -> Vec<u8> {
        let mut data = tlv(0x80, PACE_OID);
        data.extend_from_slice(&tlv(0x83, &[self.credential as u8]));
        data.extend_from_slice(&tlv(0x84, &[13]));
        let mut command = vec![0x00, 0x22, 0xc1, 0xa4];
        command.push(u8::try_from(data.len()).expect("short MSE:Set AT command"));
        command.extend_from_slice(&data);
        command
    }

    pub fn protect(&mut self, command: &[u8]) -> Result<Vec<u8>, crate::RuntimeError> {
        if self.stage != Stage::Ready {
            return Err(invalid("PACE authentication is not complete"));
        }
        if command.len() < 4 {
            return Err(invalid("secure APDU header is too short"));
        }
        let (payload, expected_length) = command_payload(command)?;
        let mut protected_header = command[..4].to_vec();
        protected_header[0] |= 0x0c;
        self.increment_sequence()?;
        let iv = aes_cbc(true, &self.encryption_key, &[0; AES_BLOCK], &self.sequence);
        let mut mac_input = self.sequence.to_vec();
        mac_input.extend_from_slice(&iso_pad(&protected_header));
        let mut body = Vec::new();
        if !payload.is_empty() {
            let encrypted = aes_cbc(true, &self.encryption_key, &iv, &iso_pad(payload));
            body.extend_from_slice(&tlv(0x87, &[&[0x01], encrypted.as_slice()].concat()));
        }
        if let Some(length) = expected_length {
            body.extend_from_slice(&tlv(0x97, &[length]));
        }
        mac_input.extend_from_slice(&iso_pad(&body));
        body.extend_from_slice(&tlv(
            0x8e,
            &aes_cmac(&self.authentication_key, &mac_input)[..8],
        ));
        let mut output = protected_header;
        output.push(u8::try_from(body.len()).map_err(|_| invalid("secure APDU is too long"))?);
        output.extend_from_slice(&body);
        output.push(0);
        Ok(output)
    }

    pub fn unprotect(&mut self, response: &[u8]) -> Result<(Vec<u8>, u16), crate::RuntimeError> {
        if self.stage != Stage::Ready {
            return Err(invalid("PACE authentication is not complete"));
        }
        if response.len() < 2 {
            return Err(invalid("secure response is too short"));
        }
        let status =
            u16::from_be_bytes([response[response.len() - 2], response[response.len() - 1]]);
        if status != 0x9000 {
            return Err(invalid(format!(
                "card rejected secure messaging with status {status:04X}"
            )));
        }
        self.increment_sequence()?;
        let mut fields = TlvFields::new(&response[..response.len() - 2]);
        let mut mac_input = self.sequence.to_vec();
        let encrypted = fields.take(0x87);
        if let Some(encrypted) = &encrypted {
            mac_input.extend_from_slice(&tlv(0x87, encrypted));
        }
        let status_object = fields
            .take(0x99)
            .ok_or_else(|| invalid("secure response status is missing"))?;
        if status_object.len() != 2 {
            return Err(invalid("secure response status has invalid length"));
        }
        mac_input.extend_from_slice(&tlv(0x99, &status_object));
        let checksum = fields
            .take(0x8e)
            .ok_or_else(|| invalid("secure response checksum is missing"))?;
        let expected = aes_cmac(&self.authentication_key, &iso_pad(&mac_input));
        if !bool::from(checksum.as_slice().ct_eq(&expected[..8])) {
            return Err(invalid("secure response checksum is invalid"));
        }
        if !fields.empty() {
            return Err(invalid("secure response contains unexpected objects"));
        }
        let plaintext = match encrypted {
            Some(encrypted) => {
                if encrypted.first() != Some(&0x01) {
                    return Err(invalid("invalid secure response padding indicator"));
                }
                if encrypted.len() == 1 || (encrypted.len() - 1) % AES_BLOCK != 0 {
                    return Err(invalid("secure response ciphertext has invalid length"));
                }
                let iv = aes_cbc(true, &self.encryption_key, &[0; AES_BLOCK], &self.sequence);
                unpad(&aes_cbc(false, &self.encryption_key, &iv, &encrypted[1..]))?
            }
            None => Vec::new(),
        };
        Ok((
            plaintext,
            u16::from_be_bytes([status_object[0], status_object[1]]),
        ))
    }

    fn increment_sequence(&mut self) -> Result<(), crate::RuntimeError> {
        for byte in self.sequence.iter_mut().rev() {
            let (next, carry) = byte.overflowing_add(1);
            *byte = next;
            if !carry {
                return Ok(());
            }
        }
        Err(invalid("secure messaging sequence overflow"))
    }
}

fn decode_secret(encoded: &[u8]) -> Result<SecretKey<BrainpoolP384r1>, crate::RuntimeError> {
    if encoded.len() != POINT_SIZE {
        return Err(invalid("PACE scalar must contain 48 bytes"));
    }
    let bytes = FieldBytes::<BrainpoolP384r1>::try_from(encoded)
        .map_err(|_| invalid("invalid PACE scalar"))?;
    SecretKey::<BrainpoolP384r1>::from_bytes(&bytes).map_err(|_| invalid("invalid PACE scalar"))
}

fn random_secret() -> Result<SecretKey<BrainpoolP384r1>, crate::RuntimeError> {
    let mut bytes = [0_u8; POINT_SIZE];
    getrandom::fill(&mut bytes).map_err(|_| invalid("PACE random scalar generation failed"))?;
    SecretKey::<BrainpoolP384r1>::from_bytes(&bytes.into())
        .map_err(|_| invalid("PACE random scalar generation failed"))
}

fn public_bytes(secret: &SecretKey<BrainpoolP384r1>) -> Vec<u8> {
    secret
        .public_key()
        .as_affine()
        .to_sec1_point(false)
        .as_bytes()
        .to_vec()
}

fn decode_public(encoded: &[u8]) -> Result<PublicKey<BrainpoolP384r1>, crate::RuntimeError> {
    PublicKey::<BrainpoolP384r1>::from_sec1_bytes(encoded)
        .map_err(|_| invalid("invalid PACE public key"))
}

fn map_generator(
    mapping_secret: &SecretKey<BrainpoolP384r1>,
    card_mapping: &PublicKey<BrainpoolP384r1>,
    nonce: &[u8],
) -> Result<ProjectivePoint<BrainpoolP384r1>, crate::RuntimeError> {
    let card_point = card_mapping.to_projective();
    let h = card_point * *mapping_secret.to_nonzero_scalar();
    let mut nonce_bytes = [0_u8; POINT_SIZE];
    nonce_bytes[POINT_SIZE - nonce.len()..].copy_from_slice(nonce);
    let nonce_scalar = SecretKey::<BrainpoolP384r1>::from_bytes(&nonce_bytes.into())
        .map_err(|_| invalid("PACE nonce is not a valid scalar"))?;
    let generator =
        ProjectivePoint::<BrainpoolP384r1>::mul_by_generator(&nonce_scalar.to_nonzero_scalar());
    let mapped = generator + h;
    if bool::from(mapped.is_identity()) {
        return Err(invalid("PACE mapped generator is the identity"));
    }
    Ok(mapped)
}

fn derive(secret: &[u8], counter: u8) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(secret);
    hash.update([0, 0, 0, counter]);
    hash.finalize().into()
}

fn authentication_token(key: &[u8; 32], public: &[u8]) -> [u8; 8] {
    let mut input = Vec::new();
    input.extend_from_slice(&tlv(0x06, PACE_OID));
    input.extend_from_slice(&tlv(0x86, public));
    let encoded = tlv(0x7f49, &input);
    let mac = aes_cmac(key, &encoded);
    mac[..8].try_into().expect("AES-CMAC prefix")
}

fn aes_cbc(encrypt: bool, key: &[u8; 32], iv: &[u8], input: &[u8]) -> Vec<u8> {
    let mut output = input.to_vec();
    if encrypt {
        cbc::Encryptor::<Aes256>::new_from_slices(key, iv)
            .expect("validated AES parameters")
            .encrypt_padded_mut::<NoPadding>(&mut output, input.len())
            .expect("complete AES blocks");
    } else {
        cbc::Decryptor::<Aes256>::new_from_slices(key, iv)
            .expect("validated AES parameters")
            .decrypt_padded_mut::<NoPadding>(&mut output)
            .expect("complete AES blocks");
    }
    output
}

fn aes_cmac(key: &[u8; 32], input: &[u8]) -> [u8; AES_BLOCK] {
    let mut mac = Cmac::<Aes256>::new_from_slice(key).expect("validated AES key");
    mac.update(input);
    mac.finalize().into_bytes().into()
}

fn iso_pad(input: &[u8]) -> Vec<u8> {
    let mut output = input.to_vec();
    output.push(0x80);
    while !output.len().is_multiple_of(AES_BLOCK) {
        output.push(0);
    }
    output
}

fn unpad(input: &[u8]) -> Result<Vec<u8>, crate::RuntimeError> {
    let Some(index) = input.iter().rposition(|byte| *byte != 0) else {
        return Err(invalid("secure response padding is missing"));
    };
    if input[index] != 0x80 {
        return Err(invalid("secure response padding is invalid"));
    }
    Ok(input[..index].to_vec())
}

fn authentication_object(data: &[u8], tag: u16) -> Result<Vec<u8>, crate::RuntimeError> {
    let mut fields = TlvFields::new(data);
    let wrapper = fields
        .take(0x7c)
        .ok_or_else(|| invalid("PACE dynamic authentication data is missing"))?;
    if !fields.empty() {
        return Err(invalid("PACE response contains unexpected outer objects"));
    }
    let mut inner = TlvFields::new(&wrapper);
    let value = inner
        .take(tag)
        .ok_or_else(|| invalid("expected PACE response object is missing"))?;
    if !inner.empty() {
        return Err(invalid(
            "PACE response contains unexpected authentication objects",
        ));
    }
    Ok(value)
}

fn command_payload(command: &[u8]) -> Result<(&[u8], Option<u8>), crate::RuntimeError> {
    if command.len() == 4 {
        return Ok((&[], None));
    }
    if command.len() == 5 {
        return Ok((&[], Some(command[4])));
    }
    let lc = usize::from(command[4]);
    if lc == 0 {
        return Err(invalid(
            "extended APDUs are not supported by this PACE profile",
        ));
    }
    if command.len() == 5 + lc {
        return Ok((&command[5..], None));
    }
    if command.len() == 6 + lc {
        return Ok((&command[5..5 + lc], Some(command[5 + lc])));
    }
    Err(invalid("APDU length does not match Lc"))
}

fn general_authenticate(payload: &[u8], chaining: bool) -> Vec<u8> {
    let mut output = vec![if chaining { 0x10 } else { 0x00 }, 0x86, 0, 0];
    output.push(u8::try_from(payload.len()).expect("short PACE command"));
    output.extend_from_slice(payload);
    output.push(0);
    output
}

fn tlv(tag: u32, value: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    if tag <= 0xff {
        output.push(u8::try_from(tag).expect("single-byte tag"));
    } else if tag <= 0xffff {
        output.extend_from_slice(&u16::try_from(tag).expect("two-byte tag").to_be_bytes());
    } else {
        panic!("TLV tags above two bytes are not supported");
    }
    if value.len() < 0x80 {
        output.push(u8::try_from(value.len()).expect("short DER length"));
    } else {
        let bytes = value.len().to_be_bytes();
        let first = bytes
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(bytes.len() - 1);
        output.push(0x80 | u8::try_from(bytes.len() - first).expect("DER length size"));
        output.extend_from_slice(&bytes[first..]);
    }
    output.extend_from_slice(value);
    output
}

struct TlvFields<'a> {
    data: &'a [u8],
}

impl<'a> TlvFields<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    fn take(&mut self, expected: u16) -> Option<Vec<u8>> {
        let tag_size = if expected > 0xff { 2 } else { 1 };
        if self.data.len() < tag_size {
            return None;
        }
        let actual = if tag_size == 1 {
            u16::from(self.data[0])
        } else {
            u16::from_be_bytes([self.data[0], self.data[1]])
        };
        if actual != expected {
            return None;
        }
        let (length, header) = der_length(&self.data[tag_size..]).ok()?;
        let end = tag_size + header + length;
        if end > self.data.len() {
            return None;
        }
        let value = self.data[tag_size + header..end].to_vec();
        self.data = &self.data[end..];
        Some(value)
    }

    fn empty(&self) -> bool {
        self.data.is_empty()
    }
}

fn der_length(input: &[u8]) -> Result<(usize, usize), crate::RuntimeError> {
    let Some(first) = input.first().copied() else {
        return Err(invalid("DER length is missing"));
    };
    if first < 0x80 {
        return Ok((first as usize, 1));
    }
    let count = (first & 0x7f) as usize;
    if count == 0 || count > 2 || input.len() < count + 1 {
        return Err(invalid("DER length is invalid"));
    }
    let mut length = 0_usize;
    for byte in &input[1..=count] {
        length = length * 256 + usize::from(*byte);
    }
    Ok((length, count + 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(value: &str) -> Vec<u8> {
        (0..value.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn derives_sha256_keys() {
        let key = derive(b"1234", 3);
        assert_eq!(
            cardpeek_core::ByteString::from_bytes(key.to_vec()).to_hex(),
            "02C86B0C110284C00B9C28408F95E6E27FFDC5A315E7F95C7C892FDBC33B6EA7"
        );
    }

    #[test]
    fn computes_nist_aes_cmac_vector() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c, 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c,
        ];
        let mac = aes_cmac(&key, &[]);
        assert_eq!(
            cardpeek_core::ByteString::from_bytes(mac.to_vec()).to_hex(),
            "D972DDE7E51B27703D7BDCC79A99B82B"
        );
    }

    #[test]
    fn completes_a_deterministic_handshake() {
        let nonce = hex("0102030405060708090A0B0C0D0E0F10");
        let mut scalar = [0_u8; POINT_SIZE];
        scalar[POINT_SIZE - 1] = 2;
        let card_mapping = decode_secret(&scalar).unwrap();
        scalar[POINT_SIZE - 1] = 3;
        let card_ephemeral = decode_secret(&scalar).unwrap();
        let mut session = Session::new(
            "can",
            b"123456",
            Some(&scalar_from(4)),
            Some(&scalar_from(5)),
        )
        .unwrap();

        let command = session.handshake(None).unwrap().unwrap();
        assert_eq!(command[0], 0x00);
        assert_eq!(&command[1..4], &[0x22, 0xc1, 0xa4]);
        assert!(command.ends_with(&[0x84, 0x01, 0x0d]));

        let command = session
            .handshake(Some((Vec::new(), 0x9000)))
            .unwrap()
            .unwrap();
        assert_eq!(command, general_authenticate(&tlv(0x7c, &[]), true));
        let encrypted_nonce = aes_cbc(true, &derive(b"123456", 3), &[0; AES_BLOCK], &nonce);
        let command = session
            .handshake(Some((tlv(0x7c, &tlv(0x80, &encrypted_nonce)), 0x9000)))
            .unwrap()
            .unwrap();
        let terminal_mapping = public_bytes(&session.mapping_secret);
        assert_eq!(
            command,
            general_authenticate(&tlv(0x7c, &tlv(0x81, &terminal_mapping)), true)
        );

        let card_mapping_public = public_bytes(&card_mapping);
        let command = session
            .handshake(Some((tlv(0x7c, &tlv(0x82, &card_mapping_public)), 0x9000)))
            .unwrap()
            .unwrap();
        let mapped_generator =
            map_generator(&session.mapping_secret, &card_mapping.public_key(), &nonce).unwrap();
        let terminal_point = mapped_generator * *session.ephemeral_secret.to_nonzero_scalar();
        let expected_public = terminal_point
            .to_affine()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();
        assert_eq!(session.ephemeral_public, expected_public);
        assert_eq!(
            command,
            general_authenticate(&tlv(0x7c, &tlv(0x83, &expected_public)), true)
        );

        let card_ephemeral_point = mapped_generator * *card_ephemeral.to_nonzero_scalar();
        let card_ephemeral_public = card_ephemeral_point
            .to_affine()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();
        let command = session
            .handshake(Some((
                tlv(0x7c, &tlv(0x84, &card_ephemeral_public)),
                0x9000,
            )))
            .unwrap()
            .unwrap();
        let card_shared_point = terminal_point * *card_ephemeral.to_nonzero_scalar();
        let mut card_shared = [0_u8; POINT_SIZE];
        card_shared.copy_from_slice(card_shared_point.to_affine().x().as_slice());
        assert_eq!(session.encryption_key, derive(&card_shared, 1));
        assert_eq!(session.authentication_key, derive(&card_shared, 2));
        let terminal_token =
            authentication_token(&session.authentication_key, &card_ephemeral_public);
        assert_eq!(
            command,
            general_authenticate(&tlv(0x7c, &tlv(0x85, &terminal_token)), false)
        );
        let card_token =
            authentication_token(&session.authentication_key, &session.ephemeral_public);
        assert!(
            session
                .handshake(Some((tlv(0x7c, &tlv(0x86, &card_token)), 0x9000)))
                .unwrap()
                .is_none()
        );
        assert!(session.protect(&hex("00A4020C020102")).is_ok());
    }

    #[test]
    fn rejects_an_invalid_card_token() {
        let mut session = Session::new(
            "can",
            b"123456",
            Some(&scalar_from(4)),
            Some(&scalar_from(5)),
        )
        .unwrap();
        session.handshake(None).unwrap();
        session.handshake(Some((Vec::new(), 0x9000))).unwrap();
        let encrypted_nonce = aes_cbc(
            true,
            &derive(b"123456", 3),
            &[0; AES_BLOCK],
            &[7; AES_BLOCK],
        );
        session
            .handshake(Some((tlv(0x7c, &tlv(0x80, &encrypted_nonce)), 0x9000)))
            .unwrap();
        session
            .handshake(Some((
                tlv(
                    0x7c,
                    &tlv(
                        0x82,
                        &public_bytes(&decode_secret(&scalar_from(2)).unwrap()),
                    ),
                ),
                0x9000,
            )))
            .unwrap();
        session
            .handshake(Some((
                tlv(
                    0x7c,
                    &tlv(
                        0x84,
                        &public_bytes(&decode_secret(&scalar_from(3)).unwrap()),
                    ),
                ),
                0x9000,
            )))
            .unwrap();
        assert!(
            session
                .handshake(Some((tlv(0x7c, &tlv(0x86, &[0; 8])), 0x9000)))
                .is_err()
        );
    }

    #[test]
    fn protects_commands_and_unprotects_a_response() {
        let mut session = Session::new(
            "can",
            b"123456",
            Some(&scalar_from(4)),
            Some(&scalar_from(5)),
        )
        .unwrap();
        session.encryption_key = derive(b"secret", 1);
        session.authentication_key = derive(b"secret", 2);
        session.stage = Stage::Ready;
        let protected = session.protect(&hex("00A4020C02010200")).unwrap();
        assert_eq!(protected[0], 0x0c);
        assert!(
            protected.windows(2).any(|window| window == [0x97, 0x01])
                && protected.ends_with(&[0x00])
        );
        let protected = session.protect(&hex("00B0000000")).unwrap();
        assert!(
            protected
                .windows(3)
                .any(|window| window == [0x97, 0x01, 0x00])
        );
        let protected = session.protect(&hex("00B00000")).unwrap();
        assert!(!protected.windows(2).any(|window| window == [0x97, 0x01]));

        let mut card = Session::new(
            "can",
            b"123456",
            Some(&scalar_from(4)),
            Some(&scalar_from(5)),
        )
        .unwrap();
        card.encryption_key = session.encryption_key;
        card.authentication_key = session.authentication_key;
        card.sequence = session.sequence;
        card.increment_sequence().unwrap();
        let status = [0x90, 0x00];
        let mut mac_input = card.sequence.to_vec();
        mac_input.extend_from_slice(&tlv(0x99, &status));
        let mac = aes_cmac(&card.authentication_key, &iso_pad(&mac_input));
        let response = [tlv(0x99, &status), tlv(0x8e, &mac[..8]), status.to_vec()].concat();
        let (data, status) = session.unprotect(&response).unwrap();
        assert_eq!(data, Vec::<u8>::new());
        assert_eq!(status, 0x9000);
        let mut tampered = response;
        let index = tampered.iter().position(|byte| *byte == 0x8e).unwrap() + 3;
        tampered[index] ^= 1;
        assert!(session.unprotect(&tampered).is_err());
    }

    fn scalar_from(value: u8) -> Vec<u8> {
        let mut scalar = vec![0_u8; POINT_SIZE];
        scalar[POINT_SIZE - 1] = value;
        scalar
    }
}
