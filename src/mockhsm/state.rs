//! `MockHSM` presents a thread-safe API by locking interior mutable state,
//! contained in the `State` struct defined in this module.

use sha2::Sha512;
use std::collections::HashMap;

use super::objects::{Object, Objects};
use commands::*;
use connector::ConnectorError;
use responses::*;
use securechannel::{Challenge, Channel, CommandMessage, CommandType, ResponseMessage, StaticKeys};
use serializers::deserialize;
use session::{PBKDF2_ITERATIONS, PBKDF2_SALT};
use {Algorithm, ObjectId, ObjectType, SessionId};

/// Default auth key ID slot
const DEFAULT_AUTH_KEY_ID: ObjectId = 1;

/// Default password
const DEFAULT_PASSWORD: &str = "password";

/// Mutable interior state of the `MockHSM`
pub(crate) struct State {
    static_keys: StaticKeys,
    sessions: HashMap<SessionId, Channel>,
    objects: Objects,
}

impl State {
    /// Create a new instance of the server's mutable interior state
    pub fn new() -> Self {
        Self {
            static_keys: StaticKeys::derive_from_password(
                DEFAULT_PASSWORD.as_bytes(),
                PBKDF2_SALT,
                PBKDF2_ITERATIONS,
            ),
            sessions: HashMap::new(),
            objects: Objects::new(),
        }
    }

    /// Create a new HSM session
    pub fn create_session(
        &mut self,
        cmd_message: &CommandMessage,
    ) -> Result<Vec<u8>, ConnectorError> {
        let cmd: CreateSessionCommand = deserialize(cmd_message.data.as_ref())
            .unwrap_or_else(|e| panic!("error parsing CreateSession command data: {:?}", e));

        assert_eq!(
            cmd.auth_key_id, DEFAULT_AUTH_KEY_ID,
            "unexpected auth key ID: {}",
            cmd.auth_key_id
        );

        // Generate a random card challenge to send back to the client
        let card_challenge = Challenge::random();

        let session_id = self
            .sessions
            .keys()
            .max()
            .map(|id| id.succ().expect("session count exceeded"))
            .unwrap_or_else(|| SessionId::new(0).unwrap());

        let channel = Channel::new(
            session_id,
            &self.static_keys,
            cmd.host_challenge,
            card_challenge,
        );

        let card_cryptogram = channel.card_cryptogram();
        assert!(self.sessions.insert(session_id, channel).is_none());

        let mut response = CreateSessionResponse {
            card_challenge,
            card_cryptogram,
        }.serialize();

        response.session_id = Some(session_id);
        Ok(response.into())
    }

    /// Authenticate an HSM session
    pub fn authenticate_session(
        &mut self,
        command: &CommandMessage,
    ) -> Result<Vec<u8>, ConnectorError> {
        let session_id = command
            .session_id
            .unwrap_or_else(|| panic!("no session ID in command: {:?}", command.command_type));

        Ok(self
            .channel(session_id)
            .verify_authenticate_session(command)
            .unwrap()
            .into())
    }

    /// Encrypted session messages
    pub fn session_message(
        &mut self,
        encrypted_command: CommandMessage,
    ) -> Result<Vec<u8>, ConnectorError> {
        let session_id = encrypted_command.session_id.unwrap_or_else(|| {
            panic!(
                "no session ID in command: {:?}",
                encrypted_command.command_type
            )
        });

        let command = self
            .channel(session_id)
            .decrypt_command(encrypted_command)
            .unwrap();

        let response = match command.command_type {
            CommandType::DeleteObject => self.delete_object(&command.data),
            CommandType::Echo => self.echo(&command.data),
            CommandType::GenAsymmetricKey => self.gen_asymmetric_key(&command.data),
            CommandType::GetObjectInfo => self.get_object_info(&command.data),
            CommandType::GetPubKey => self.get_pubkey(&command.data),
            CommandType::ListObjects => self.list_objects(&command.data),
            CommandType::SignDataEdDSA => self.sign_data_eddsa(&command.data),
            unsupported => panic!("unsupported command type: {:?}", unsupported),
        };

        Ok(self
            .channel(session_id)
            .encrypt_response(response)
            .unwrap()
            .into())
    }

    /// Delete an object
    fn delete_object(&mut self, cmd_data: &[u8]) -> ResponseMessage {
        let command: DeleteObjectCommand = deserialize(cmd_data)
            .unwrap_or_else(|e| panic!("error parsing CommandType::DeleteObject: {:?}", e));

        match command.object_type {
            // TODO: support other asymmetric keys besides Ed25519 keys
            ObjectType::Asymmetric => match self.objects.ed25519_keys.remove(&command.object_id) {
                Some(_) => DeleteObjectResponse {}.serialize(),
                None => {
                    ResponseMessage::error(&format!("no such object ID: {:?}", command.object_id))
                }
            },
            _ => panic!("MockHSM only supports delete_object for ObjectType::Asymmetric"),
        }
    }

    /// Echo a message back to the host
    fn echo(&self, cmd_data: &[u8]) -> ResponseMessage {
        EchoResponse {
            message: cmd_data.into(),
        }.serialize()
    }

    /// Generate a new random asymmetric key
    fn gen_asymmetric_key(&mut self, cmd_data: &[u8]) -> ResponseMessage {
        let command: GenAsymmetricKeyCommand = deserialize(cmd_data)
            .unwrap_or_else(|e| panic!("error parsing CommandType::GetObjectInfo: {:?}", e));

        match command.algorithm {
            Algorithm::EC_ED25519 => {
                let key = Object::new(command.label, command.capabilities, command.domains);
                assert!(
                    self.objects
                        .ed25519_keys
                        .insert(command.key_id, key)
                        .is_none()
                );
            }
            other => panic!("unsupported algorithm: {:?}", other),
        }

        GenAsymmetricKeyResponse {
            key_id: command.key_id,
        }.serialize()
    }

    /// Get detailed info about a specific object
    fn get_object_info(&self, cmd_data: &[u8]) -> ResponseMessage {
        let command: GetObjectInfoCommand = deserialize(cmd_data)
            .unwrap_or_else(|e| panic!("error parsing CommandType::GetObjectInfo: {:?}", e));

        if command.object_type != ObjectType::Asymmetric {
            panic!("MockHSM only supports ObjectType::Asymmetric for now");
        }

        // TODO: support other asymmetric keys besides Ed25519 keys
        match self.objects.ed25519_keys.get(&command.object_id) {
            Some(key) => GetObjectInfoResponse {
                capabilities: key.capabilities,
                id: command.object_id,
                length: key.length,
                domains: key.domains,
                object_type: key.object_type,
                algorithm: key.algorithm,
                sequence: key.sequence,
                origin: key.origin,
                label: key.label.clone(),
                delegated_capabilities: key.delegated_capabilities,
            }.serialize(),
            None => ResponseMessage::error(&format!("no such object ID: {:?}", command.object_id)),
        }
    }

    /// Get the public key associated with a key in the HSM
    fn get_pubkey(&self, cmd_data: &[u8]) -> ResponseMessage {
        let command: GetPubKeyCommand = deserialize(cmd_data)
            .unwrap_or_else(|e| panic!("error parsing CommandType::GetPubKey: {:?}", e));

        // TODO: support other asymmetric keys besides Ed25519 keys
        match self.objects.ed25519_keys.get(&command.key_id) {
            Some(key) => GetPubKeyResponse {
                algorithm: Algorithm::EC_ED25519,
                data: Vec::from(key.value.public.as_bytes().as_ref()),
            }.serialize(),
            None => ResponseMessage::error(&format!("no such object ID: {:?}", command.key_id)),
        }
    }

    /// List all objects presently accessible to a session
    fn list_objects(&self, cmd_data: &[u8]) -> ResponseMessage {
        // TODO: filter support
        let _command: ListObjectsCommand = deserialize(cmd_data)
            .unwrap_or_else(|e| panic!("error parsing CommandType::ListObjects: {:?}", e));

        // TODO: support other asymmetric keys besides Ed25519 keys
        let list_entries = self
            .objects
            .ed25519_keys
            .iter()
            .map(|(object_id, object)| ListObjectsEntry {
                id: *object_id,
                object_type: object.object_type,
                sequence: object.sequence,
            })
            .collect();

        ListObjectsResponse {
            objects: list_entries,
        }.serialize()
    }

    /// Sign a message using the Ed25519 signature algorithm
    fn sign_data_eddsa(&self, cmd_data: &[u8]) -> ResponseMessage {
        let command: SignDataEdDSACommand = deserialize(cmd_data)
            .unwrap_or_else(|e| panic!("error parsing CommandType::SignDataEdDSA: {:?}", e));

        // TODO: support other asymmetric keys besides Ed25519 keys
        match self.objects.ed25519_keys.get(&command.key_id) {
            Some(key) => {
                let signature = key.value.sign::<Sha512>(command.data.as_ref()).to_bytes();
                SignDataEdDSAResponse {
                    signature: Vec::from(signature.as_ref()),
                }.serialize()
            }
            None => ResponseMessage::error(&format!("no such object ID: {:?}", command.key_id)),
        }
    }

    /// Obtain the channel for a session by its ID
    fn channel(&mut self, id: SessionId) -> &mut Channel {
        self.sessions
            .get_mut(&id)
            .unwrap_or_else(|| panic!("invalid session ID: {:?}", id))
    }
}
