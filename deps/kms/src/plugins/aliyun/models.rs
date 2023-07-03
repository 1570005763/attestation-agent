use std::{collections::HashMap, any::Any};

use reqwest::header::HeaderMap;

#[derive(Clone, Debug, Default)]
pub struct EncryptRequest {
    pub request_headers: HeaderMap,
    pub key_id: Option<String>,
    pub plaintext: Option<Vec<u8>>,
    pub algorithm: Option<String>,
    pub aad: Option<Vec<u8>>,
    pub iv: Option<Vec<u8>>,
    pub padding_mode: Option<String>,
}

impl EncryptRequest {
    pub fn new(
        key_id: Option<String>,
        plaintext: Option<Vec<u8>>,
        algorithm: Option<String>,
        aad: Option<Vec<u8>>,
        iv: Option<Vec<u8>>,
        padding_mode: Option<String>,
    ) -> EncryptRequest {
        EncryptRequest {
            request_headers: HeaderMap::new(),
            key_id,
            plaintext,
            algorithm,
            aad,
            iv,
            padding_mode,
        }
    }

    pub fn validate(&self) {
        // implement validation logic here
    }

    pub fn to_map(&self) -> HashMap<String, Box<dyn Any>> {
        let mut result: HashMap<String, Box<dyn Any>>  = HashMap::new();
        if let Some(key_id) = &self.key_id {
            result.insert("KeyId".to_string(), Box::new(key_id.to_string()));
        }
        if let Some(plaintext) = &self.plaintext {
            result.insert("Plaintext".to_string(), Box::new(plaintext.to_vec()));
        }
        if let Some(algorithm) = &self.algorithm {
            result.insert("Algorithm".to_string(), Box::new(algorithm.to_string()));
        }
        if let Some(aad) = &self.aad {
            result.insert("Aad".to_string(), Box::new(aad.to_vec()));
        }
        if let Some(iv) = &self.iv {
            result.insert("Iv".to_string(), Box::new(iv.to_vec()));
        }
        if let Some(padding_mode) = &self.padding_mode {
            result.insert("PaddingMode".to_string(), Box::new(padding_mode.to_string()));
        }
        result
    }

    pub fn from_map(&mut self, m: HashMap<String, Box<dyn Any>>) -> &mut EncryptRequest {
        if let Some(key_id) = m.get("KeyId") {
            self.key_id = key_id.downcast_ref::<String>().cloned();
        }
        if let Some(plaintext) = m.get("Plaintext") {
            self.plaintext = plaintext.downcast_ref::<Vec<u8>>().cloned();
        }
        if let Some(algorithm) = m.get("Algorithm") {
            self.algorithm = algorithm.downcast_ref::<String>().cloned();
        }
        if let Some(aad) = m.get("Aad") {
            self.aad = aad.downcast_ref::<Vec<u8>>().cloned();
        }
        if let Some(iv) = m.get("Iv") {
            self.iv = iv.downcast_ref::<Vec<u8>>().cloned();
        }
        if let Some(padding_mode) = m.get("PaddingMode") {
            self.padding_mode = padding_mode.downcast_ref::<String>().cloned();
        }
        self
    }
}

#[derive(Clone, Debug, Default)]
pub struct EncryptResponse {
    pub response_headers: HeaderMap,
    pub key_id: Option<String>,
    pub ciphertext_blob: Option<Vec<u8>>,
    pub iv: Option<Vec<u8>>,
    pub algorithm: Option<String>,
    pub padding_mode: Option<String>,
    pub response_id: Option<String>,
}

impl EncryptResponse {
    pub fn new(
        key_id: Option<String>,
        ciphertext_blob: Option<Vec<u8>>,
        iv: Option<Vec<u8>>,
        algorithm: Option<String>,
        padding_mode: Option<String>,
        response_id: Option<String>,
    ) -> EncryptResponse {
        EncryptResponse {
            response_headers: HeaderMap::new(),
            key_id,
            ciphertext_blob,
            iv,
            algorithm,
            padding_mode,
            response_id,
        }
    }

    pub fn validate(&self) {
        // implement validation logic here
    }

    pub fn to_map(&self) -> HashMap<String,Box<dyn Any>> {
        let mut result: HashMap<String,Box<dyn Any>> = HashMap::new();
        if let Some(key_id) = &self.key_id {
            result.insert("KeyId".to_string(), Box::new(key_id.to_string()));
        }
        if let Some(ciphertext_blob) = &self.ciphertext_blob {
            result.insert("CiphertextBlob".to_string(), Box::new(ciphertext_blob.to_vec()));
        }
        if let Some(iv) = &self.iv {
            result.insert("Iv".to_string(), Box::new(iv.to_vec()));
        }
        if let Some(algorithm) = &self.algorithm {
            result.insert("Algorithm".to_string(), Box::new(algorithm.to_string()));
        }
        if let Some(padding_mode) = &self.padding_mode {
            result.insert("PaddingMode".to_string(), Box::new(padding_mode.to_string()));
        }
        if let Some(request_id) = &self.response_id {
            result.insert("RequestId".to_string(), Box::new(request_id.to_string()));
        }
        result
    }

    pub fn from_map(&mut self, m: HashMap<String, Box<dyn Any>>) -> &mut EncryptResponse {
        if let Some(key_id) = m.get("KeyId") {
            self.key_id = key_id.downcast_ref::<String>().cloned();
        }
        if let Some(ciphertext_blob) = m.get("CiphertextBlob") {
            self.ciphertext_blob = ciphertext_blob.downcast_ref::<Vec<u8>>().cloned();
        }
        if let Some(iv) = m.get("Iv") {
            self.iv = iv.downcast_ref::<Vec<u8>>().cloned();
        }
        if let Some(algorithm) = m.get("Algorithm") {
            self.algorithm = algorithm.downcast_ref::<String>().cloned();
        }
        if let Some(padding_mode) = m.get("PaddingMode") {
            self.padding_mode = padding_mode.downcast_ref::<String>().cloned();
        }
        if let Some(request_id) = m.get("RequestId") {
            self.response_id = request_id.downcast_ref::<String>().cloned();
        }
        self
    }
}

#[derive(Clone, Debug, Default)]
pub struct DecryptRequest {
    pub request_headers: HeaderMap,
    pub key_id: Option<String>,
    pub ciphertext_blob: Option<Vec<u8>>,
    pub algorithm: Option<String>,
    pub aad: Option<Vec<u8>>,
    pub iv: Option<Vec<u8>>,
    pub padding_mode: Option<String>,
}

impl DecryptRequest {
    pub fn new(
        key_id: Option<String>,
        ciphertext_blob: Option<Vec<u8>>,
        algorithm: Option<String>,
        aad: Option<Vec<u8>>,
        iv: Option<Vec<u8>>,
        padding_mode: Option<String>,
    ) -> DecryptRequest {
        DecryptRequest {
            request_headers: HeaderMap::new(),
            key_id,
            ciphertext_blob,
            algorithm,
            aad,
            iv,
            padding_mode,
        }
    }

    pub fn validate(&self) {
        // implement validation logic here
    }

    pub fn to_map(&self) -> HashMap<String, Box<dyn Any>> {
        let mut result: HashMap<String, Box<dyn Any>> = HashMap::new();
        if let Some(ciphertext_blob) = &self.ciphertext_blob {
            result.insert("CiphertextBlob".to_string(), Box::new(ciphertext_blob.to_vec()));
        }
        if let Some(key_id) = &self.key_id {
            result.insert("KeyId".to_string(), Box::new(key_id.to_string()));
        }
        if let Some(algorithm) = &self.algorithm {
            result.insert("Algorithm".to_string(), Box::new(algorithm.to_string()));
        }
        if let Some(aad) = &self.aad {
            result.insert("Aad".to_string(), Box::new(aad.to_vec()));
        }
        if let Some(iv) = &self.iv {
            result.insert("Iv".to_string(), Box::new(iv.to_vec()));
        }
        if let Some(padding_mode) = &self.padding_mode {
            result.insert("PaddingMode".to_string(), Box::new(padding_mode.to_string()));
        }
        result
    }

    pub fn from_map(&mut self, m: HashMap<String, Box<dyn Any>>) -> &mut DecryptRequest {
        if let Some(ciphertext_blob) = m.get("CiphertextBlob") {
            self.ciphertext_blob = ciphertext_blob.downcast_ref::<Vec<u8>>().cloned();
        }
        if let Some(key_id) = m.get("KeyId") {
            self.key_id = key_id.downcast_ref::<String>().cloned();
        }
        if let Some(algorithm) = m.get("Algorithm") {
            self.algorithm = algorithm.downcast_ref::<String>().cloned();
        }
        if let Some(aad) = m.get("Aad") {
            self.aad = aad.downcast_ref::<Vec<u8>>().cloned();
        }
        if let Some(iv) = m.get("Iv") {
            self.iv = iv.downcast_ref::<Vec<u8>>().cloned();
        }
        if let Some(padding_mode) = m.get("PaddingMode") {
            self.padding_mode = padding_mode.downcast_ref::<String>().cloned();
        }
        self
    }
}

#[derive(Clone, Debug, Default)]
pub struct DecryptResponse {
    pub response_headers: HeaderMap,
    pub key_id: Option<String>,
    pub plaintext: Option<Vec<u8>>,
    pub algorithm: Option<String>,
    pub padding_mode: Option<String>,
    pub request_id: Option<String>,
}

impl DecryptResponse {
    pub fn new(
        key_id: Option<String>,
        plaintext: Option<Vec<u8>>,
        algorithm: Option<String>,
        padding_mode: Option<String>,
        request_id: Option<String>,
    ) -> DecryptResponse {
        DecryptResponse {
            response_headers: HeaderMap::new(),
            key_id,
            plaintext,
            algorithm,
            padding_mode,
            request_id,
        }
    }

    pub fn validate(&self) {
        // implement validation logic here
    }

    pub fn to_map(&self) -> HashMap<String, Box<dyn Any>> {
        let mut result: HashMap<String, Box<dyn Any>> = HashMap::new();
        if let Some(key_id) = &self.key_id {
            result.insert("KeyId".to_string(), Box::new(key_id.to_string()));
        }
        if let Some(plaintext) = &self.plaintext {
            result.insert("Plaintext".to_string(), Box::new(plaintext.to_vec()));
        }
        if let Some(algorithm) = &self.algorithm {
            result.insert("Algorithm".to_string(), Box::new(algorithm.to_string()));
        }
        if let Some(padding_mode) = &self.padding_mode {
            result.insert("PaddingMode".to_string(), Box::new(padding_mode.to_string()));
        }
        if let Some(request_id) = &self.request_id {
            result.insert("RequestId".to_string(), Box::new(request_id.to_string()));
        }
        result
    }

    pub fn from_map(&mut self, m: HashMap<String, Box<dyn Any>>) -> &mut DecryptResponse {
        if let Some(key_id) = m.get("KeyId") {
            self.key_id = key_id.downcast_ref::<String>().cloned();
        }
        if let Some(plaintext) = m.get("Plaintext") {
            self.plaintext = plaintext.downcast_ref::<Vec<u8>>().cloned();
        }
        if let Some(algorithm) = m.get("Algorithm") {
            self.algorithm = algorithm.downcast_ref::<String>().cloned();
        }
        if let Some(padding_mode) = m.get("PaddingMode") {
            self.padding_mode = padding_mode.downcast_ref::<String>().cloned();
        }
        if let Some(request_id) = m.get("RequestId") {
            self.request_id = request_id.downcast_ref::<String>().cloned();
        }
        self
    }
}