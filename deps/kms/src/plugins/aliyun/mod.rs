// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This is a Aliyun KMS implementation.
//!
//! Aliyun KMS uses KMS from Alibaba Cloud to support all functions.
//! The product detail can be found here: https://www.alibabacloud.com/product/kms.

// use std::collections::HashSet;

use anyhow::*;
use async_trait::async_trait;
use reqwest::header::HeaderMap;
use serde::{Deserialize, Serialize};

use crate::KMS;

mod client;
mod client_util;
mod config;
mod credential;
mod models;

use self::{config::Config, credential::Credential};
use client::Client as DKMSClient;
use models::*;

#[derive(Serialize, Deserialize)]
struct Ciphertext {
    data: Vec<u8>,
    iv: Vec<u8>,
}

/// A Aliyun KMS implementation
pub struct SimpleAliyunKms {
    client: DKMSClient,
}

#[async_trait]
impl KMS for SimpleAliyunKms {
    async fn generate_key(&mut self) -> Result<String> {
        // unimpliment, only for test
        let key_id = "key-shh6****".to_owned();
        Ok(key_id)
    }

    async fn encrypt(&mut self, data: &[u8], keyid: &str) -> Result<Vec<u8>> {
        // let mut req_map: HashMap<String, Box<dyn Any>> = HashMap::new();
        // req_map.insert("KeyId".to_string(), Box::new(keyid.to_string()));
        let request = EncryptRequest {
            request_headers: HeaderMap::new(),
            key_id: Some(keyid.to_string()),
            plaintext: Some(data.to_vec()),
            algorithm: Some("AES_GCM".to_string()),
            aad: None,
            iv: None,
            padding_mode: None,
        };

        // let request = EncryptRequest::default();
        // request.from_map(req_map);
        let response = self
            .client
            .encrypt(&request)
            .await
            .context("client encryption")?;
        let data = response
            .ciphertext_blob
            .ok_or_else(|| anyhow!("encrypt response has no ciphertext_blob"))?;
        let iv = response
            .iv
            .ok_or_else(|| anyhow!("encrypt response has no iv"))?;
        let cp = Ciphertext { data, iv };
        Ok(serde_json::to_vec(&cp)?)
    }

    async fn decrypt(&mut self, ciphertext: &[u8], keyid: &str) -> Result<Vec<u8>> {
        let cp: Ciphertext = serde_json::from_slice(ciphertext)?;
        let request = DecryptRequest {
            request_headers: HeaderMap::new(),
            key_id: Some(keyid.to_string()),
            ciphertext_blob: Some(cp.data),
            algorithm: Some("AES_GCM".to_string()),
            aad: None,
            iv: Some(cp.iv),
            padding_mode: None,
        };

        let response = self.client.decrypt(&request).await?;
        let data = response
            .plaintext
            .ok_or_else(|| anyhow!("decrypt response has no plaintext"))?;
        Ok(data)
    }
}

impl SimpleAliyunKms {}

impl SimpleAliyunKms {
    pub fn new(config: Config, credential: Credential) -> Self {
        Self {
            client: DKMSClient::new(config, credential),
        }
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use crate::{plugins::aliyun::SimpleAliyunKms, KMS};

    use super::{config::Config, credential::Credential};

    #[rstest]
    #[case(b"this is a test plaintext")]
    #[case(b"this is a another test plaintext")]
    #[tokio::test]
    async fn key_lifetime(#[case] plaintext: &[u8]) {
        let config = Config {
            protocol: "https".to_owned(),
            endpoint: "kst-shh6****.cryptoservice.kms.aliyuncs.com".to_owned(),
            region_id: "cn-shanghai".to_owned(),
            method: "POST".to_owned(),
            signature_method: "RSA_PKCS1_SHA_256".to_owned(),
        };
        let credential = Credential {
            key_file_dir: "src/plugins/aliyun/key".to_owned(),
            client_key_id: "KAAP.f4c8****".to_owned(),
        };
        let mut kms = SimpleAliyunKms::new(config, credential);

        let keyid = kms.generate_key().await.expect("generate key");
        let ciphertext = kms.encrypt(plaintext, &keyid).await.expect("encrypt");
        let decrypted = kms.decrypt(&ciphertext, &keyid).await.expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn encrypt_and_decrpty_with_different_keyid() {
        let config = Config {
            protocol: "https".to_owned(),
            endpoint: "kst-shh6****.cryptoservice.kms.aliyuncs.com".to_owned(),
            region_id: "cn-shanghai".to_owned(),
            method: "POST".to_owned(),
            signature_method: "RSA_PKCS1_SHA_256".to_owned(),
        };
        let credential = Credential {
            key_file_dir: "src/plugins/aliyun/key".to_owned(),
            client_key_id: "KAAP.f4c8****".to_owned(),
        };
        let mut kms = SimpleAliyunKms::new(config, credential);
        let plaintext = b"encrypt_and_decrpty_with_different_keyid";

        let keyid_1 = kms.generate_key().await.expect("generate key");
        let ciphertext = kms.encrypt(plaintext, &keyid_1).await.expect("encrypt");

        let keyid_2 = "key-shh6****".to_owned();
        let decrypted = kms.decrypt(&ciphertext, &keyid_2).await;

        assert!(decrypted.is_err())
    }
}
