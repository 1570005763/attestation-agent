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
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

use crate::KMS;

mod client;
mod models;
mod config;
mod util;

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
        let key_id = "key-shh64705d53mly8ubf1yx".to_owned();
        Ok(key_id)
    }

    async fn encrypt(&mut self, data: &[u8], keyid: &str) -> Result<Vec<u8>> {
        // let mut req_map: HashMap<String, Box<dyn Any>> = HashMap::new();
        // req_map.insert("KeyId".to_string(), Box::new(keyid.to_string()));
        let request = EncryptRequest::new(
            Some(keyid.to_string()),
            Some(data.to_vec()),
            Some("AES_GCM".to_string()),
            None,
            None,
            None
        );
        // let request = EncryptRequest::default();
        // request.from_map(req_map);
        let response = self.client.encrypt(&request).await.context("client encryption")?;
        let data = response.ciphertext_blob.ok_or_else(|| anyhow!("encrypt response has no ciphertext_blob"))?;
        let iv = response.iv.ok_or_else(|| anyhow!("encrypt response has no iv"))?;
        let cp = Ciphertext { data, iv };
        Ok(serde_json::to_vec(&cp)?)
    }

    async fn decrypt(&mut self, ciphertext: &[u8], keyid: &str) -> Result<Vec<u8>> {
        let cp: Ciphertext = serde_json::from_slice(ciphertext)?;
        let request = DecryptRequest::new(
            Some(keyid.to_string()),
            Some(cp.data),
            Some("AES_GCM".to_string()),
            None,
            Some(cp.iv),
            None
        );
        let response = self.client.decrypt(&request).await?;
        let data = response.plaintext.ok_or_else(|| anyhow!("decrypt response has no plaintext"))?;
        Ok(data)
    }
}

impl SimpleAliyunKms {

}

impl SimpleAliyunKms {
    fn new(config: HashMap<String, String>) -> Self {
        Self {
            client: DKMSClient::new(config),
            // client: DKMSClient::new(
            //     // env::var("ACCESS_KEY_ID").unwrap(),
            //     // env::var("ACCESS_KEY_SECRET").unwrap(),
            //     key_id.to_owned(),
            //     key_secret.to_owned(),
            //     // "https://kst-shh64702cf2jvcw428tbd.cryptoservice.kms.aliyuncs.com/".to_owned(),
            //     "https://kms.cn-shanghai.aliyuncs.com/".to_owned(),
            // )
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use rstest::rstest;

    use crate::{plugins::aliyun::SimpleAliyunKms, KMS};

    #[rstest]
    #[case(b"this is a test plaintext")]
    #[case(b"this is a another test plaintext")]
    #[tokio::test]
    async fn key_lifetime(#[case] plaintext: &[u8]) {
        let config: HashMap<String, String> =
            [("client_key_file".to_string(), "clientKey_KAAP.f4c8****.json".to_string()),
            ("password".to_string(), "fa79****".to_string()),
            ("protocol".to_string(), "https".to_string()),
            ("endpoint".to_string(), "kst-shh6****.cryptoservice.kms.aliyuncs.com".to_string()),]
            .iter().cloned().collect();
        let mut kms = SimpleAliyunKms::new(config);

        let keyid = kms.generate_key().await.expect("generate key");
        let ciphertext = kms.encrypt(plaintext, &keyid).await.expect("encrypt");
        let decrypted = kms.decrypt(&ciphertext, &keyid).await.expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    // #[tokio::test]
    // async fn encrypt_with_an_non_existent_key() {
    //     let mut kms = SimpleAlibabaCloudKms::default();
    //     let ciphertext = kms.encrypt(b"a test text", "an-non-existent-key-id").await;
    //     assert!(ciphertext.is_err())
    // }

    // #[tokio::test]
    // async fn decrypt_with_an_non_existent_key() {
    //     let mut kms = SimpleAlibabaCloudKms::default();
    //     let keyid = kms.generate_key().await.expect("generate key");
    //     let ciphertext = kms.encrypt(b"a test text", &keyid).await.expect("encrypt");

    //     // Use a fake key id to decrypt
    //     let decrypted = kms.decrypt(&ciphertext, "an-non-existent-key-id").await;
    //     assert!(decrypted.is_err())
    // }
}
