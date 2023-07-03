use anyhow::*;
use serde_json::Value;
use std::fs;

use openssl::pkcs12::Pkcs12;
use openssl::sign::Signer;

pub struct Client {
    access_key_id: String,
    access_key_secret: String,
    password: String,
}

impl Client {
    pub fn new(client_key_file: &String, password: &String) -> Result<Self> {
        let (access_key_id, access_key_secret) = Self::get_client_key(client_key_file)?;
        Ok(Self {
            access_key_id,
            access_key_secret,
            password: password.to_string()
        })
    }

    fn get_client_key(client_key_file: &String) -> Result<(String, String)> {
        // use std::env;
        // let current_dir = env::current_dir().unwrap();
        // println!("Current directory: {}", current_dir.display());

        // let file = format!("deps/kms/src/plugins/aliyun/util/key/{}", client_key_file);
        let file = format!("src/plugins/aliyun/util/key/{}", client_key_file);
        let load_file = fs::File::open(file)?;
        let json_data: Value = serde_json::from_reader(load_file)?;
        let key_id = json_data["KeyId"].as_str().ok_or_else(||anyhow!("no KeyId"))?.to_owned();
        let key_secret = json_data["PrivateKeyData"].as_str().ok_or_else(||anyhow!("no PrivateKeyData"))?.to_owned();
        Ok((key_id, key_secret))
    }

    pub fn get_access_key_id(&self) -> String {
        self.access_key_id.clone()
    }

    fn get_access_key_secret(&self) -> String {
        self.access_key_secret.clone()
    }

    pub fn get_signature(&self, str_to_sign: &str) -> Result<String> {
        let private_key_der = base64::decode(self.access_key_secret.as_bytes())?;
        let pkcs12 = Pkcs12::from_der(&private_key_der)?;
        println!("load private_key success");
        let parsed = pkcs12.parse2(&self.password)?;
        let private_key = parsed.pkey.ok_or_else(||anyhow!("no pkey"))?;
        println!("parse private_key success");

        let mut signer = Signer::new(
            openssl::hash::MessageDigest::sha256(),
            &private_key,
        )?;
        signer.update(str_to_sign.as_bytes())?;
        let signature = signer.sign_to_vec()?;

        // Ok(format!("TOKEN {}", base64::encode(signature)))
        Ok(format!("Bearer {}", base64::encode(signature)))
    }


    fn format_private_key(&self, private_key: &str) -> String {
        let pem_begin: &str = "-----BEGIN RSA PRIVATE KEY-----\n";
        let pem_end: &str = "\n-----END RSA PRIVATE KEY-----";

        let mut formatted_key = private_key.to_string();
        if !formatted_key.starts_with(pem_begin) {
            formatted_key = format!("{}{}", pem_begin, formatted_key);
        }
        if !formatted_key.ends_with(pem_end) {
            formatted_key = format!("{}{}", formatted_key, pem_end);
        }
        formatted_key
    }
}
