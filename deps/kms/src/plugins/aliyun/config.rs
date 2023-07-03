#[derive(Clone, Debug, Default)]
pub struct Config {
    api_name: String,
    api_version: String,
    protocol: String,
    endpoint: String,
    region_id: String,
    method: String,
    signature_method: String,
}