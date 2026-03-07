pub(crate) mod apikey_auth;
pub(crate) mod noop_auth;
pub(crate) mod oauth2_client_cred_auth;
pub(crate) mod registry;

pub(crate) use registry::AuthPluginRegistry;
