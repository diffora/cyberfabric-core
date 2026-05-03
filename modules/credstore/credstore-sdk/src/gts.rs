use gts_macros::struct_to_gts_schema;
use modkit::gts::BaseModkitPluginV1;

#[struct_to_gts_schema(
    dir_path = "schemas",
    base = BaseModkitPluginV1,
    schema_id = "gts.cf.core.modkit.plugin.v1~cf.core.credstore.plugin.v1~",
    description = "CredStore plugin specification",
    properties = ""
)]
pub struct CredStorePluginSpecV1;
