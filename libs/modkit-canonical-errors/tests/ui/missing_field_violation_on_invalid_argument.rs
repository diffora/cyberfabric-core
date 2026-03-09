extern crate cf_modkit_errors;

use cf_modkit_errors::resource_error;

#[resource_error("gts.cf.core.users.user.v1~")]
struct UserResourceError;

fn main() {
    // invalid_argument requires at least one .with_field_violation() before .create()
    let _err = UserResourceError::invalid_argument()
        .create();
}
