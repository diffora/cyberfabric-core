extern crate cf_modkit_errors;

use cf_modkit_errors::resource_error;

#[resource_error("gts.cf.core.users.user.v1~")]
struct UserResourceError;

fn main() {
    // not_found requires .with_resource() before .create()
    let _err = UserResourceError::not_found("User not found")
        .create();
}
