extern crate cf_modkit_errors;

use cf_modkit_errors::resource_error;

#[resource_error("gts.cf.core.users.user.v1~")]
struct UserResourceError;

fn main() {
    // out_of_range requires .with_field_violation() before .create()
    let _err = UserResourceError::out_of_range("Page out of range")
        .create();
}
