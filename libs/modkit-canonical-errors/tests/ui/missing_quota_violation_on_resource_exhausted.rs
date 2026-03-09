extern crate cf_modkit_errors;

use cf_modkit_errors::resource_error;

#[resource_error("gts.cf.core.users.user.v1~")]
struct UserResourceError;

fn main() {
    // resource_exhausted requires at least one .with_quota_violation() before .create()
    let _err = UserResourceError::resource_exhausted("Quota exceeded")
        .create();
}
