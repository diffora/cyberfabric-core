extern crate cf_modkit_errors;

use cf_modkit_errors::resource_error;

fn main() {
    // aborted requires .with_reason() before .create()
    #[resource_error("gts.cf.core.users.user.v1~")]
    struct UserResourceError;

    let _err = UserResourceError::aborted("Operation aborted due to concurrency conflict")
        .create();
}
