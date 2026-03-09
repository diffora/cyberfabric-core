extern crate cf_modkit_errors;

use cf_modkit_errors::CanonicalError;

fn main() {
    // unauthenticated requires .with_reason() before .create()
    let _err = CanonicalError::unauthenticated()
        .create();
}
