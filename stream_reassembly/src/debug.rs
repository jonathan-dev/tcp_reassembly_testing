#[macro_export]
#[cfg(debug_assertions)]
macro_rules! debug_print {
    ($( $args:expr ),*) => { println!( $( $args ),* ); }
}

// Non-debug version
#[macro_export]
#[cfg(not(debug_assertions))]
macro_rules! debug_print {
    ($( $args:expr ),*) => {};
}
