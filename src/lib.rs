pub mod bls;

pub type Error = failure::Error;
pub type Result<T> = std::result::Result<T, Error>;

#[macro_export]
macro_rules! fail {
    ($error:literal) => {
        return Err(failure::err_msg(format!("{} {}:{}", $error, file!(), line!())))
    };
    // uncomment to explicit panic for any ExceptionCode
    // (ExceptionCode::CellUnderflow) => {
    //     panic!("{}", error!(ExceptionCode::CellUnderflow))
    // };
    ($error:expr) => {
        return Err(error!($error))
    };
    ($fmt:expr, $($arg:tt)*) => {
        return Err(failure::err_msg(format!("{} {}:{}", format!($fmt, $($arg)*), file!(), line!())))
    };
}

