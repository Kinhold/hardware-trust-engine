use crate::HteError;
use jni::objects::{JClass, JString};
use jni::sys::jstring;
use jni::JNIEnv;
use std::panic;

fn process_attestation_payload(input: String) -> Result<String, HteError> {
    if input.is_empty() {
        return Err(HteError::InvalidAttestationData(
            "input payload is empty".to_string(),
        ));
    }
    Err(HteError::Unsupported(
        "Android attestation processing is not implemented".to_string(),
    ))
}

#[no_mangle]
pub extern "system" fn Java_com_genspark_hte_HteBridge_processPayload(
    mut env: JNIEnv,
    _class: JClass,
    input: JString,
) -> jstring {
    let input_str = match env.get_string(&input) {
        Ok(s) => s.into(),
        Err(e) => {
            let _ = env.throw_new(
                "com/genspark/hte/HteNativeException",
                format!("Failed to get Java string: {}", e),
            );
            return std::ptr::null_mut();
        }
    };

    let result = panic::catch_unwind(|| process_attestation_payload(input_str));

    match result {
        Ok(Ok(output)) => match env.new_string(output) {
            Ok(s) => s.into_raw(),
            Err(e) => {
                let _ = env.throw_new(
                    "com/genspark/hte/HteNativeException",
                    format!("Failed to create Java string: {}", e),
                );
                std::ptr::null_mut()
            }
        },
        Ok(Err(e)) => {
            let _ = env.throw_new(
                "com/genspark/hte/HteNativeException",
                format!("Native error: {}", e),
            );
            std::ptr::null_mut()
        }
        Err(_) => {
            let _ = env.throw_new(
                "com/genspark/hte/HteNativeException",
                "Native code panicked!",
            );
            std::ptr::null_mut()
        }
    }
}
