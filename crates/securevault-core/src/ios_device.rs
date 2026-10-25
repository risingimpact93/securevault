//! iOS device name. UIDevice when UIKit is present, otherwise the Unix hostname.
//! Compiled only for `target_os = "ios"`.

/// `UIDevice.current.name`. Missing UIKit or an empty name returns `None`.
pub fn device_name() -> Option<String> {
    use objc2::msg_send;
    use objc2::rc::Retained;
    use objc2::runtime::{AnyClass, AnyObject};
    use objc2_foundation::NSString;

    unsafe {
        let class = AnyClass::get(c"UIDevice")?;
        let device: Retained<AnyObject> = msg_send![class, currentDevice];
        let name: Retained<NSString> = msg_send![&*device, name];
        let text = name.to_string();
        let trimmed = text.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    }
}

/// `gethostname`. The iOS sandbox often has no `hostname` binary.
pub fn host_name() -> Option<String> {
    let mut buf = [0u8; 256];
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if rc != 0 {
        return None;
    }
    let end = buf.iter().position(|byte| *byte == 0).unwrap_or(buf.len());
    let text = String::from_utf8_lossy(&buf[..end]).trim().to_string();
    if text.is_empty() || text == "localhost" {
        None
    } else {
        Some(text)
    }
}
