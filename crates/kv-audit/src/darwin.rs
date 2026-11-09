//! The Darwin ACL API is descriptor based; pathname helpers cannot safely
//! replace it while an audit directory or child name can be renamed.
#![allow(unsafe_code)]

use std::ffi::{c_int, c_void};
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::ptr::NonNull;

const ACL_TYPE_EXTENDED: c_int = 0x100;
const ACL_FIRST_ENTRY: c_int = 0;
const FILESEC_ACL: c_int = 5;

unsafe extern "C" {
    fn acl_get_fd_np(fd: c_int, kind: c_int) -> *mut c_void;
    fn acl_get_entry(acl: *mut c_void, entry_id: c_int, entry: *mut *mut c_void) -> c_int;
    fn acl_free(pointer: *mut c_void) -> c_int;
    fn filesec_init() -> *mut c_void;
    fn filesec_set_property(filesec: *mut c_void, property: c_int, value: *const c_void) -> c_int;
    fn fchmodx_np(fd: c_int, filesec: *mut c_void) -> c_int;
    fn filesec_free(filesec: *mut c_void);
}

struct Acl(NonNull<c_void>);
impl Drop for Acl {
    fn drop(&mut self) {
        // SAFETY: acl_get_fd_np allocated this non-null ACL; this owner frees it once.
        unsafe {
            acl_free(self.0.as_ptr());
        }
    }
}

struct FileSecurity(NonNull<c_void>);
impl Drop for FileSecurity {
    fn drop(&mut self) {
        // SAFETY: filesec_init allocated this non-null object, exclusively owned here.
        unsafe {
            filesec_free(self.0.as_ptr());
        }
    }
}

pub(super) fn has_acl(file: &File) -> io::Result<bool> {
    // SAFETY: the File remains borrowed and open for the call. No memory pointer
    // is passed in; the returned allocation is transferred to the RAII owner.
    let pointer = unsafe {
        // __error returns this thread's valid errno slot. Python resets it too,
        // so a null result without an errno cannot inherit an unrelated error.
        *libc::__error() = 0;
        acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED)
    };
    let Some(pointer) = NonNull::new(pointer) else {
        let error = io::Error::last_os_error();
        return if error
            .raw_os_error()
            .is_some_and(|code| [libc::ENOENT, libc::ENOTSUP, libc::EOPNOTSUPP].contains(&code))
        {
            Ok(false)
        } else {
            Err(error)
        };
    };
    let acl = Acl(pointer);
    let mut entry = std::ptr::null_mut();
    // SAFETY: acl is a live ACL object and entry is valid writable pointer storage.
    // Darwin returns -1 when no first entry exists, matching the Python helper.
    Ok(unsafe { acl_get_entry(acl.0.as_ptr(), ACL_FIRST_ENTRY, &mut entry) } != -1)
}

pub(super) fn clear_acl(file: &File) -> io::Result<()> {
    if !has_acl(file)? {
        return Ok(());
    }
    // SAFETY: no arguments; a non-null result transfers ownership to this scope.
    let security =
        FileSecurity(NonNull::new(unsafe { filesec_init() }).ok_or_else(io::Error::last_os_error)?);
    // FILESEC_REMOVE_ACL is the documented sentinel (void *)1, not a pointer
    // that the API dereferences. The filesec object is live and exclusively held.
    let remove_acl = std::ptr::without_provenance::<c_void>(1);
    // SAFETY: these are the documented property, sentinel, and allocated object.
    if unsafe { filesec_set_property(security.0.as_ptr(), FILESEC_ACL, remove_acl) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: File and filesec object both remain alive for the call; only ACL
    // properties were set, so this cannot redirect a pathname or close the fd.
    if unsafe { fchmodx_np(file.as_raw_fd(), security.0.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if has_acl(file)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "audit ACL removal failed",
        ));
    }
    Ok(())
}
