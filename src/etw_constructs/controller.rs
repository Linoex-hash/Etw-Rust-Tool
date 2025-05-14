use core::slice;
use std::{
    ffi::{c_void, CStr},
    mem,
};

use windows::{
    core::PCSTR,
    Win32::{
        Foundation::{
            ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_BAD_LENGTH, ERROR_BAD_PATHNAME,
            ERROR_INVALID_PARAMETER, ERROR_NO_SYSTEM_RESOURCES, ERROR_SUCCESS,
            INVALID_HANDLE_VALUE,
        },
        System::Diagnostics::Etw::{
            ControlTraceA, StartTraceA, SystemTraceControlGuid, CONTROLTRACE_HANDLE,
            EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_FLAG_PROCESS, EVENT_TRACE_PROPERTIES,
            EVENT_TRACE_REAL_TIME_MODE, EVENT_TRACE_SYSTEM_LOGGER_MODE, WNODE_FLAG_TRACED_GUID,
            WNODE_HEADER,
        },
    },
};

pub struct Controller {
    trace_handle: CONTROLTRACE_HANDLE,
    session_name: &'static CStr, // This session name should be a global variable.
    event_prop_buf: Vec<u8>,
}

/// A Controller construct for windows ETW. Creates a controller and manages its session
impl Controller {
    /// Creates a new controller and starts a session with it. This will allocate a buffer holding an [`EVENT_TRACE_PROPERTIES``] structure along with space to store the session name after
    /// For information as to why the session name needs to be stored after the properties structure, please consult https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
    /// Panics if the session cannot be started
    pub fn new(session_name: &'static CStr) -> Self {
        let mut handle: CONTROLTRACE_HANDLE = CONTROLTRACE_HANDLE::default();
        let mut event_prop_buf: Vec<u8> = Vec::with_capacity(
            mem::size_of::<EVENT_TRACE_PROPERTIES>() + session_name.to_bytes_with_nul().len(),
        );
        // Set event properties in temp struct and copy everything over when complete
        {
            let temp_prop = EVENT_TRACE_PROPERTIES {
                Wnode: WNODE_HEADER {
                    BufferSize: event_prop_buf.capacity() as u32,
                    Guid: SystemTraceControlGuid,
                    ClientContext: 1,
                    Flags: WNODE_FLAG_TRACED_GUID,
                    ..Default::default()
                },
                EnableFlags: EVENT_TRACE_FLAG_PROCESS,
                LogFileMode: EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE,
                LogFileNameOffset: 0, // Sets realtime session
                LoggerNameOffset: mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32,
                ..Default::default()
            };

            event_prop_buf.extend_from_slice(unsafe {
                slice::from_raw_parts(
                    &temp_prop as *const EVENT_TRACE_PROPERTIES as *const u8,
                    mem::size_of::<EVENT_TRACE_PROPERTIES>(),
                )
            });
        }

        Controller::_start_session(
            &mut handle,
            Self::_properties(&mut event_prop_buf),
            session_name,
        );

        Self {
            trace_handle: handle,
            session_name,
            event_prop_buf,
        }
    }

    /// Starts the Trace Session with the given session_name. Panics if it's not possible
    fn _start_session(
        handle: &mut CONTROLTRACE_HANDLE,
        properties: &mut EVENT_TRACE_PROPERTIES,
        session_name: &CStr,
    ) {
        let status =
            unsafe { StartTraceA(handle, Self::_session_name_ptr(session_name), properties) };

        match status {
            ERROR_SUCCESS => {}
            ERROR_BAD_LENGTH => {
                panic!(
                    "One of the following is true:
                        The Wnode.Buffer size is incorrect: {:?}?
                        The backing buffer to the event trace properties is not large enough
                    ",
                    properties.Wnode.BufferSize
                );
            }
            ERROR_INVALID_PARAMETER => {
                panic!(
                    "One of the following is true:
                        TraceHandle is null: {:?},
                        LogFileNameOffset of Properties is {},
                        LoggerNameOffset of Properties is {},
                        LogFileMode of Properties is {},
                        Wnode GUID is SystemTraceControl GUID, but the InstanceName parameter is {:?}
                    ",
                    handle,
                    properties.LogFileNameOffset,
                    properties.LoggerNameOffset,
                    properties.LogFileMode,
                    session_name
                );
            }
            ERROR_ALREADY_EXISTS => panic!(
                "Error, session with name {:?} or GUID {:?} alreay exists!",
                session_name, properties.Wnode.Guid
            ),
            ERROR_BAD_PATHNAME => {
                panic!("This is supposed to be a realtime session")
            }
            ERROR_NO_SYSTEM_RESOURCES => panic!("Not enough system resources"),
            ERROR_ACCESS_DENIED => {
                panic!("Only users with administrative privileges can run this!")
            }
            status => panic!("Unspecified Error: {:?}", status),
        }
    }

    // Internal function to grab the session name from a &CStr. Not a method because the borrow checker will cause problems.
    fn _session_name_ptr(session_name: &CStr) -> PCSTR {
        PCSTR::from_raw(session_name.as_ptr() as *const u8)
    }

    // Internal function to grab the properties from a Vec<u8>. Not a method because the borrow checker will cause problems.
    fn _properties(evt_prop_buf: &mut Vec<u8>) -> &mut EVENT_TRACE_PROPERTIES {
        unsafe { (evt_prop_buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES).as_mut() }
            .expect("Could not get access to mutable ref to event properties")
    }
}

/// Stop the trace if the controller goes out of scope.
impl Drop for Controller {
    fn drop(&mut self) {
        println!("Controller went out of scope, dropping session...");
        // check to see if the trace handle is not invalid, this means we have a trace session
        if self.trace_handle.Value as *mut c_void != INVALID_HANDLE_VALUE.0 {
            unsafe {
                let _ = ControlTraceA(
                    self.trace_handle,
                    Self::_session_name_ptr(self.session_name),
                    Self::_properties(&mut self.event_prop_buf),
                    EVENT_TRACE_CONTROL_STOP,
                );
            }
        }
    }
}
