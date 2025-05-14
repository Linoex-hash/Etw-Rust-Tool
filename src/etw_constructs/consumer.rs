use std::{ffi::CStr, sync::OnceLock};

use windows::{
    core::PSTR,
    Win32::{
        Foundation::{
            ERROR_BAD_LENGTH, ERROR_CANCELLED, ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER,
            ERROR_INVALID_TIME, ERROR_NOACCESS, ERROR_SUCCESS, ERROR_WMI_INSTANCE_NOT_FOUND,
            FILETIME,
        },
        System::{
            Diagnostics::Etw::{
                CloseTrace, OpenTraceA, ProcessTrace, EVENT_RECORD, EVENT_TRACE_LOGFILEA,
                EVENT_TRACE_LOGFILEA_0, EVENT_TRACE_LOGFILEA_1, PROCESSTRACE_HANDLE,
                PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME,
            },
            SystemInformation::GetLocalTime,
            Time::SystemTimeToFileTime,
        },
    },
};

pub(crate) static SIGINT: OnceLock<()> = OnceLock::new();

#[derive(Default)]
pub struct Consumer {
    reghandle: PROCESSTRACE_HANDLE,
    current_time: FILETIME,
}

unsafe extern "system" fn on_termination(_logfile: *mut EVENT_TRACE_LOGFILEA) -> u32 {
    SIGINT.get().is_none() as u32
}

/// An EWT consumer. Consumes events from an existing controller session. Stops its trace session when dropped.
impl Consumer {
    /// Creates a consumer set to trace `session_name` and calls [`OpenTraceA`] to start an existing trace session
    /// Accepts an optional callback function that is invoked every time an event is recorded
    pub fn new(
        session_name: &'static CStr,
        process_evt_handler: Option<unsafe extern "system" fn(*mut EVENT_RECORD)>,
    ) -> Self {
        Self {
            current_time: Self::_get_current_time_as_filetime(),
            reghandle: {
                let mut event_consume_properties = EVENT_TRACE_LOGFILEA {
                    LoggerName: Self::_session_name_pstr(session_name),
                    BufferCallback: Some(on_termination),
                    Anonymous1: EVENT_TRACE_LOGFILEA_0 {
                        ProcessTraceMode: PROCESS_TRACE_MODE_REAL_TIME
                            | PROCESS_TRACE_MODE_EVENT_RECORD,
                    },
                    Anonymous2: EVENT_TRACE_LOGFILEA_1 {
                        EventRecordCallback: process_evt_handler,
                    },
                    ..Default::default()
                };
                unsafe { OpenTraceA(&mut event_consume_properties) }
            },
        }
    }

    /// Wrapper for ProcessTraceA, panics if the error is not success
    pub fn start_listening(&self) {
        let status_code =
            unsafe { ProcessTrace(&[self.reghandle], Some(&self.current_time), None) };

        match status_code {
            ERROR_SUCCESS => {}
            ERROR_BAD_LENGTH => {
                panic!("HandleCount is not valid or the number of handles is greater than 64.")
            }
            ERROR_INVALID_HANDLE => {
                panic!("An element of HandleArray is not a valid event tracing session handle.")
            }
            ERROR_INVALID_TIME => {
                panic!("EndTime is less than StartTime.")
            }
            ERROR_INVALID_PARAMETER => {
                panic!("HandleArray is NULL, contains both file processing sessions and real-time processing sessions, or contains more than one real-time processing session.")
            }
            ERROR_NOACCESS => {
                panic!(
                "An exception occurred in one of the callback functions that receives the events."
            )
            }
            ERROR_CANCELLED => {
                panic!(
                "An exception occurred in one of the callback functions that receives the events."
            )
            }
            ERROR_WMI_INSTANCE_NOT_FOUND => {
                panic!("The trace collection session from which you are trying to consume events in real time is not running or does not have the real-time trace mode enabled.")
            }
            status => panic!("Unspecified Error: {:?}", status),
        }
    }

    fn _session_name_pstr(str: &CStr) -> PSTR {
        PSTR::from_raw(str.as_ptr() as *mut u8)
    }

    /// Gets the current time as a windows SYSTEMTIME object, then converts it to a FILETIME object
    fn _get_current_time_as_filetime() -> FILETIME {
        let systemtime = unsafe { GetLocalTime() };

        // to get local time and https://learn.microsoft.com/en-us/windows/win32/api/timezoneapi/nf-timezoneapi-systemtimetofiletime to convert to file time
        let mut filetime: FILETIME = FILETIME::default();
        unsafe { SystemTimeToFileTime(&systemtime, &mut filetime) }
            .expect("Could not convert system timie to filetime!");

        filetime
    }
}

impl Drop for Consumer {
    fn drop(&mut self) {
        println!("Consumer went out of scope, closing trace...");
        if self.reghandle.Value != 0 {
            unsafe {
                let _ = CloseTrace(self.reghandle);
            }
        }
    }
}
