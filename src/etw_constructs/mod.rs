use std::ffi::CStr;

use windows::Win32::System::Diagnostics::Etw::EVENT_RECORD;

pub mod consumer;
pub mod controller;
pub mod tdh_wrapper;

pub struct ETWSession {
    _controller: controller::Controller,
    consumer: consumer::Consumer,
}

impl ETWSession {
    pub fn new(
        session_name: &'static CStr,
        process_evt_handler: Option<unsafe extern "system" fn(*mut EVENT_RECORD)>,
    ) -> Self {
        Self {
            _controller: controller::Controller::new(session_name),
            consumer: consumer::Consumer::new(session_name, process_evt_handler),
        }
    }

    pub fn start_session(&self) {
        self.consumer.start_listening();
    }
}
