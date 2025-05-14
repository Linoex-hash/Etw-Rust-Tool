use std::collections::HashMap;

use windows::{
    core::PWSTR,
    Win32::{
        Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, WIN32_ERROR},
        System::Diagnostics::Etw::{
            TdhFormatProperty, TdhGetEventInformation, EVENT_MAP_INFO, EVENT_PROPERTY_INFO,
            EVENT_RECORD, TDH_CONTEXT, TRACE_EVENT_INFO,
        },
    },
};

#[derive(Debug, Default)]
pub struct ProcessTypeGroup1 {
    _unique_process_key: u64, // I know it says u32 in the description, but I have had values that go up to 64
    _process_id: u32,
    _parent_id: u32,
    _session_id: u32,
    _exit_status: i32,
    _directory_table_base: u64,
    _user_sid: String,
    _image_file_name: String,
    _command_line: String,
}

impl From<HashMap<String, String>> for ProcessTypeGroup1 {
    fn from(value: HashMap<String, String>) -> Self {
        Self {
            _unique_process_key: value
                .get("UniqueProcessKey")
                .and_then(|val| u64::from_str_radix(val.trim_start_matches("0x"), 16).ok())
                .unwrap_or_default(),
            _process_id: value
                .get("ProcessId")
                .and_then(|val| u32::from_str_radix(val.trim_start_matches("0x"), 16).ok())
                .unwrap_or_default(),
            _parent_id: value
                .get("ParentId")
                .and_then(|val| u32::from_str_radix(val.trim_start_matches("0x"), 16).ok())
                .unwrap_or_default(),
            _session_id: value
                .get("SessionId")
                .and_then(|val| u32::from_str_radix(val.trim_start_matches("0x"), 16).ok())
                .unwrap_or_default(),
            _exit_status: value
                .get("ExitStatus")
                .and_then(|val| i32::from_str_radix(val.trim_start_matches("0x"), 16).ok())
                .unwrap_or_default(),
            _directory_table_base: value
                .get("DirectoryTableBase")
                .and_then(|val| u64::from_str_radix(val.trim_start_matches("0x"), 16).ok())
                .unwrap_or_default(),
            _user_sid: value.get("UserSID").cloned().unwrap_or_default(),
            _image_file_name: value.get("ImageFileName").cloned().unwrap_or_default(),
            _command_line: value.get("CommandLine").cloned().unwrap_or_default(),
        }
    }
}

pub struct Tdh;

impl Tdh {
    /// Gets information about the event. Returns a Vec<u8> on success with the event information, a WIN32ERROR on failure
    pub fn get_event_information(
        record: &EVENT_RECORD,
        tdh_context: Option<&[TDH_CONTEXT]>,
    ) -> Result<Vec<u8>, WIN32_ERROR> {
        let mut expected_buf_size = 0;

        let int_tdh_info = |buffer: Option<&mut Vec<u8>>, expected_buf_size: &mut u32| unsafe {
            WIN32_ERROR(TdhGetEventInformation(
                record,
                tdh_context,
                buffer.map(|s| s.as_mut_ptr() as *mut TRACE_EVENT_INFO),
                expected_buf_size,
            ))
        };
        let status = int_tdh_info(None, &mut expected_buf_size);

        if status != ERROR_INSUFFICIENT_BUFFER {
            return Err(status);
        }

        let mut buffer = vec![0u8; expected_buf_size as usize];

        match int_tdh_info(Some(&mut buffer), &mut expected_buf_size) {
            ERROR_SUCCESS => Ok(buffer),
            error_code => Err(error_code),
        }
    }

    /// Gets the data of a property whose name is identifed by the `property_info` field. Uses `tdhformatproperty` to do this.
    /// Returns a Vector of bytes corresponding to the property value on success and the data consumed from userdata - a WIN32_ERROR on failure.
    pub fn format_property(
        event: &TRACE_EVENT_INFO,
        _mapinfo: Option<&EVENT_MAP_INFO>,
        pointer_size: u32,
        property_info: &EVENT_PROPERTY_INFO,
        userdata: &[u8],
    ) -> Result<(Vec<u16>, usize), WIN32_ERROR> {
        let mut buf_size = 0;
        let mut consumed_data = 0;

        let int_tdh_format =
            |buffer: Option<&mut Vec<u16>>, buf_size: &mut u32, consumed_data: &mut u16| {
                WIN32_ERROR(unsafe {
                    TdhFormatProperty(
                        event,
                        None,
                        pointer_size,
                        property_info.Anonymous1.nonStructType.InType,
                        if property_info.Anonymous1.nonStructType.OutType == 0 {
                            // https://learn.microsoft.com/en-us/windows/win32/api/tdh/ns-tdh-event_property_info if this is null, use intype
                            property_info.Anonymous1.nonStructType.InType
                        } else {
                            property_info.Anonymous1.nonStructType.OutType
                        },
                        property_info.Anonymous3.length,
                        userdata,
                        buf_size,
                        buffer
                            .map(|x| PWSTR::from_raw(x.as_mut_ptr()))
                            .unwrap_or_else(PWSTR::null),
                        consumed_data,
                    )
                })
            };

        let status = int_tdh_format(None, &mut buf_size, &mut consumed_data);

        if status != ERROR_INSUFFICIENT_BUFFER {
            return Err(status);
        }

        let mut buffer = vec![0u16; buf_size as usize];

        match int_tdh_format(Some(&mut buffer), &mut buf_size, &mut consumed_data) {
            ERROR_SUCCESS => Ok((buffer, consumed_data as usize)),
            error => Err(error),
        }
    }
}
