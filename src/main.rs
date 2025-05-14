mod etw_constructs;

use core::slice;
use std::{collections::HashMap, ffi::CString, mem, sync::LazyLock};

use etw_constructs::tdh_wrapper;
use etw_constructs::ETWSession;
use windows::Win32::System::Diagnostics::Etw::KERNEL_LOGGER_NAMEA;
use windows::Win32::System::Diagnostics::Etw::{
    EVENT_HEADER_FLAG_32_BIT_HEADER, EVENT_HEADER_FLAG_64_BIT_HEADER, EVENT_RECORD,
    TRACE_EVENT_INFO,
};

use tdh_wrapper::{ProcessTypeGroup1, Tdh};

// Use NT Kernel logger, so KERNEL_LOGGER_NAMEA
static SESSION_NAME: LazyLock<CString> = LazyLock::new(|| unsafe {
    CString::from_vec_unchecked(KERNEL_LOGGER_NAMEA.as_bytes().to_vec())
});

unsafe extern "system" fn on_process_creation(eventrecord: *mut EVENT_RECORD) {
    let record = unsafe { eventrecord.as_ref() }.expect("Expected trace, found nothing");

    // example from https://learn.microsoft.com/en-us/windows/win32/etw/using-tdhformatproperty-to-consume-event-data
    // https://learn.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_header
    // https://learn.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_descriptor
    if ![0x1].contains(&record.EventHeader.EventDescriptor.Opcode) || record.UserDataLength == 0 {
        return;
    }

    println!("Received Event! Trying to Parse:\n");
    println!(
        "Process that generated the event: {}",
        record.EventHeader.ProcessId
    );

    println!(
        "Event Code OP: {:#x}",
        record.EventHeader.EventDescriptor.Opcode
    );

    let mut buffer = Tdh::get_event_information(record, None).expect("Could not get buffer information. Please consult https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-. For what the error code means.");

    if let Some(trace) = (buffer.as_mut_ptr() as *mut TRACE_EVENT_INFO).as_mut() {
        // [EVENT_PROPERTY_INFO; 1] can be more than one element as given by PropertyCount
        let property_infos = slice::from_raw_parts(
            trace.EventPropertyInfoArray.as_ptr(),
            trace.PropertyCount as usize,
        );

        let pointer_size: u32 = dbg!(if record.EventHeader.Flags as u32
            & EVENT_HEADER_FLAG_32_BIT_HEADER
            != 0
        {
            4
        } else if record.EventHeader.Flags as u32 & EVENT_HEADER_FLAG_64_BIT_HEADER != 0 {
            8
        } else {
            mem::size_of::<*const u32>() as u32
        });

        let mut property_info_map: HashMap<String, String> = HashMap::new();

        let mut userdata: &[u8] =
            slice::from_raw_parts(record.UserData as *const u8, record.UserDataLength as usize);

        for property_info in property_infos
            .iter()
            .take(trace.TopLevelPropertyCount as usize)
        {
            let (property_data, consumed_bytes) = Tdh::format_property(trace, None, pointer_size, property_info, userdata).expect("Could not get buffer information. Please consult https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-. For what the error code means.");

            let property_name = {
                let property_name: Vec<u16> = buffer[property_info.NameOffset as usize..]
                    .chunks(2)
                    .map(|x| u16::from_le_bytes([x[0], x[1]]))
                    .take_while(|x| *x != 0)
                    .collect();

                String::from_utf16_lossy(&property_name)
            };

            // Get the property data as all the valid bytes in the property data buffer up until the first nul byte
            let property_data = {
                let valid_property_slice = &property_data[..property_data
                    .iter()
                    .position(|x| *x == 0)
                    .unwrap_or(property_data.len())];

                String::from_utf16_lossy(valid_property_slice)
            };

            // map property name to its value
            property_info_map.insert(property_name, property_data);

            // move start of user data by consumed data bytes, since we already visited it
            userdata = &userdata[consumed_bytes..];
        }

        let process_info = ProcessTypeGroup1::from(property_info_map);

        // op code must be 1
        println!();
        println!("{:#?}", process_info);
        println!();
    }
}

fn main() {
    let session = ETWSession::new(&SESSION_NAME, Some(on_process_creation));

    ctrlc::set_handler(move || {
        if etw_constructs::consumer::SIGINT.set(()).is_ok() {
            println!("\nCtrl-C pressed, stopping trace session\n");
        }
    })
    .expect("Could not create ctrlc handler!");

    session.start_session(); // This drops the consumer for somer reason.
}
