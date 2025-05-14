# Etw Rust Tool

## Description

This is an open source Rust tool that monitors process creation events using the Event Tracing for Windows system. The biggest motiviations for this project is to workaround some of the security pitfalls from using the WMI libraries. This is designed to work on Windows 10 and 11.


## How to Run

1. Clone this repository on a Windows Machine
2. Run this project with `cargo run -r`
3. Optionally, you can build this project in release mode, and run the executable there.