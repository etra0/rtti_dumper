use memory_rs::external::process::Process;
use simple_injector::inject_dll;
use std::os::windows::io::FromRawHandle;
use std::{ffi::CString, fs::File, io::Write};
use winapi::um::handleapi;
use winapi::um::namedpipeapi::ConnectNamedPipe;
use winapi::um::winbase::{self, CreateNamedPipeA};

mod globals;

use clap::{App, Arg};

const BUFFER_SIZE: u32 = 512;

/// Creates a Pipe which sole purpose is to tell the DLL how many threads
/// it's supposed to use in order to do the scanning.
fn create_pipe(params: globals::Parameters) -> Result<(), Box<dyn std::error::Error>> {
    let pipe_name = CString::new(globals::PIPE_NAME.as_bytes())?;

    let h_pipe = unsafe {
        CreateNamedPipeA(
            pipe_name.as_ptr() as *const i8,
            winbase::PIPE_ACCESS_OUTBOUND,
            winbase::PIPE_TYPE_MESSAGE | winbase::PIPE_READMODE_MESSAGE | winbase::PIPE_WAIT,
            2,
            BUFFER_SIZE,
            BUFFER_SIZE,
            0,
            std::ptr::null_mut(),
        )
    };

    if h_pipe == handleapi::INVALID_HANDLE_VALUE {
        return Err("Couldn't create pipe".into());
    }

    unsafe {
        ConnectNamedPipe(h_pipe, std::ptr::null_mut());
    }

    println!("Pipe connected");

    let msg = serde_json::to_string(&params)?;
    let msg = CString::new(msg.as_bytes())?;

    let mut pipe_file = unsafe { File::from_raw_handle(h_pipe) };

    // Send the number of proc through the pipes.
    pipe_file.write_all(msg.as_bytes())?;

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = App::new("RTTI Dumper")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Sebastián Aedo <sebastian.aedo@sansano.usm.cl>")
        .about("Tries to dump the virtual table function from the RTTI")
        .arg(
            Arg::with_name("process")
                .help("Name of the process to dump")
                .required(true)
                .value_name("PROCESS")
                .index(1),
        )
        .arg(
            Arg::with_name("threads")
                .short("t")
                .long("threads")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("json")
                .short("j")
                .long("json")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("proc_target")
                .short("p")
                .long("proc_target")
                .takes_value(true)
                .help("Name of the executable to dump. This is useful if you want to dump a DLL for example.")
        )
        .get_matches();

    let n_threads = matches.value_of("threads").unwrap_or("4");
    let use_json = matches.is_present("json");
    let proc_target = matches.value_of("proc_target").map(|x| x.to_string());

    let proc_name = matches.value_of("process").unwrap();

    let n_threads: u16 = n_threads.parse()?;

    let proc = Process::new(&proc_name).unwrap();
    let mut dll = std::env::current_exe().unwrap();
    dll.pop();
    dll.push("dumper_lib.dll");

    inject_dll(&proc, &dll.to_string_lossy());

    let params = globals::Parameters {
        threads: n_threads,
        use_json,
        proc_target
    };
    create_pipe(params)?;

    Ok(())
}
