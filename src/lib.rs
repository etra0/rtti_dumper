use memory_rs::internal::memory::resolve_module_path;
use memory_rs::internal::process_info::ProcessInfo;
use rayon::prelude::*;
use std::ffi::CString;
use std::io::{BufReader, Read, Write};
use std::path::PathBuf;
use std::sync::{atomic::AtomicUsize, atomic::Ordering, Arc};
use winapi::shared::minwindef::LPVOID;
use winapi::um::consoleapi::AllocConsole;
use winapi::um::libloaderapi::{self, FreeLibraryAndExitThread};
use winapi::um::wincon::FreeConsole;
use winapi::um::winuser::MessageBoxA;

mod globals;
mod rtti;

use rtti::*;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn show_message(msg: &str, is_err: bool) {
    let msg = CString::new(msg).unwrap();
    let caption = CString::new("RTTI Dumper").unwrap();

    let kind = if is_err { 0x10 } else { 0x40 };

    unsafe {
        MessageBoxA(std::ptr::null_mut(), msg.as_ptr(), caption.as_ptr(), kind);
    }
}

/// Extract the number of arguments from the pipe created by the injector.
fn get_arguments() -> Result<globals::Parameters> {
    let pipe_name = globals::PIPE_NAME;
    dbg!(&pipe_name);

    let pipe_file = loop {
        if let Ok(file) = std::fs::File::open(pipe_name) {
            break file;
        } else {
            println!("Waiting for the pipe");
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    };

    let mut buf_reader = BufReader::new(pipe_file);
    let mut contents = String::new();

    buf_reader.read_to_string(&mut contents)?;

    let params: globals::Parameters = serde_json::from_str(&contents)?;

    Ok(params)
}

unsafe extern "system" fn wrapper(lib: LPVOID) -> u32 {
    AllocConsole();

    let params = match get_arguments() {
        Ok(o) => o,
        Err(e) => {
            println!("{}", e);
            println!("Can't read from the pipe, so back to 4 threads.");
            globals::Parameters::default()
        }
    };

    match get_rtti_values(lib, params) {
        Ok(o) => {
            show_message(o, false);
        }
        Err(e) => {
            let msg = format!("{}", e);
            show_message(&msg, true);
        }
    };

    FreeConsole();
    FreeLibraryAndExitThread(lib as _, 0);
    0
}

unsafe fn get_module_name(lib: LPVOID) -> Result<String> {
    let mut buf = [0_u8; 255];

    memory_rs::try_winapi!(libloaderapi::GetModuleFileNameA(
        lib as _,
        buf.as_mut_ptr() as *mut i8,
        255
    ));
    let null_terminator = buf.iter().position(|&x| x == 0).unwrap();
    let name = String::from_utf8_lossy(&buf[..null_terminator]).to_string();

    Ok(name)
}

fn get_rtti_values(lib: LPVOID, params: globals::Parameters) -> Result<&'static str> {
    let proc_inf = ProcessInfo::new(None)?;

    let region = Arc::new(proc_inf.region);

    let mut path = unsafe { resolve_module_path(lib)? };
    let av_signature_lambda = |x: &[u8]| -> bool { matches!(x, b".?AV") };

    // Used to benchmark.
    let t = std::time::Instant::now();

    let av_matches = region.scan_aob_all_matches(av_signature_lambda, 4)?;

    let game_name: String = unsafe {
        let name: PathBuf = get_module_name(std::ptr::null_mut())?.into();
        let name = name.file_name().ok_or("Couldn't get exec name")?;
        String::from(name.to_string_lossy())
    };

    let total_addr = av_matches.len();

    if total_addr == 0 {
        return Ok("There's no AV information");
    }

    // We'll use only 1 thread if the number of addresses found
    // is less than 100, since it doesn't worth the overhead.
    let mut n_threads = 1;
    if total_addr >= 100 {
        n_threads = params.threads as _;
    }

    println!("Using {} threads", n_threads);
    rayon::ThreadPoolBuilder::new()
        .num_threads(n_threads)
        .build_global()
        .unwrap();

    // Counter to get some progress reporting.
    let total_revised = Arc::new(AtomicUsize::new(0));

    let total_scans = Arc::new(AtomicUsize::new(0));

    let mut handles = vec![];

    // Scale exec size to MB.
    let exec_size = region.size as f32 / (1024. * 1024.);
    {
        let total_revised = total_revised.clone();
        let total_scans = total_scans.clone();
        handles.push(std::thread::spawn(move || {
            let time = std::time::Instant::now();
            loop {
                let total_revised = total_revised.load(Ordering::Relaxed);
                let total_scans = total_scans.load(Ordering::Relaxed);
                let speed = (total_scans as f32 * exec_size) / time.elapsed().as_secs_f32();

                println!(
                    "Progress: {} / {} ({:.2}%) @ {:.2} MB/s",
                    total_revised,
                    total_addr,
                    (total_revised as f32) * 100. / (total_addr as f32),
                    speed
                );
                if total_revised == total_addr {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        }));
    }

    let mut results: Vec<RTTIMatch> = av_matches
        .par_iter()
        .filter_map(|&x| {
            let res = scan_rtti(x, &region, &total_revised, &total_scans);
            if !res.is_ok() {
                println!("{} returned an err", x);
            }

            res.ok()
        })
        .filter_map(|x| x)
        .collect();

    for h in handles {
        h.join().expect("Can't join");
    }

    results.sort_by(|a: &RTTIMatch, b: &RTTIMatch| a.name.partial_cmp(&b.name).expect("Cant sort"));

    path.push(format!(
        "offsets_{}.{}",
        game_name,
        if params.use_json { "json" } else { "tsv" }
    ));
    let offsets_f = std::fs::File::create(path)?;

    if params.use_json {
        let result = serde_json::to_string(&(*results))?;
        write!(&offsets_f, "{}", result)?;
    } else {
        for value in results.iter() {
            writeln!(&offsets_f, "{}", value)?;
        }
    }

    let diff = t.elapsed().as_secs_f32();
    println!("took {}", diff);

    Ok("RTTI dumped correctly")
}

memory_rs::main_dll!(wrapper);
