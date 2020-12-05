use memory_rs::internal::memory::{resolve_module_path, scan_aligned_value, scan_aob_all_matches};
use memory_rs::internal::process_info::ProcessInfo;
use memory_rs::try_winapi;
use std::convert::TryInto;
use std::ffi::{CStr, CString};
use std::io::{BufReader, Read, Write};
use std::path::PathBuf;
use std::sync::{atomic::AtomicUsize, atomic::Ordering, Arc, Mutex};
use winapi::shared::minwindef::LPVOID;
use winapi::um::consoleapi::AllocConsole;
use winapi::um::libloaderapi::{self, FreeLibraryAndExitThread};
use winapi::um::wincon::FreeConsole;
use winapi::um::winuser::MessageBoxA;

mod globals;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// This struct will contain the basic information about the RTTI when
/// the scan_aob gets a match.
struct RTTIMatch {
    /// Name of the RTTI.
    name: String,

    /// Address of the string found - 0x10
    addr: usize,

    /// Possible matches containing the rtti information
    possible_matches: Vec<usize>,
}

impl std::fmt::Display for RTTIMatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}\t{:x}\t{:x?}",
            self.name, self.addr, self.possible_matches
        )
    }
}

fn show_message(msg: &str, is_err: bool) {
    let msg = CString::new(msg).unwrap();
    let caption = CString::new("RTTI Dumper").unwrap();

    let kind = if is_err { 0x10 } else { 0x40 };

    unsafe {
        MessageBoxA(std::ptr::null_mut(), msg.as_ptr(), caption.as_ptr(), kind);
    }
}

/// Extract the number of arguments from the pipe created by the injector.
fn get_arguments() -> Result<u16> {
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

    let n_proc: u16 = contents.parse()?;

    Ok(n_proc)
}

unsafe extern "system" fn wrapper(lib: LPVOID) -> u32 {
    AllocConsole();

    let n_proc = match get_arguments() {
        Ok(o) => o,
        Err(_) => {
            println!("Can't read from the pipe, so back to 4 threads.");
            4
        }
    };

    match get_rtti_values(lib, n_proc) {
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
    let mut buf: Vec<i8> = Vec::with_capacity(255);

    try_winapi!(libloaderapi::GetModuleFileNameA(
        lib as _,
        buf.as_mut_ptr(),
        255
    ));
    let name = CStr::from_ptr(buf.as_ptr());
    let name = String::from(name.to_str()?);

    Ok(name)
}

fn get_rtti_values(lib: LPVOID, n_proc: u16) -> Result<&'static str> {
    let proc_inf = ProcessInfo::new(None)?;
    let mut path = unsafe { resolve_module_path(lib)? };
    let av_signature_lambda = |x: &[u8]| -> bool { matches!(x, b".?AV") };

    // Used to benchmark.
    let t = std::time::Instant::now();

    let av_matches = scan_aob_all_matches(proc_inf.addr, proc_inf.size, av_signature_lambda, 4)?;

    let game_name: String = unsafe {
        let name: PathBuf = get_module_name(std::ptr::null_mut())?.into();
        let name = name.file_name().ok_or("Couldn't get exec name")?;
        String::from(name.to_string_lossy())
    };

    path.push(format!("offsets_{}.tsv", game_name));

    let total_addr = av_matches.len();

    if total_addr == 0 {
        return Ok("There's no AV information");
    }

    // We'll use only 1 thread if the number of addresses found
    // is less than 100, since it doesn't worth the overhead.
    let mut n_threads = 1;
    if total_addr >= 100 {
        n_threads = n_proc as _;
    }

    let chunk_size = if n_threads > 1 {
        av_matches.len() / (n_threads - 1)
    } else {
        av_matches.len()
    };

    println!("Using {} threads", n_threads);

    let av_matches_splitted: Vec<Arc<Vec<usize>>> = av_matches
        .chunks(chunk_size)
        .map(|x| Arc::new(x.try_into().expect("Couldn't convert vectors to arc")))
        .collect();

    // Store all the RTTIMatch results.
    let results = Arc::new(Mutex::new(Vec::new()));

    // Counter to get some progress reporting.
    let total_revised = Arc::new(AtomicUsize::default());

    let mut handles = vec![];

    for chunk in av_matches_splitted {
        let chunk = chunk.clone();
        let base_addr = proc_inf.addr;
        let exec_size = proc_inf.size;
        let results = results.clone();
        let total_revised = total_revised.clone();
        handles.push(std::thread::spawn(move || {
            for a in chunk.iter() {
                let name = {
                    let lossy = unsafe { CStr::from_ptr((*a) as _) };
                    let name = String::from(lossy.to_string_lossy());
                    name
                };

                let relative_rtti_info: u32 =
                    (*a - 0x10 - base_addr).try_into().expect("Overflow issue");
                let matches = scan_aligned_value(base_addr, exec_size, relative_rtti_info)
                    .expect("Can't scan 1");

                let mut possible_matches = vec![];
                for m in matches {
                    let results =
                        scan_aligned_value(base_addr, exec_size, m - 0xC).expect("Can't scan 2");
                    possible_matches.extend_from_slice(&results);
                }

                let rtti = RTTIMatch {
                    name,
                    addr: (*a),
                    possible_matches,
                };
                let mut results = results.lock().expect("Can't lock");
                results.push(rtti);
                total_revised.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }

    // Scale exec size to MB.
    let exec_size = proc_inf.size as f32 / (1024. * 1024.);
    handles.push(std::thread::spawn(move || {
        let time = std::time::Instant::now();
        loop {
            let total_revised = total_revised.load(Ordering::SeqCst);
            let speed = (total_revised as f32 * exec_size) / time.elapsed().as_secs_f32();

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

    for h in handles {
        h.join().expect("Can't join");
    }

    println!("All threads ended");

    let offsets_f = std::fs::File::create(path)?;
    let mut results = results.try_lock().expect("Can't lock 2");
    (*results).sort_by(|a, b| a.name.partial_cmp(&b.name).expect("Cant sort"));
    for res in (*results).iter() {
        writeln!(&offsets_f, "{}", res)?;
    }

    let diff = t.elapsed().as_secs_f32();
    println!("took {}", diff);

    Ok("RTTI dumped correctly")
}

memory_rs::main_dll!(wrapper);
