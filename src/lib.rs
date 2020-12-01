use memory_rs::internal::memory::scan_aob_all_matches;
use memory_rs::internal::process_info::ProcessInfo;
use memory_rs::try_winapi;
use std::{sync::Mutex, convert::TryInto, sync::RwLock};
use std::ffi::{CStr, CString};
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::sync::Arc;
use winapi::shared::minwindef::LPVOID;
use winapi::um::consoleapi::AllocConsole;
use winapi::um::libloaderapi::{self, FreeLibraryAndExitThread};
use winapi::um::wincon::FreeConsole;
use winapi::um::winuser::MessageBoxA;


type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Debug)]
struct RTTIMatch {
    name: String,
    addr: usize,
    possible_matches: Vec<usize>
}

impl std::fmt::Display for RTTIMatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
	write!(f, "{}\t\t{:x}\t{:x?}", self.name, self.addr, self.possible_matches)
    }
}

fn show_message(msg: &str, is_err: bool) {
    let msg = CString::new(msg).unwrap();
    let caption = CString::new("RTTI Dumper").unwrap();

    let kind = if is_err {
        0x10
    } else {
        0x40
    };

    unsafe {
        MessageBoxA(std::ptr::null_mut(), msg.as_ptr(), caption.as_ptr(), kind);
    }
}

unsafe extern "system"  fn wrapper(lib: LPVOID) -> u32 {
    match get_rtti_values(lib) {
        Ok(_) => show_message("Dumped correctly", false),
        Err(e) => {
            let msg = format!("{}", e);
            show_message(&msg, true);
        }
    };

    FreeConsole();
    FreeLibraryAndExitThread(lib as _, 0);
    return 0;
}

fn resolve_path(path: &str) -> PathBuf {
    let mut path: std::path::PathBuf = path.into();
    path.pop();
    return path;
}

unsafe fn get_module_name(lib: LPVOID) -> Result<String> {
    let mut buf: Vec<i8> = Vec::with_capacity(255);

    try_winapi!(libloaderapi::GetModuleFileNameA(lib as _, buf.as_mut_ptr(), 255));
    let name = CStr::from_ptr(buf.as_ptr());
    let name = String::from(name.to_str()?);

    return Ok(name);
}

fn get_rtti_values(lib: LPVOID) -> Result<()> {
    unsafe {
    try_winapi!(AllocConsole());
    }

    let proc_inf = ProcessInfo::new(None)?;

    let name = unsafe { get_module_name(lib)? };
    let mut path = resolve_path(&name);

    let av_signature_lambda = |x: &[u8]| -> bool {
        match x {
            b".?AV" => true,
            _ => false
        }
    };

    let t = std::time::Instant::now();
    let addr = scan_aob_all_matches(proc_inf.addr, proc_inf.size, av_signature_lambda, 4)?;
    let diff = t.elapsed().as_secs_f32();

    println!("Base path: {:?}", path);
    path.push("offsets.txt");
    let offsets_f = std::fs::File::create(path)?;

    let total_addr = addr.len();
    let splitted: Vec<Arc<Vec<usize>>> = addr
        .chunks(addr.len() / 14)
        .map(|x| Arc::new(x.try_into().unwrap()))
        .collect();

    let results = Arc::new(Mutex::new(Vec::new()));
    let total_revised = Arc::new(RwLock::new(0_usize));

    let mut handles = vec![];

    for chunk in splitted {
        let chunk = chunk.clone();
        let base_addr = proc_inf.addr;
        let exec_size = proc_inf.size;
        let mutex_ = results.clone();
        let total_revised_ = total_revised.clone();
        unsafe {
        handles.push(std::thread::spawn(move || {
            for a in chunk.iter() {
                let name = {
                    let lossy = unsafe { CStr::from_ptr((*a) as _) };
                    let name = String::from(lossy.to_string_lossy());
                    name
                };

                let relative_locator: u32 = ((*a - 0x10 - base_addr)).try_into().unwrap();
                let relative_allocator_aob: [u8; 4] = unsafe { std::mem::transmute(relative_locator) };
                let lambda = move |x: &[u8]| -> bool {
                    x == &relative_allocator_aob
                };
                let matches = scan_aob_all_matches(base_addr, exec_size, lambda, 4).unwrap();

                let rtti = RTTIMatch { name: name.into(), addr: (*a), possible_matches: matches };
                let mut mutex_ = mutex_.lock().unwrap();
                mutex_.push(rtti);
                let mut total_revised_ = total_revised_.write().unwrap();
                *total_revised_ += 1;
            }
        }));
        }
    }

    {
        let total_revised_ = total_revised.clone();
        handles.push(std::thread::spawn(move || {
            loop {
                let a = total_revised_.read().unwrap();
                println!("Progress: {} / {} ({:.2}%)", *a, total_addr, ((*a) as f32)*100./(total_addr as f32));
                if *a == total_addr { 
                    break;
                }
                drop(a);
                std::thread::sleep(std::time::Duration::from_secs(1));

            }
        }));
    }

    for h in handles {
        h.join();
    }
    println!("All threads ended");

    unsafe {
        let a = (*Arc::into_raw(results)).lock()?;
        for res in a.iter() {
            writeln!(&offsets_f, "{}", res);
        };
    }

    // for a in addr.iter() {
    //     let name = {
    //         let lossy = unsafe { CStr::from_ptr((*a) as _) };
    //         let name = String::from(lossy.to_string_lossy());
    //         name
    //     };

    //     let relative_locator: u32 = ((*a - 0x10 - proc_inf.addr)).try_into()?;
    //     let relative_allocator_aob: [u8; 4] = unsafe { std::mem::transmute(relative_locator) };
    //     let lambda = move |x: &[u8]| -> bool {
    //         x == &relative_allocator_aob
    //     };
    //     let matches = scan_aob_all_matches(proc_inf.addr, proc_inf.size, lambda, 4);
    //     writeln!(&offsets_f, "{}\t{:x}\t{:x?}", name, *a, matches)?;
    // }

    println!("took {}", diff);

    let mut buffer = String::new();
    let stdin = io::stdin(); // We get `Stdin` here.
    stdin.lock().read_line(&mut buffer).unwrap();


    Ok(())
}

memory_rs::main_dll!(wrapper);
