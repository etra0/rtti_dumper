use simple_injector::inject_dll;
use memory_rs::external::process::Process;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        println!("Not enough arguments");
        return;
    }

    let name = args.get(1).unwrap();
    let proc = Process::new(&name).unwrap();
    let mut dll = std::env::current_exe().unwrap();
    dll.pop();
    dll.push("dumper_lib.dll");


    inject_dll(&proc, &dll.to_string_lossy());
}
