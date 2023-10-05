use anyhow::{anyhow, bail, Context, Result};
use colored::Colorize;
use ctrlc::set_handler;
use lazy_static::lazy_static;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{PerfBufferBuilder, RingBufferBuilder};
use object::{Object, ObjectSymbol};
use plain::Plain;
use std::env::args;
use std::ffi::CStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;

#[path = "bpf/.output/ifunc.skel.rs"]
mod ifunc;
use ifunc::*;

const GLIBC: &str = "/lib/libc.so.6";
const FUNC_NAME: &str = "strlen";
const DEFAULT_COMM: &str = "a.out";

type Data = ifunc_bss_types::data_t;
unsafe impl Plain for Data {}

lazy_static! {
    static ref RESOLVE_ADDR: RwLock<usize> = RwLock::new(0);
    static ref IMPL_ADDR: RwLock<usize> = RwLock::new(0);
}

fn main() -> Result<()> {
    let args = args();
    let comm = if args.len() > 1 {
        args.into_iter().nth(1).unwrap()
    } else {
        DEFAULT_COMM.to_string()
    };
    bump_memlock_rlimit()?;
    let skel_builder = IfuncSkelBuilder::default();
    let skel = skel_builder.open()?;
    let mut skel = skel.load()?;

    let func_offset = get_func_address(GLIBC, FUNC_NAME)?;
    let resolve_uprobe =
        skel.progs_mut()
            .resolve_trace()
            .attach_uprobe(false, -1, GLIBC, func_offset)?;

    let impl_uretprobe =
        skel.progs_mut()
            .impl_trace()
            .attach_uprobe(true, -1, GLIBC, func_offset)?;

    let perf1 = PerfBufferBuilder::new(skel.maps().resolve_addr())
        .sample_cb(get_resolve_addr)
        .build()?;

    let perf2 = PerfBufferBuilder::new(skel.maps().impl_addr())
        .sample_cb(get_impl_addr)
        .build()?;

    while *RESOLVE_ADDR.read().unwrap() == 0 || *IMPL_ADDR.read().unwrap() == 0 {
        perf1.poll(Duration::from_millis(100))?;
        perf2.poll(Duration::from_millis(100))?;
    }

    drop(perf1);
    drop(perf2);
    drop(resolve_uprobe);
    drop(impl_uretprobe);

    let real_offset = *IMPL_ADDR.read().unwrap() - *RESOLVE_ADDR.read().unwrap() + func_offset;
    println!("resolve_addr   : {:#x}", *RESOLVE_ADDR.read().unwrap());
    println!("resolve_offset : {:#x}", func_offset);
    println!("impl_addr      : {:#x}", *IMPL_ADDR.read().unwrap());
    println!("impl_offset    : {:#x}", real_offset);

    let skel_builder = IfuncSkelBuilder::default();
    let skel = skel_builder.open()?;
    let mut skel = skel.load()?;

    // attach uretprobe
    let _uretprobe = skel
        .progs_mut()
        .ifunc_trace()
        .attach_uprobe(true, -1, GLIBC, real_offset)?;

    let running = Arc::new(AtomicBool::new(true));

    let maps = skel.maps();
    let mut rb = RingBufferBuilder::default();
    rb.add(maps.rb(), |data| {
        let mut da = Data::default();
        da.copy_from_bytes(data).unwrap();
        handle(&da, &comm);
        0
    })?;
    let rb = rb.build()?;

    let r = running.clone();
    set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    println!("{:<6} {:<6} {:<12} {:<3} STR", "PID", "UID", "COMM", "LEN");
    while running.load(Ordering::SeqCst) {
        let _ = rb.poll(Duration::from_millis(100));
    }
    Ok(())
}

#[cfg(target_pointer_width = "64")]
fn get_resolve_addr(_cpu: i32, data: &[u8]) {
    let mut u = [0u8; 8];
    u.copy_from_bytes(data).unwrap();
    let addr = usize::from_le_bytes(u);
    *RESOLVE_ADDR.write().unwrap() = addr;
}

#[cfg(target_pointer_width = "64")]
fn get_impl_addr(_cpu: i32, data: &[u8]) {
    let mut u = [0u8; 8];
    u.copy_from_bytes(data).unwrap();
    let addr = usize::from_le_bytes(u);
    *IMPL_ADDR.write().unwrap() = addr;
}

fn handle(data: &Data, cmd: &str) -> i32 {
    let comm = CStr::from_bytes_until_nul(&data.comm[..])
        .unwrap()
        .to_str()
        .unwrap();
    if comm != cmd {
        return 0;
    }

    println!(
        "{:<6} {:<6} {:<12} {:<3} {}",
        data.pid,
        data.uid,
        comm,
        data.size,
        if data.size > data.str.len() as i32 {
            "OUT RANGE".red().to_string()
        } else {
            String::from_utf8_lossy(&data.str[..data.size as usize]).to_string()
        }
    );
    0
}

fn get_func_address(so_path: &str, fn_name: &str) -> Result<usize> {
    let buffer =
        std::fs::read(so_path).with_context(|| format!("could no read file {}", so_path))?;
    let file = object::File::parse(buffer.as_slice())?;
    let mut symbols = file.dynamic_symbols();
    let symbol = symbols
        .find(|symbol| {
            if let Ok(name) = symbol.name() {
                return name == fn_name;
            }
            false
        })
        .ok_or(anyhow!("symbol not found"))?;

    Ok(symbol.address() as usize)
}

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}
