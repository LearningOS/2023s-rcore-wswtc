//! Process management syscalls
use crate::{
    config::MAX_SYSCALL_NUM,
    task::{
        change_program_brk, exit_current_and_run_next, suspend_current_and_run_next, TaskStatus,mmap,munmap,current_memory_set_munmap,current_memory_set_mmap,current_id,
    },
};
use crate::task::get_task_info;

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub msec: usize,
}

use crate::mm::PhysAddr;
use crate::task::current_user_token;
use crate::mm::VirtAddr;
use crate::timer::get_time_ms;
use crate::mm::page_table::PageTable;

use crate::config::PAGE_SIZE;
use crate::mm::VPNRange;
use crate::mm::MapPermission;
/// Task information
#[allow(dead_code)]
pub struct TaskInfo {
    /// Task status in it's life cycle
    pub status: TaskStatus,
    /// The numbers of syscall called by task
    pub syscall_times: [u32; MAX_SYSCALL_NUM],
    /// Total running time of task
    pub time: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(_exit_code: i32) -> ! {
    trace!("kernel: sys_exit");
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(_ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel: sys_get_time");
    let virt_addr = VirtAddr(_ts as usize);
    if let Some(phys_addr) = virt2phys_addr(virt_addr) {
        let us = get_time_ms() + 1000;
        let kernel_ts = phys_addr.0 as *mut TimeVal;
        unsafe {
            *kernel_ts = TimeVal {
                sec: us / 1_000,
                msec: 1 + (us % 1_000),
            };
        }
        0
    } else {
        -1
    }
}

/// YOUR JOB: Finish sys_task_info to pass testcases
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TaskInfo`] is splitted by two pages ?
pub fn sys_task_info(_ti: *mut TaskInfo) -> isize {
    trace!("kernel: sys_task_info NOT IMPLEMENTED YET!");
    let virt_addr = VirtAddr(_ti as usize);
    if let Some(phys_addr) = virt2phys_addr(virt_addr) {
        get_task_info(phys_addr.0 as *mut TaskInfo);
        0
    } else {
        -1
    }
}

// YOUR JOB: Implement mmap.
pub fn sys_mmap(start: usize, len: usize, port: usize) -> isize {
    trace!("kernel: sys_mmap NOT IMPLEMENTED YET!");
    //mmap(_start,_len,_port)
    if (start & (PAGE_SIZE - 1)) != 0 
        || (port & !0x7) != 0
        || (port & 0x7) == 0 {
        return -1;
    }

    let len = ( (len + PAGE_SIZE - 1) / PAGE_SIZE ) * PAGE_SIZE;
    let start_vpn =  VirtAddr::from(start).floor();
    let end_vpn =  VirtAddr::from(start + len).ceil();
    
    let page_table_user = PageTable::from_token(current_user_token());
    // make sure there are no mapped pages in [start..start+len)
    for vpn in VPNRange::new(start_vpn, end_vpn) {
        if let Some(_) = page_table_user.translate(vpn) {
            return -1;
        }
    }
    let mut map_perm = MapPermission::U;
    if (port & 0x1) != 0 {
        map_perm |= MapPermission::R;
    }
    if (port & 0x2) !=0 {
        map_perm |= MapPermission::W;
    }
    if (port & 0x4) !=0 {
        map_perm |= MapPermission::X;
    }

    match current_memory_set_mmap(
        VirtAddr::from(start), 
        VirtAddr::from(start + len), 
        map_perm) {
            Ok(_) => 0,
            Err(e) => {
                error!("[Kernel]: mmap error {}, task id={}", e, current_id());
                -1
            }
    }
}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(start: usize, len: usize) -> isize {
    //trace!("kernel: sys_munmap NOT IMPLEMENTED YET!");
    //munmap(_start, _len)
    if (start & (PAGE_SIZE - 1)) != 0 {
        return -1;
    }

    let len = ( (len + PAGE_SIZE - 1) / PAGE_SIZE ) * PAGE_SIZE;
    let start_vpn =  VirtAddr::from(start).floor();
    let end_vpn =  VirtAddr::from(start + len).ceil();

    let page_table_user = PageTable::from_token(current_user_token());
    // make sure there are no unmapped pages in [start..start+len)
    for vpn in VPNRange::new(start_vpn, end_vpn) {
        if let None = page_table_user.translate(vpn) {
            return -1;
        }
    }
    
    current_memory_set_munmap( VirtAddr::from(start), VirtAddr::from(start + len))
}
/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel: sys_sbrk");
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}
/// lab4add
fn virt2phys_addr(virt_addr: VirtAddr) -> Option<PhysAddr> {
    let offset = virt_addr.page_offset();
    let vpn = virt_addr.floor();
    let ppn = PageTable::from_token(current_user_token())
        .translate(vpn)
        .map(|entry| entry.ppn());
    if let Some(ppn) = ppn {
        Some(PhysAddr::combine(ppn, offset))
    } else {
        println!("virt2phys_addr() fail");
        None
    }
}