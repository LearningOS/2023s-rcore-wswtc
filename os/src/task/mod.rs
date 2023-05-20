//! Task management implementation
//!
//! Everything about task management, like starting and switching tasks is
//! implemented here.
//!
//! A single global instance of [`TaskManager`] called `TASK_MANAGER` controls
//! all the tasks in the operating system.
//!
//! Be careful when you see `__switch` ASM function in `switch.S`. Control flow around this function
//! might not be what you expect.

mod context;
mod switch;
#[allow(clippy::module_inception)]
mod task;

use crate::timer::get_time_ms;
use crate::task::task::TaskInfoInner;
use crate::syscall::process::TaskInfo;
pub use crate::mm::memory_set::{kernel_stack_position, MapPermission, MemorySet, KERNEL_SPACE};
use crate::mm::VirtPageNum;
use crate::mm::VirtAddr;
use crate::config::PAGE_SIZE;
use crate::mm::VPNRange;
use crate::loader::{get_app_data, get_num_app};
use crate::sync::UPSafeCell;
use crate::trap::TrapContext;
use alloc::vec::Vec;
use lazy_static::*;
use switch::__switch;
pub use task::{TaskControlBlock, TaskStatus};

pub use context::TaskContext;

/// The task manager, where all the tasks are managed.
///
/// Functions implemented on `TaskManager` deals with all task state transitions
/// and task context switching. For convenience, you can find wrappers around it
/// in the module level.
///
/// Most of `TaskManager` are hidden behind the field `inner`, to defer
/// borrowing checks to runtime. You can see examples on how to use `inner` in
/// existing functions on `TaskManager`.
pub struct TaskManager {
    /// total number of tasks
    num_app: usize,
    /// use inner value to get mutable access
    inner: UPSafeCell<TaskManagerInner>,
}

/// The task manager inner in 'UPSafeCell'
struct TaskManagerInner {
    /// task list
    pub tasks: Vec<TaskControlBlock>,
    /// id of current `Running` task
    pub current_task: usize,
}

lazy_static! {
    /// a `TaskManager` global instance through lazy_static!
    pub static ref TASK_MANAGER: TaskManager = {
        println!("init TASK_MANAGER");
        let num_app = get_num_app();
        println!("num_app = {}", num_app);
        let mut tasks: Vec<TaskControlBlock> = Vec::new();
        for i in 0..num_app {
            tasks.push(TaskControlBlock::new(get_app_data(i), i));
        }
        TaskManager {
            num_app,
            inner: unsafe {
                UPSafeCell::new(TaskManagerInner {
                    tasks,
                    current_task: 0,
                })
            },
        }
    };
}

impl TaskManager {
    /// Run the first task in task list.
    ///
    /// Generally, the first task in task list is an idle task (we call it zero process later).
    /// But in ch4, we load apps statically, so the first task is a real app.
    fn run_first_task(&self) -> ! {
        let mut inner = self.inner.exclusive_access();
        let next_task = &mut inner.tasks[0];
        next_task.task_status = TaskStatus::Running;
        let next_task_cx_ptr = &next_task.task_cx as *const TaskContext;
        drop(inner);
        let mut _unused = TaskContext::zero_init();
        // before this, we should drop local variables that must be dropped manually
        unsafe {
            __switch(&mut _unused as *mut _, next_task_cx_ptr);
        }
        panic!("unreachable in run_first_task!");
    }

    /// Change the status of current `Running` task into `Ready`.
    fn mark_current_suspended(&self) {
        let mut inner = self.inner.exclusive_access();
        let cur = inner.current_task;
        inner.tasks[cur].task_status = TaskStatus::Ready;
    }

    /// Change the status of current `Running` task into `Exited`.
    fn mark_current_exited(&self) {
        let mut inner = self.inner.exclusive_access();
        let cur = inner.current_task;
        inner.tasks[cur].task_status = TaskStatus::Exited;
    }

    /// Find next task to run and return task id.
    ///
    /// In this case, we only return the first `Ready` task in task list.
    fn find_next_task(&self) -> Option<usize> {
        let inner = self.inner.exclusive_access();
        let current = inner.current_task;
        (current + 1..current + self.num_app + 1)
            .map(|id| id % self.num_app)
            .find(|id| inner.tasks[*id].task_status == TaskStatus::Ready)
    }

    /// Get the current 'Running' task's token.
    fn get_current_token(&self) -> usize {
        let inner = self.inner.exclusive_access();
        inner.tasks[inner.current_task].get_user_token()
    }

    /// Get the current 'Running' task's trap contexts.
    fn get_current_trap_cx(&self) -> &'static mut TrapContext {
        let inner = self.inner.exclusive_access();
        inner.tasks[inner.current_task].get_trap_cx()
    }

    /// Change the current 'Running' task's program break
    pub fn change_current_program_brk(&self, size: i32) -> Option<usize> {
        let mut inner = self.inner.exclusive_access();
        let cur = inner.current_task;
        inner.tasks[cur].change_program_brk(size)
    }

    /// Switch current `Running` task to the task we have found,
    /// or there is no `Ready` task and we can exit with all applications completed
    fn run_next_task(&self) {
        if let Some(next) = self.find_next_task() {
            let mut inner = self.inner.exclusive_access();
            let current = inner.current_task;
            inner.tasks[next].task_status = TaskStatus::Running;
            inner.current_task = next;
            let current_task_cx_ptr = &mut inner.tasks[current].task_cx as *mut TaskContext;
            let next_task_cx_ptr = &inner.tasks[next].task_cx as *const TaskContext;
            drop(inner);
            // before this, we should drop local variables that must be dropped manually
            unsafe {
                __switch(current_task_cx_ptr, next_task_cx_ptr);
            }
            // go back to user mode
        } else {
            panic!("All applications completed!");
        }
    }

    fn set_syscall_times(&self, syscall_id: usize) {
        let mut inner = self.inner.exclusive_access();
        let current_id = inner.current_task;
        inner.tasks[current_id].task_info_inner.syscall_times[syscall_id] += 1;
    }

    fn get_current_task_info(&self, ti: *mut TaskInfo) {
        let inner = self.inner.exclusive_access();
        let current_id = inner.current_task;
        let TaskInfoInner {syscall_times, start_time} = inner.tasks[current_id].task_info_inner;

        unsafe {
            *ti = TaskInfo {
                status: TaskStatus::Running,
                syscall_times,
                time: get_time_ms() - start_time,
            };
        }
    }
    fn mmap(&self, start: usize, len: usize, port: usize) -> isize {
        if len == 0 {
            return 0;
        }
        if len > 1073741824{
            return -1;
        }
        if start % 4096 != 0 {
            return -1;
        }
        let mut length = len;
        if len % 4096 != 0 {
            length = len + (4096 - len % 4096);
        }
        if (port & !0x7 != 0) || (port & 0x7 == 0) {
            return -1;
        }
        
        // println!("@");
        let mut inner = self.inner.exclusive_access();
        let current = inner.current_task;
        // println!("Start : {:#X}", VirtPageNum::from(start/4096).0);
        let from:usize = start / 4096;
        let to:usize = (start + length) / 4096;
        // println!("from to {} {}", from, to);
        for vpn in from..to {
            if true == inner.tasks[current].memory_set.find_vpn(VirtPageNum::from(vpn)) {
                return -1;
            }
        }
        
        let permission = match port {
            1 => MapPermission::U | MapPermission::R,
            2 => MapPermission::U | MapPermission::W,
            3 => MapPermission::U | MapPermission::R | MapPermission::W,
            4 => MapPermission::U | MapPermission::X,
            5 => MapPermission::U | MapPermission::R | MapPermission::X,
            6 => MapPermission::U | MapPermission::X | MapPermission::W,
            _ => MapPermission::U | MapPermission::R | MapPermission::W | MapPermission::X,
        };

        inner.tasks[current].memory_set.insert_framed_area(VirtAddr::from(start), VirtAddr::from(start+length), permission);

        for vpn in from..to {
            if false == inner.tasks[current].memory_set.find_vpn(VirtPageNum::from(vpn)) {
                return -1;
            }
        }
        return length as isize;
    }

    pub fn munmap(&self, start: usize, len: usize) -> isize {
        if len == 0 {
            return 0;
        }
        if len > 1073741824{
            return -1;
        }
        if start % 4096 != 0 {
            return -1;
        }
        let mut length = len;
        if len % 4096 != 0 {
            length = len + (4096 - len % 4096);
        }
        let mut inner = self.inner.exclusive_access();
        let current = inner.current_task;
        let from:usize = start / 4096;
        let to:usize = (start + length) / 4096;
        for vpn in from..to {
            if false == inner.tasks[current].memory_set.find_vpn(VirtPageNum::from(vpn)) {
                return -1;
            }
        }

        for vpn in from..to {
            inner.tasks[current].memory_set.munmap(VirtPageNum::from(vpn));
        }

        for vpn in from..to {
            if true == inner.tasks[current].memory_set.find_vpn(VirtPageNum::from(vpn)) {
                return -1;
            }
        }

        return len as isize;
    }

    fn task_map(&self, start: usize, len: usize, port: usize) -> isize {
        if start & (PAGE_SIZE - 1) != 0 {
            println!(
                "expect the start address to be aligned with a page, but get an invalid start: {:#x}",
                start
            );
            return -1;
        }
        // port最低三位[x w r]，其他位必须为0
        if port > 7usize || port == 0 {
            println!("invalid port: {:#b}", port);
            return -1;
        }

        let mut inner = self.inner.exclusive_access();
        let task_id = inner.current_task;
        let current_task = &mut inner.tasks[task_id];
        let memory_set = &mut current_task.memory_set;
  
        // check valid
        let start_vpn = VirtPageNum::from(VirtAddr(start));
        let end_vpn = VirtPageNum::from(VirtAddr(start + len).ceil());
        for vpn in start_vpn.0 .. end_vpn.0 {
            if let Some(pte) = memory_set.translate(VirtPageNum(vpn)) {
                if pte.is_valid() {
                    println!("vpn {} has been occupied!", vpn);
                    return -1;
                }
            }
        }

	// PTE_U 的语义是【用户能否访问该物理帧】
        let permission = MapPermission::from_bits((port as u8) << 1).unwrap() | MapPermission::U;
        memory_set.insert_framed_area(VirtAddr(start), VirtAddr(start+len), permission);
        0
    }

    fn task_munmap(&self, start: usize, len: usize) -> isize {
        if start & (PAGE_SIZE - 1) != 0 {
            println!(
                "expect the start address to be aligned with a page, but get an invalid start: {:#x}",
                start
            );
            return -1;
        }
      
        let mut inner = self.inner.exclusive_access();
        let task_id = inner.current_task;
        let current_task = &mut inner.tasks[task_id];
        let memory_set = &mut current_task.memory_set;

        // check valid
        let start_vpn = VirtPageNum::from(VirtAddr(start));
        let end_vpn = VirtPageNum::from(VirtAddr(start + len).ceil());
        for vpn in start_vpn.0 .. end_vpn.0 {
            if let Some(pte) = memory_set.translate(VirtPageNum(vpn)) {
                if !pte.is_valid() {
                    println!("vpn {} is not valid before unmap", vpn);
                    return -1;
                }
            }
        }
      
        let vpn_range = VPNRange::new(start_vpn, end_vpn);
        for vpn in vpn_range {
            memory_set.munmap(vpn);
        }
        
        0
    }

    fn current_memory_set_mmap(&self, start_va: VirtAddr, end_va: VirtAddr, permission: MapPermission) -> Result<(), &'static str > {
        let mut inner = self.inner.exclusive_access();
        let current_task = inner.current_task;
        inner.tasks[current_task].memory_set.insert_framed_area(start_va, end_va, permission);
        Ok(())
    }

    fn current_memory_set_munmap(&self, start_va: VirtAddr, end_va: VirtAddr) -> isize {
        let mut inner = self.inner.exclusive_access();
        let current_task = inner.current_task;
        inner.tasks[current_task].memory_set.remove_mapped_frames(start_va, end_va)
    }

    fn get_current_id(&self) -> usize {
        let inner = self.inner.exclusive_access();
        inner.current_task
    }
}

pub fn current_id() -> usize {
    TASK_MANAGER.get_current_id()
}

pub fn current_memory_set_mmap(start_va: VirtAddr, end_va: VirtAddr, permission: MapPermission) -> Result<(), &'static str > {
    TASK_MANAGER.current_memory_set_mmap(start_va, end_va, permission)
}

pub fn current_memory_set_munmap(start_va: VirtAddr, end_va: VirtAddr) -> isize {
    TASK_MANAGER.current_memory_set_munmap(start_va, end_va)
}
pub fn mmap(start: usize, len: usize, port: usize) -> isize {
    TASK_MANAGER.mmap(start, len, port)
}

pub fn munmap(start: usize, len: usize) -> isize {
    TASK_MANAGER.munmap(start, len)
}

pub fn record_syscall(syscall_id: usize) {
    TASK_MANAGER.set_syscall_times(syscall_id);
}

pub fn get_task_info(ti: *mut TaskInfo) {
    TASK_MANAGER.get_current_task_info(ti);
}
/// Run the first task in task list.
pub fn run_first_task() {
    TASK_MANAGER.run_first_task();
}

/// Switch current `Running` task to the task we have found,
/// or there is no `Ready` task and we can exit with all applications completed
fn run_next_task() {
    TASK_MANAGER.run_next_task();
}

/// Change the status of current `Running` task into `Ready`.
fn mark_current_suspended() {
    TASK_MANAGER.mark_current_suspended();
}

/// Change the status of current `Running` task into `Exited`.
fn mark_current_exited() {
    TASK_MANAGER.mark_current_exited();
}

/// Suspend the current 'Running' task and run the next task in task list.
pub fn suspend_current_and_run_next() {
    mark_current_suspended();
    run_next_task();
}

/// Exit the current 'Running' task and run the next task in task list.
pub fn exit_current_and_run_next() {
    mark_current_exited();
    run_next_task();
}

/// Get the current 'Running' task's token.
pub fn current_user_token() -> usize {
    TASK_MANAGER.get_current_token()
}

/// Get the current 'Running' task's trap contexts.
pub fn current_trap_cx() -> &'static mut TrapContext {
    TASK_MANAGER.get_current_trap_cx()
}

/// Change the current 'Running' task's program break
pub fn change_program_brk(size: i32) -> Option<usize> {
    TASK_MANAGER.change_current_program_brk(size)
}
