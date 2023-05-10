//! Types related to task management

use super::TaskContext;
use crate::task::MAX_SYSCALL_NUM;

/// The task control block (TCB) of a task.
#[derive(Copy, Clone)]
pub struct TaskControlBlock {
    /// The task status in it's lifecycle
    pub task_status: TaskStatus,
    /// The task context
    pub task_cx: TaskContext,
    // ///系统调用c次数
    // pub syscall_times: [u32; MAX_SYSCALL_NUM],   
    // ///开始时间
    // pub start_time: usize,
    pub task_info_inner: TaskInfoInner,     
}

/// 2
#[derive(Copy, Clone)]
pub struct TaskInfoInner{
    pub syscall_times: [u32; MAX_SYSCALL_NUM],
    pub start_time: usize,
}

/// The status of a task
#[derive(Copy, Clone, PartialEq)]
pub enum TaskStatus {
    /// uninitialized
    UnInit,
    /// ready to run
    Ready,
    /// running
    Running,
    /// exited
    Exited,
}
