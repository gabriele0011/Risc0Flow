//! System Resource Monitoring Module
//!
//! This module provides real-time monitoring of system resources during proof generation.
//! It implements a non-blocking background monitoring pattern using a dedicated thread
//! that periodically samples CPU and memory usage of the current process.
//!
//! # Architecture
//!
//! The monitoring system follows a producer-consumer pattern:
//! - **Producer**: Background thread that samples metrics at fixed intervals
//! - **Consumer**: Main thread that retrieves aggregated metrics via `stop()`
//!
//! # Memory Efficiency
//!
//! To support long-running proof generation (potentially hours), the module uses
//! Welford's online algorithm for computing running averages, ensuring O(1) memory
//! complexity regardless of execution duration.

use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::thread;
use std::time::{Duration, Instant};
use sysinfo::{Pid, System};


// ============================================================================
// DATA STRUCTURES
// ============================================================================

/// Aggregated system resource metrics collected during monitored execution.
///
/// This structure contains summary statistics computed from periodic sampling
/// of the host process. All metrics are computed incrementally to minimize
/// memory overhead during long-running operations.
///
/// # Fields
///
/// | Field | Unit | Description |
/// |-------|------|-------------|
/// | `peak_ram_kb` | KB | Maximum resident set size observed |
/// | `avg_cpu_usage` | % | Arithmetic mean of CPU utilization samples |
/// | `max_cpu_usage` | % | Peak CPU utilization observed |
/// | `execution_time_ms` | ms | Wall-clock time from start to stop |
/// | `max_threads` | count | Maximum concurrent thread count |
///
/// # Notes
///
/// - CPU usage percentages may exceed 100% on multi-core systems (e.g., 800% = 8 cores at 100%)
/// - RAM measurement uses RSS (Resident Set Size), not virtual memory
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct SystemMetrics {
    pub peak_ram_kb: u64,
    pub avg_cpu_usage: f32,
    pub max_cpu_usage: f32,
    pub execution_time_ms: u128,
    pub max_threads: usize,
}


/// Handle for controlling an active background monitoring thread.
///
/// This structure implements the RAII pattern for resource monitoring:
/// - `start()` spawns the monitoring thread
/// - `stop()` terminates the thread and returns collected metrics
///
/// # Thread Safety
///
/// Communication between the main thread and monitor thread uses atomic operations
/// with `Relaxed` memory ordering, which is sufficient for a simple boolean flag
/// where precise synchronization is not required.
///
/// # Ownership
///
/// The `stop()` method consumes `self`, ensuring that each monitor instance
/// can only be stopped once and that resources are properly released.
pub struct MetricsMonitor {
    /// Atomic flag signaling the background thread to terminate
    running: Arc<AtomicBool>,
    /// Join handle for the background monitoring thread
    handle: Option<thread::JoinHandle<SystemMetrics>>,
}


// ============================================================================
// IMPLEMENTATION
// ============================================================================

impl MetricsMonitor {
    /// Spawns a background thread that monitors system resource usage.
    ///
    /// The monitoring thread samples the current process at 500ms intervals,
    /// collecting CPU utilization, memory consumption, and thread count.
    /// Sampling continues until `stop()` is called.
    ///
    /// # Algorithm Details
    ///
    /// - **CPU Average**: Computed using Welford's online algorithm to maintain
    ///   numerical stability and O(1) memory usage:
    ///   ```text
    ///   avg_n = avg_{n-1} + (x_n - avg_{n-1}) / n
    ///   ```
    ///
    /// - **Initial Delay**: A 100ms delay after the first refresh ensures valid
    ///   CPU readings, as `sysinfo` requires a time delta for accurate measurements.
    ///
    /// # Returns
    ///
    /// A `MetricsMonitor` handle that must be stopped to retrieve the collected metrics.
    ///
    /// # Example
    ///
    /// ```rust
    /// let monitor = MetricsMonitor::start();
    /// // ... perform monitored operation ...
    /// let metrics = monitor.stop();
    /// println!("Peak RAM: {} KB", metrics.peak_ram_kb);
    /// ```
    pub fn start() -> Self {
        let running = Arc::new(AtomicBool::new(true));
        let r_clone = running.clone();

        let handle = thread::spawn(move || {
            let start_time = Instant::now();
            let mut sys = System::new();
            
            // Obtain PID for process-specific monitoring (avoids system-wide overhead)
            let pid = Pid::from(std::process::id() as usize);
            
            // Peak tracking variables
            let mut peak_ram: u64 = 0;
            let mut max_cpu: f32 = 0.0;
            let mut max_threads: usize = 0;
            
            // Welford's online algorithm state for running average
            let mut avg_cpu: f32 = 0.0;
            let mut sample_count: u64 = 0;

            // Initial refresh with settling delay for accurate first CPU reading
            // (sysinfo requires time delta between refreshes for CPU calculation)
            sys.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[pid]), true);
            thread::sleep(Duration::from_millis(100));

            // Main sampling loop: executes until termination signal received
            while r_clone.load(Ordering::Relaxed) {
                // Selective process refresh minimizes syscall overhead
                sys.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[pid]), true);
                
                if let Some(process) = sys.process(pid) {
                    // Memory tracking: RSS in kilobytes
                    let ram = process.memory() / 1024;
                    if ram > peak_ram {
                        peak_ram = ram;
                    }

                    // CPU tracking with Welford's incremental mean update
                    let cpu = process.cpu_usage();
                    sample_count += 1;
                    avg_cpu += (cpu - avg_cpu) / sample_count as f32;
                    
                    if cpu > max_cpu {
                        max_cpu = cpu;
                    }

                    // Thread count tracking (fallback to 1 if unavailable)
                    let threads = process.tasks().map(|t| t.len()).unwrap_or(1);
                    if threads > max_threads {
                        max_threads = threads;
                    }
                }

                // Fixed sampling interval balances granularity vs overhead
                thread::sleep(Duration::from_millis(500));
            }

            let execution_time_ms = start_time.elapsed().as_millis();

            SystemMetrics {
                peak_ram_kb: peak_ram,
                avg_cpu_usage: avg_cpu,
                max_cpu_usage: max_cpu,
                execution_time_ms,
                max_threads,
            }
        });

        MetricsMonitor {
            running,
            handle: Some(handle),
        }
    }

    /// Terminates the monitoring thread and retrieves aggregated metrics.
    ///
    /// This method signals the background thread to stop, waits for it to
    /// complete its final iteration, and returns the collected metrics.
    ///
    /// # Ownership
    ///
    /// Consumes `self` to enforce single-use semantics and ensure proper
    /// thread cleanup. The monitor cannot be restarted after stopping.
    ///
    /// # Error Handling
    ///
    /// If the background thread panics, returns a zeroed `SystemMetrics`
    /// struct rather than propagating the panic.
    ///
    /// # Returns
    ///
    /// `SystemMetrics` containing aggregated measurements from the entire
    /// monitoring period.
    pub fn stop(mut self) -> SystemMetrics {
        // Signal termination to the background thread
        self.running.store(false, Ordering::Relaxed);
        
        if let Some(handle) = self.handle.take() {
            // Block until background thread completes final iteration
            handle.join().unwrap_or(SystemMetrics {
                peak_ram_kb: 0,
                avg_cpu_usage: 0.0,
                max_cpu_usage: 0.0,
                execution_time_ms: 0,
                max_threads: 0,
            })
        } else {
            // Fallback for edge case where handle was already taken
            SystemMetrics {
                peak_ram_kb: 0,
                avg_cpu_usage: 0.0,
                max_cpu_usage: 0.0,
                execution_time_ms: 0,
                max_threads: 0,
            }
        }
    }
}


// Binary entry point (module is primarily used as a library)
#[allow(dead_code)]
fn main() {}