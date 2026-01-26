use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::thread;
use std::time::Duration;
use sysinfo::{Pid, System};

#[derive(Debug, Clone, Copy)]
pub struct SystemMetrics {
    pub peak_ram_kb: u64,
    pub avg_cpu_usage: f32,
    pub max_cpu_usage: f32,
}

pub struct MetricsMonitor {
    running: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<SystemMetrics>>,
}

impl MetricsMonitor {
    /// Starts resource monitoring in a separate background thread.
    ///
    /// Returns a `MetricsMonitor` handle that controls the monitoring thread.
    /// The thread samples CPU and RAM usage every 500ms until `stop()` is called.
    pub fn start() -> Self {
        let running = Arc::new(AtomicBool::new(true));
        let r_clone = running.clone();

        let handle = thread::spawn(move || {
            let mut sys = System::new();
            // Retrieve the current process PID for targeted monitoring
            let pid = Pid::from(std::process::id() as usize);
            
            let mut peak_ram = 0;
            let mut cpu_samples = Vec::new();
            let mut max_cpu = 0.0;

            // Main monitoring loop: runs until stop signal is received
            while r_clone.load(Ordering::Relaxed) {
                // Refresh only the current process info for efficiency (sysinfo v0.30+)
                sys.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[pid]), true);
                
                if let Some(process) = sys.process(pid) {
                    // Track peak RAM usage (convert from bytes to KB)
                    let ram = process.memory() / 1024;
                    if ram > peak_ram {
                        peak_ram = ram;
                    }

                    // Track CPU usage percentage and collect samples for averaging
                    let cpu = process.cpu_usage();
                    if cpu > max_cpu {
                        max_cpu = cpu;
                    }
                    cpu_samples.push(cpu);
                }

                // Sampling interval: 500ms provides good granularity without overhead
                thread::sleep(Duration::from_millis(500));
            }

            // Compute average CPU usage from collected samples
            let avg_cpu = if !cpu_samples.is_empty() {
                cpu_samples.iter().sum::<f32>() / cpu_samples.len() as f32
            } else {
                0.0
            };

            SystemMetrics {
                peak_ram_kb: peak_ram,
                avg_cpu_usage: avg_cpu,
                max_cpu_usage: max_cpu,
            }
        });

        MetricsMonitor {
            running,
            handle: Some(handle),
        }
    }

    /// Stops the monitoring thread and returns the collected metrics.
    ///
    /// Consumes the monitor and waits for the background thread to terminate.
    /// Returns a `SystemMetrics` struct containing peak RAM, average CPU, and max CPU.
    pub fn stop(mut self) -> SystemMetrics {
        self.running.store(false, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            handle.join().unwrap_or(SystemMetrics {
                peak_ram_kb: 0,
                avg_cpu_usage: 0.0,
                max_cpu_usage: 0.0,
            })
        } else {
            SystemMetrics {
                peak_ram_kb: 0,
                avg_cpu_usage: 0.0,
                max_cpu_usage: 0.0,
            }
        }
    }
}

#[allow(dead_code)]
fn main() {}