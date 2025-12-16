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
    /// Avvia il monitoraggio delle risorse in un thread separato.
    /// Ritorna un oggetto MetricsMonitor che controlla il thread.
    pub fn start() -> Self {
        let running = Arc::new(AtomicBool::new(true));
        let r_clone = running.clone();

        let handle = thread::spawn(move || {
            let mut sys = System::new();
            // Ottieni il PID del processo corrente
            let pid = Pid::from(std::process::id() as usize);
            
            let mut peak_ram = 0;
            let mut cpu_samples = Vec::new();
            let mut max_cpu = 0.0;

            // Loop di monitoraggio
            while r_clone.load(Ordering::Relaxed) {
                // Aggiorna solo le info del processo corrente per efficienza
                // sysinfo v0.30+: refresh_processes con filtro
                sys.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[pid]), true);
                
                if let Some(process) = sys.process(pid) {
                    // RAM (sysinfo restituisce Bytes, convertiamo in KB)
                    let ram = process.memory() / 1024;
                    if ram > peak_ram {
                        peak_ram = ram;
                    }

                    // CPU (%)
                    let cpu = process.cpu_usage();
                    if cpu > max_cpu {
                        max_cpu = cpu;
                    }
                    cpu_samples.push(cpu);
                }

                // Campionamento ogni 500ms
                thread::sleep(Duration::from_millis(500));
            }

            // Calcolo media CPU
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

    /// Ferma il monitoraggio e restituisce le metriche raccolte.
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