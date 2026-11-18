//! Measured host work, not a per-invocation CPU isolation claim.
use std::time::Instant;

use rustix::time::{ClockId, Timespec, clock_gettime};

use crate::domain::values::{Usage, WireInt};
use crate::protocol::error::{ErrorCode, ProofError, ProofResult};

pub struct EffectMeter {
    started: Instant,
    cpu_started: Timespec,
    pub(crate) bytes: u64,
    pub dispatched: bool,
    pub(crate) write_pending: bool,
}

impl EffectMeter {
    pub fn start() -> Self {
        Self {
            started: Instant::now(),
            cpu_started: clock_gettime(ClockId::ProcessCPUTime),
            bytes: 0,
            dispatched: false,
            write_pending: false,
        }
    }

    pub fn add_bytes(&mut self, bytes: usize) -> ProofResult<()> {
        self.bytes = self
            .bytes
            .checked_add(u64::try_from(bytes).map_err(|_| budget())?)
            .ok_or_else(budget)?;
        Ok(())
    }

    pub fn usage(&self) -> ProofResult<Usage> {
        let end = clock_gettime(ClockId::ProcessCPUTime);
        // Concurrent host work can be conservatively attributed to this native
        // process-wide counter; it is not hard per-invocation CPU accounting.
        let ns = (i128::from(end.tv_sec) - i128::from(self.cpu_started.tv_sec)) * 1_000_000_000
            + i128::from(end.tv_nsec)
            - i128::from(self.cpu_started.tv_nsec);
        if ns < 0 {
            return Err(ProofError::new(
                ErrorCode::IntegrityError,
                "Native process CPU clock moved backwards",
            ));
        }
        let cpu = u64::try_from(ns / 1000).map_err(|_| budget())?;
        let elapsed = u64::try_from(self.started.elapsed().as_micros()).map_err(|_| budget())?;
        Ok(Usage {
            units: WireInt::new(u64::from(self.dispatched))?,
            bytes: WireInt::new(self.bytes)?,
            cpu_us: WireInt::new(cpu)?,
            elapsed_us: WireInt::new(elapsed)?,
        })
    }
}

fn budget() -> ProofError {
    ProofError::new(
        ErrorCode::BudgetExhausted,
        "Measured resource usage exceeds wire limits",
    )
}
