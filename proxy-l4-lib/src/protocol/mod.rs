use crate::{error::ProxyError, probe::ProbeResult};
use bytes::BytesMut;
use std::future::Future;
use std::pin::Pin;

pub mod registry;
pub mod tcp;
pub mod udp;

/// Trait for protocol detection on network streams
/// 
/// This trait provides a unified interface for detecting different protocols
/// from incoming network data. Implementors should examine the provided buffer
/// and return a result indicating whether the protocol was detected, more data
/// is needed, or detection failed.
pub trait ProtocolDetector<T>: Send + Sync {
    /// Detect the protocol from the given buffer
    /// 
    /// # Arguments
    /// * `buffer` - Mutable buffer containing network data to analyze
    /// 
    /// # Returns
    /// * `Ok(ProbeResult::Success(T))` - Protocol successfully detected
    /// * `Ok(ProbeResult::PollNext)` - Need more data to determine protocol
    /// * `Ok(ProbeResult::Failure)` - This is not the expected protocol
    /// * `Err(ProxyError)` - Error occurred during detection
    fn detect<'a>(&'a self, buffer: &'a mut BytesMut) -> Pin<Box<dyn Future<Output = Result<ProbeResult<T>, ProxyError>> + Send + 'a>>;
    
    /// Get the human-readable name of this protocol detector
    fn name(&self) -> &'static str;
    
    /// Get the priority of this detector (lower numbers = higher priority)
    /// 
    /// When multiple detectors are available, they will be tried in order
    /// of priority. This allows more specific detectors to run before
    /// more general ones.
    fn priority(&self) -> u8 {
        100 // Default priority
    }
}
