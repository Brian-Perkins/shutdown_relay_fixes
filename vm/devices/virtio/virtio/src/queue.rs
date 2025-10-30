// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Core virtio queue implementation, without any notification mechanisms, async
//! support, or other transport-specific details.

use crate::spec::VirtioDeviceFeatures;
use crate::spec::queue as spec;
use crate::spec::u16_le;
use core::panic;
use guestmem::GuestMemory;
use guestmem::GuestMemoryError;
use spec::DescriptorFlags;
use spec::EventSuppressionFlags;
use spec::PackedDescriptor;
use spec::PackedEventSuppresion;
use spec::SplitDescriptor;
use static_assertions::const_assert_eq;
use std::sync::atomic;
use thiserror::Error;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

fn descriptor_offset(index: u16) -> u64 {
    const_assert_eq!(size_of::<SplitDescriptor>(), size_of::<PackedDescriptor>());
    index as u64 * size_of::<SplitDescriptor>() as u64
}

fn read_descriptor<T: IntoBytes + FromBytes + Immutable + KnownLayout>(
    queue_desc: &GuestMemory,
    index: u16,
) -> Result<T, QueueError> {
    queue_desc
        .read_plain::<T>(descriptor_offset(index))
        .map_err(QueueError::Memory)
}

pub struct SplitQueueCompletionContext {
    descriptor_index: u16,
}

#[derive(Debug)]
struct SplitQueueGetWork {
    queue_avail: GuestMemory,
    queue_used: GuestMemory,
    queue_size: u16,
    last_avail_index: u16,
    use_ring_event_index: bool,
}

impl SplitQueueGetWork {
    pub fn new(
        features: VirtioDeviceFeatures,
        mem: GuestMemory,
        params: QueueParams,
    ) -> Result<Self, QueueError> {
        let queue_avail = mem
            .subrange(
                params.avail_addr,
                spec::AVAIL_OFFSET_RING
                    + spec::AVAIL_ELEMENT_SIZE * params.size as u64
                    + size_of::<u16>() as u64,
                true,
            )
            .map_err(QueueError::Memory)?;

        let queue_used = mem
            .subrange(
                params.used_addr,
                spec::USED_OFFSET_RING
                    + spec::USED_ELEMENT_SIZE * params.size as u64
                    + size_of::<u16>() as u64,
                true,
            )
            .map_err(QueueError::Memory)?;
        Ok(Self {
            queue_avail,
            queue_used,
            queue_size: params.size,
            last_avail_index: 0,
            use_ring_event_index: features.bank0().ring_event_idx(),
        })
    }

    fn set_used_flags(&self, flags: spec::UsedFlags) -> Result<(), QueueError> {
        self.queue_used
            .write_plain::<u16_le>(0, &u16::from(flags).into())
            .map_err(QueueError::Memory)
    }

    fn get_available_index(&self) -> Result<u16, QueueError> {
        Ok(self
            .queue_avail
            .read_plain::<u16_le>(spec::AVAIL_OFFSET_IDX)
            .map_err(QueueError::Memory)?
            .get())
    }

    fn is_available(&mut self) -> Result<Option<u16>, QueueError> {
        let mut avail_index = Self::get_available_index(self)?;
        if avail_index == self.last_avail_index {
            if self.use_ring_event_index {
                self.set_available_event(avail_index)?;
            } else {
                self.set_used_flags(spec::UsedFlags::new())?;
            }
            // Ensure the available event/used flags are visible before checking
            // the available index again.
            atomic::fence(atomic::Ordering::SeqCst);
            avail_index = Self::get_available_index(self)?;
            if avail_index == self.last_avail_index {
                return Ok(None);
            }
        }

        if self.use_ring_event_index {
            self.set_available_event(self.last_avail_index)?;
        } else {
            self.set_used_flags(spec::UsedFlags::new().with_no_notify(true))?;
        }
        // Ensure available index read is ordered before subsequent descriptor
        // reads.
        atomic::fence(atomic::Ordering::Acquire);
        self.last_avail_index = self.last_avail_index.wrapping_add(1);
        Ok(Some(self.last_avail_index % self.queue_size))
    }

    fn get_available_descriptor_index(&self, wrapped_index: u16) -> Result<u16, QueueError> {
        Ok(self
            .queue_avail
            .read_plain::<u16_le>(
                spec::AVAIL_OFFSET_RING + spec::AVAIL_ELEMENT_SIZE * wrapped_index as u64,
            )
            .map_err(QueueError::Memory)?
            .get())
    }

    fn set_available_event(&self, index: u16) -> Result<(), QueueError> {
        let addr = spec::USED_OFFSET_RING + spec::USED_ELEMENT_SIZE * (self.queue_size as u64);
        self.queue_used
            .write_plain::<u16_le>(addr, &index.into())
            .map_err(QueueError::Memory)
    }
}

#[derive(Debug)]
struct SplitQueueCompleteWork {
    queue_avail: GuestMemory,
    queue_used: GuestMemory,
    queue_size: u16,
    last_used_index: u16,
    use_ring_event_index: bool,
}

impl SplitQueueCompleteWork {
    pub fn new(
        features: VirtioDeviceFeatures,
        mem: GuestMemory,
        params: QueueParams,
    ) -> Result<Self, QueueError> {
        let queue_avail = mem
            .subrange(
                params.avail_addr,
                spec::AVAIL_OFFSET_RING
                    + spec::AVAIL_ELEMENT_SIZE * params.size as u64
                    + size_of::<u16>() as u64,
                true,
            )
            .map_err(QueueError::Memory)?;
        let queue_used = mem
            .subrange(
                params.used_addr,
                spec::USED_OFFSET_RING
                    + spec::USED_ELEMENT_SIZE * params.size as u64
                    + size_of::<u16>() as u64,
                true,
            )
            .map_err(QueueError::Memory)?;
        Ok(Self {
            queue_avail,
            queue_used,
            queue_size: params.size,
            last_used_index: 0,
            use_ring_event_index: features.bank0().ring_event_idx(),
        })
    }

    pub fn complete_descriptor(
        &mut self,
        context: &SplitQueueCompletionContext,
        bytes_written: u32,
    ) -> Result<bool, QueueError> {
        self.set_used_descriptor(
            self.last_used_index,
            context.descriptor_index,
            bytes_written,
        )?;
        let last_used_index = self.last_used_index;
        self.last_used_index = self.last_used_index.wrapping_add(1);

        // Ensure used element writes are ordered before used index write.
        atomic::fence(atomic::Ordering::Release);
        self.set_used_index(self.last_used_index)?;

        // Ensure the used index write is visible before reading the field that
        // determines whether to signal.
        atomic::fence(atomic::Ordering::SeqCst);
        let send_signal = if self.use_ring_event_index {
            last_used_index == self.get_used_event()?
        } else {
            !self.get_available_flags()?.no_interrupt()
        };

        Ok(send_signal)
    }

    fn get_available_flags(&self) -> Result<spec::AvailableFlags, QueueError> {
        Ok(self
            .queue_avail
            .read_plain::<u16_le>(spec::AVAIL_OFFSET_FLAGS)
            .map_err(QueueError::Memory)?
            .get()
            .into())
    }

    fn get_used_event(&self) -> Result<u16, QueueError> {
        let addr = spec::AVAIL_OFFSET_RING + spec::AVAIL_ELEMENT_SIZE * self.queue_size as u64;
        Ok(self
            .queue_avail
            .read_plain::<u16_le>(addr)
            .map_err(QueueError::Memory)?
            .get())
    }

    fn set_used_descriptor(
        &self,
        queue_last_used_index: u16,
        descriptor_index: u16,
        bytes_written: u32,
    ) -> Result<(), QueueError> {
        let wrapped_index = (queue_last_used_index % self.queue_size) as u64;
        let addr = spec::USED_OFFSET_RING + spec::USED_ELEMENT_SIZE * wrapped_index;
        self.queue_used
            .write_plain(
                addr,
                &spec::UsedElement {
                    id: (descriptor_index as u32).into(),
                    len: bytes_written.into(),
                },
            )
            .map_err(QueueError::Memory)
    }

    fn set_used_index(&self, index: u16) -> Result<(), QueueError> {
        self.queue_used
            .write_plain::<u16_le>(spec::USED_OFFSET_IDX, &index.into())
            .map_err(QueueError::Memory)
    }
}

pub struct PackedQueueCompletionContext {
    descriptor_index: u16,
    buffer_id: u16,
    descriptor_count: u16,
}

#[derive(Debug)]
struct PackedQueueGetWork {
    queue_desc: GuestMemory,
    device_event: GuestMemory,
    queue_size: u16,
    next_avail_index: u16,
    _use_event_index: bool,
    wrapped_bit: bool,
}

impl PackedQueueGetWork {
    pub fn new(
        features: VirtioDeviceFeatures,
        mem: GuestMemory,
        params: QueueParams,
    ) -> Result<Self, QueueError> {
        let queue_desc = mem
            .subrange(params.desc_addr, descriptor_offset(params.size), true)
            .map_err(QueueError::Memory)?;
        let offset = params.desc_addr + descriptor_offset(params.size);
        let device_event = mem
            .subrange(offset, size_of::<PackedEventSuppresion>() as u64, true)
            .map_err(QueueError::Memory)?;
        Ok(Self {
            queue_desc,
            device_event,
            queue_size: params.size,
            next_avail_index: 0,
            _use_event_index: features.bank0().ring_event_idx(),
            wrapped_bit: true,
        })
    }

    pub fn is_available(&self) -> Result<Option<u16>, QueueError> {
        loop {
            let disable_event =
                PackedEventSuppresion::new().with_flags(EventSuppressionFlags::Disabled);
            self.device_event
                .write_plain(0, &disable_event.into_bits())
                .map_err(QueueError::Memory)?;
            atomic::fence(atomic::Ordering::Acquire);
            let descriptor: PackedDescriptor =
                read_descriptor(&self.queue_desc, self.next_avail_index)?;
            let flags = descriptor.flags();
            if flags.available() == self.wrapped_bit && flags.used() != self.wrapped_bit {
                return Ok(Some(self.next_avail_index));
            }
            let enable_event =
                PackedEventSuppresion::new().with_flags(EventSuppressionFlags::Enabled);
            self.device_event
                .write_plain(0, &enable_event.into_bits())
                .map_err(QueueError::Memory)?;
            atomic::fence(atomic::Ordering::SeqCst);
            let descriptor: PackedDescriptor =
                read_descriptor(&self.queue_desc, self.next_avail_index)?;
            let flags = descriptor.flags();
            if flags.available() != self.wrapped_bit || flags.used() == self.wrapped_bit {
                return Ok(None);
            }
        }
    }

    pub fn consume_next_available_descriptors(
        &mut self,
        wrapped_index: u16,
        count: u16,
        last_descriptor: QueueDescriptor,
    ) -> PackedQueueCompletionContext {
        let completion_context = PackedQueueCompletionContext {
            descriptor_index: wrapped_index,
            buffer_id: last_descriptor
                .buffer_id
                .expect("packed descriptors have buffer id"),
            descriptor_count: count,
        };

        let next_avail_index = (wrapped_index + count) % self.queue_size;
        if next_avail_index < self.next_avail_index {
            self.wrapped_bit = !self.wrapped_bit;
        }
        self.next_avail_index = next_avail_index;
        completion_context
    }
}

#[derive(Debug)]
struct PackedQueueCompleteWork {
    queue_desc: GuestMemory,
    driver_event: GuestMemory,
    queue_size: u16,
    next_index: u16,
    wrapped_bit: bool,
    use_event_index: bool,
}

impl PackedQueueCompleteWork {
    pub fn new(
        features: VirtioDeviceFeatures,
        mem: GuestMemory,
        params: QueueParams,
    ) -> Result<Self, QueueError> {
        let queue_desc = mem
            .subrange(params.desc_addr, descriptor_offset(params.size), true)
            .map_err(QueueError::Memory)?;
        let offset = params.desc_addr
            + descriptor_offset(params.size)
            + size_of::<PackedEventSuppresion>() as u64;
        let driver_event = mem
            .subrange(offset, size_of::<PackedEventSuppresion>() as u64, true)
            .map_err(QueueError::Memory)?;
        Ok(Self {
            queue_desc,
            driver_event,
            queue_size: params.size,
            next_index: 0,
            wrapped_bit: true,
            use_event_index: features.bank0().ring_event_idx(),
        })
    }

    pub fn complete_descriptor(
        &mut self,
        context: &PackedQueueCompletionContext,
        bytes_written: u32,
    ) -> Result<bool, QueueError> {
        let descriptor = PackedDescriptor::new()
            .with_buffer_id(context.buffer_id)
            .with_length(bytes_written)
            .with_flags(
                DescriptorFlags::new()
                    .with_available(self.wrapped_bit)
                    .with_used(self.wrapped_bit),
            );
        self.queue_desc
            .write_plain(descriptor_offset(self.next_index), &descriptor)
            .map_err(QueueError::Memory)?;
        // Ensure the descriptor update is visible before checking if the guest requires notification.
        atomic::fence(atomic::Ordering::SeqCst);
        let driver_event: PackedEventSuppresion = self
            .driver_event
            .read_plain(0)
            .map_err(QueueError::Memory)?;
        let send_signal = match driver_event.flags() {
            EventSuppressionFlags::Disabled => false,
            EventSuppressionFlags::DescriptorIndex if self.use_event_index => {
                driver_event.offset() == self.next_index && driver_event.wrap() == self.wrapped_bit
            }
            _ => true,
        };
        let next_index = (self.next_index + context.descriptor_count) % self.queue_size;
        if next_index < self.next_index {
            self.wrapped_bit = !self.wrapped_bit;
        }
        self.next_index = next_index;
        Ok(send_signal)
    }
}

pub struct QueueDescriptor {
    address: u64,
    length: u32,
    flags: DescriptorFlags,
    buffer_id: Option<u16>,
    next: Option<u16>,
}

pub enum QueueCompletionContext {
    Split(SplitQueueCompletionContext),
    Packed(PackedQueueCompletionContext),
}

pub struct QueueWork {
    context: QueueCompletionContext,
    pub payload: Vec<VirtioQueuePayload>,
}

impl QueueWork {
    pub fn descriptor_index(&self) -> u16 {
        match &self.context {
            QueueCompletionContext::Split(context) => context.descriptor_index,
            QueueCompletionContext::Packed(context) => context.descriptor_index,
        }
    }
}

#[derive(Debug)]
enum QueueGetWorkInner {
    Split(SplitQueueGetWork),
    Packed(PackedQueueGetWork),
}

#[derive(Debug)]
enum QueueCompleteWorkInner {
    Split(SplitQueueCompleteWork),
    Packed(PackedQueueCompleteWork),
}

#[derive(Debug, Copy, Clone, Default)]
pub struct QueueParams {
    pub size: u16,
    pub enable: bool,
    pub desc_addr: u64,
    pub avail_addr: u64,
    pub used_addr: u64,
}

#[derive(Debug, Error)]
pub enum QueueError {
    #[error("error accessing queue memory")]
    Memory(#[source] GuestMemoryError),
    #[error("an indirect descriptor had the indirect flag set")]
    DoubleIndirect,
    #[error("a descriptor chain is too long or has a cycle")]
    TooLong,
    #[error("completed descriptor index {0} not found")]
    CompletedDescriptorIndexNotFound(u16),
    #[error("Invalid queue size {0}. Must be a power of 2.")]
    InvalidQueueSize(u16),
}

#[derive(Debug)]
pub(crate) struct QueueCoreGetWork {
    queue_desc: GuestMemory,
    queue_size: u16,
    features: VirtioDeviceFeatures,
    mem: GuestMemory,
    inner: QueueGetWorkInner,
}

impl QueueCoreGetWork {
    pub fn new(
        features: VirtioDeviceFeatures,
        mem: GuestMemory,
        params: QueueParams,
    ) -> Result<Self, QueueError> {
        // Queue size must be a power of 2
        if !params.size.is_power_of_two() {
            return Err(QueueError::InvalidQueueSize(params.size));
        }
        let queue_desc = mem
            .subrange(params.desc_addr, descriptor_offset(params.size), true)
            .map_err(QueueError::Memory)?;
        let inner = if features.bank1().ring_packed() {
            QueueGetWorkInner::Packed(PackedQueueGetWork::new(
                features.clone(),
                mem.clone(),
                params,
            )?)
        } else {
            QueueGetWorkInner::Split(SplitQueueGetWork::new(
                features.clone(),
                mem.clone(),
                params,
            )?)
        };
        Ok(Self {
            queue_desc,
            queue_size: params.size,
            features,
            mem,
            inner,
        })
    }

    pub fn try_next_work(&mut self) -> Result<Option<QueueWork>, QueueError> {
        let index = match &mut self.inner {
            QueueGetWorkInner::Split(split) => split.is_available()?,
            QueueGetWorkInner::Packed(packed) => packed.is_available()?,
        };
        let Some(index) = index else {
            return Ok(None);
        };
        if let QueueGetWorkInner::Split(split) = &mut self.inner {
            // Fetch descriptor index from given available index.
            let descriptor_index = split.get_available_descriptor_index(index)?;
            let payload = self
                .reader(descriptor_index)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Some(QueueWork {
                context: QueueCompletionContext::Split(SplitQueueCompletionContext {
                    descriptor_index,
                }),
                payload,
            }))
        } else {
            let payload = self.reader(index).collect::<Result<Vec<_>, _>>()?;
            // Packed descriptors can use additional ring-contiguous
            // descriptors to describe a buffer. Find the last descriptor in
            // the current chain and update the available index accordingly.
            // Indirect descriptors are ignored.
            let desc_walker = DescriptorChain::new(self, false, index);
            let (last_index, last) = desc_walker
                .enumerate()
                .last()
                .expect("should be at least one descriptor in chain");
            let QueueGetWorkInner::Packed(packed) = &mut self.inner else {
                unreachable!();
            };
            let count = last_index as u16 + 1;
            let completion_context = packed.consume_next_available_descriptors(index, count, last?);
            Ok(Some(QueueWork {
                context: QueueCompletionContext::Packed(completion_context),
                payload,
            }))
        }
    }

    fn reader(&mut self, descriptor_index: u16) -> DescriptorReader<'_> {
        DescriptorReader {
            chain: DescriptorChain::new(
                self,
                self.features.bank0().ring_indirect_desc(),
                descriptor_index,
            ),
        }
    }

    fn descriptor(
        &self,
        desc_queue: &GuestMemory,
        index: u16,
        active_indirect_len: Option<u16>,
    ) -> Result<QueueDescriptor, QueueError> {
        let descriptor = match self.inner {
            QueueGetWorkInner::Split(_) => {
                let descriptor: SplitDescriptor = read_descriptor(desc_queue, index)?;
                QueueDescriptor {
                    address: descriptor.address.get(),
                    length: descriptor.length.get(),
                    flags: descriptor.flags(),
                    buffer_id: None,
                    next: if descriptor.flags().next() {
                        Some(descriptor.next.get())
                    } else {
                        None
                    },
                }
            }
            QueueGetWorkInner::Packed(_) => {
                let descriptor: PackedDescriptor = read_descriptor(desc_queue, index)?;
                QueueDescriptor {
                    address: descriptor.address.get(),
                    length: descriptor.length.get(),
                    flags: descriptor.flags(),
                    buffer_id: Some(descriptor.buffer_id.get()),
                    next: if descriptor.flags().next() {
                        Some(index.wrapping_add(1))
                    } else if let Some(active_indirect_len) = active_indirect_len {
                        // Packed descriptors consume all of the indirect
                        // descriptors, even when the next flag is not set.
                        let next = index.wrapping_add(1);
                        if next < active_indirect_len {
                            Some(next)
                        } else {
                            None
                        }
                    } else {
                        None
                    },
                }
            }
        };
        Ok(descriptor)
    }

    fn size(&self) -> u16 {
        self.queue_size
    }
}

#[derive(Debug)]
pub struct QueueCoreCompleteWork {
    inner: QueueCompleteWorkInner,
}

impl QueueCoreCompleteWork {
    pub fn new(
        features: VirtioDeviceFeatures,
        mem: GuestMemory,
        params: QueueParams,
    ) -> Result<Self, QueueError> {
        let inner = if features.bank1().ring_packed() {
            QueueCompleteWorkInner::Packed(PackedQueueCompleteWork::new(
                features.clone(),
                mem.clone(),
                params,
            )?)
        } else {
            QueueCompleteWorkInner::Split(SplitQueueCompleteWork::new(
                features.clone(),
                mem.clone(),
                params,
            )?)
        };
        Ok(Self { inner })
    }

    pub fn complete_descriptor(
        &mut self,
        work: &QueueWork,
        bytes_written: u32,
    ) -> Result<bool, QueueError> {
        match &mut self.inner {
            QueueCompleteWorkInner::Split(split) => {
                let QueueCompletionContext::Split(context) = &work.context else {
                    panic!("mismatched queue completion context for split queue");
                };
                split.complete_descriptor(context, bytes_written)
            }
            QueueCompleteWorkInner::Packed(packed) => {
                let QueueCompletionContext::Packed(context) = &work.context else {
                    panic!("mismatched queue completion context for packed queue");
                };
                packed.complete_descriptor(context, bytes_written)
            }
        }
    }
}

pub(crate) fn new_queue(
    features: VirtioDeviceFeatures,
    mem: GuestMemory,
    params: QueueParams,
) -> Result<(QueueCoreGetWork, QueueCoreCompleteWork), QueueError> {
    let get_work = QueueCoreGetWork::new(features.clone(), mem.clone(), params)?;
    let complete_work = QueueCoreCompleteWork::new(features.clone(), mem.clone(), params)?;
    Ok((get_work, complete_work))
}

pub struct DescriptorChain<'a> {
    queue: &'a QueueCoreGetWork,
    queue_size: u16,
    indirect_support: bool,
    indirect_queue: Option<GuestMemory>,
    descriptor_index: Option<u16>,
    num_read: u16,
    max_desc_chain: u16,
}

impl<'a> DescriptorChain<'a> {
    const MAX_DESC_CHAIN: u16 = 128;

    fn new(queue: &'a QueueCoreGetWork, indirect_support: bool, descriptor_index: u16) -> Self {
        Self {
            queue,
            queue_size: queue.size(),
            indirect_support,
            indirect_queue: None,
            descriptor_index: Some(descriptor_index),
            num_read: 0,
            max_desc_chain: std::cmp::min(queue.size(), Self::MAX_DESC_CHAIN),
        }
    }

    fn next_descriptor(&mut self) -> Result<Option<QueueDescriptor>, QueueError> {
        let Some(descriptor_index) = self.descriptor_index else {
            return Ok(None);
        };
        let descriptor = self.queue.descriptor(
            self.indirect_queue
                .as_ref()
                .unwrap_or(&self.queue.queue_desc),
            descriptor_index,
            self.indirect_queue.as_ref().map(|_| self.queue_size),
        )?;
        let descriptor = if !self.indirect_support || !descriptor.flags.indirect() {
            descriptor
        } else {
            if self.indirect_queue.is_some() {
                return Err(QueueError::DoubleIndirect);
            }
            let indirect_queue = self.indirect_queue.insert(
                self.queue
                    .mem
                    .subrange(descriptor.address, descriptor.length as u64, true)
                    .map_err(QueueError::Memory)?,
            );
            self.descriptor_index = Some(0);
            self.queue_size = std::cmp::min(u16::MAX as u32, descriptor.length) as u16
                / size_of::<SplitDescriptor>() as u16;
            self.max_desc_chain = std::cmp::min(self.queue_size, Self::MAX_DESC_CHAIN);
            self.queue
                .descriptor(indirect_queue, 0, Some(self.queue_size))?
        };

        self.num_read += 1;
        self.descriptor_index = descriptor.next.map(|next| next % self.queue_size);
        // Limit the descriptor chain length to avoid running out of memory.
        // This may be due to a cycle in the descriptor chain.
        if self.descriptor_index.is_some() && self.num_read == self.max_desc_chain {
            return Err(QueueError::TooLong);
        }
        Ok(Some(descriptor))
    }
}

impl Iterator for DescriptorChain<'_> {
    type Item = Result<QueueDescriptor, QueueError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_descriptor().transpose()
    }
}

pub struct VirtioQueuePayload {
    pub writeable: bool,
    pub address: u64,
    pub length: u32,
}

pub struct DescriptorReader<'a> {
    chain: DescriptorChain<'a>,
}

impl Iterator for DescriptorReader<'_> {
    type Item = Result<VirtioQueuePayload, QueueError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.chain.next().map(|descriptor| {
            descriptor.map(|descriptor| VirtioQueuePayload {
                writeable: descriptor.flags.write(),
                address: descriptor.address,
                length: descriptor.length,
            })
        })
    }
}
