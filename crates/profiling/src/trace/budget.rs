//! Bound total upstream callbacks as well as the raw JSON sink. The pinned
//! exporter uses an unbounded channel; stopping admission bounds its total input.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use tracing::{Subscriber, span};
use tracing_subscriber::{Layer, layer::Context, registry::LookupSpan};

pub(super) const MAX_CALLBACKS: u64 = 65_536;

#[derive(Clone, Default)]
pub(super) struct Budget(Arc<AtomicU64>);

impl Budget {
    fn reserve_callback(&self) -> bool {
        self.0
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                (n <= MAX_CALLBACKS).then(|| n + 1)
            })
            .is_ok_and(|n| n < MAX_CALLBACKS)
    }

    pub(super) fn exceeded(&self) -> bool {
        self.0.load(Ordering::Relaxed) > MAX_CALLBACKS
    }
}

pub(super) struct BoundedLayer<L> {
    pub(super) inner: L,
    pub(super) budget: Budget,
}

impl<S, L> Layer<S> for BoundedLayer<L>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    L: Layer<S>,
{
    fn on_new_span(&self, attrs: &span::Attributes<'_>, id: &span::Id, ctx: Context<'_, S>) {
        // Default Chrome Threaded mode stores safe stage args but queues no message here.
        self.inner.on_new_span(attrs, id, ctx);
    }
    fn on_enter(&self, id: &span::Id, ctx: Context<'_, S>) {
        if self.budget.reserve_callback() {
            self.inner.on_enter(id, ctx);
        }
    }
    fn on_exit(&self, id: &span::Id, ctx: Context<'_, S>) {
        if self.budget.reserve_callback() {
            self.inner.on_exit(id, ctx);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn upstream_callback_budget_saturates_without_panicking() {
        let budget = Budget::default();
        for _ in 0..MAX_CALLBACKS {
            assert!(budget.reserve_callback());
        }
        assert!(!budget.exceeded());
        assert!(!budget.reserve_callback());
        assert!(budget.exceeded());
        for _ in 0..100 {
            assert!(!budget.reserve_callback());
        }
    }
}
