use crate::commit::{TrinityReceiver, TrinitySender};
use std::marker::PhantomData;

#[allow(dead_code)]
pub struct KZGOTSender<'a, Ctx> {
    pub(crate) trinity_sender: TrinitySender<'a>,
    pub(crate) _phantom: PhantomData<Ctx>,
}

#[allow(dead_code)]
pub struct KZGOTReceiver<'a, Ctx> {
    pub(crate) trinity_receiver: TrinityReceiver<'a>,
    pub(crate) _phantom: PhantomData<Ctx>,
}
