use crate::commit::{TrinityReceiver, TrinitySender};
use std::marker::PhantomData;

pub struct Block([u8; 16]);

pub struct KZGOTSender<'a, Ctx> {
    pub(crate) trinity_sender: TrinitySender<'a>,
    pub(crate) _phantom: PhantomData<Ctx>,
}

pub struct KZGOTReceiver<'a, Ctx> {
    pub(crate) trinity_receiver: TrinityReceiver<'a>,
    pub(crate) _phantom: PhantomData<Ctx>,
}
