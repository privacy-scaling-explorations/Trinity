use crate::commit::{KZGType, Trinity, TrinityMsg, TrinityReceiver, TrinitySender};
use async_trait::async_trait;
use mpz_ot::{
    chou_orlandi::{Sender, SenderError},
    OTError, OTReceiver, OTReceiverOutput, OTSender, OTSenderOutput, OTSetup, TransferId,
};
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
