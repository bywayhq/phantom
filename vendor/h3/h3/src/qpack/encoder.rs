use std::{cmp, io::Cursor};

use bytes::{Buf, BufMut, BytesMut};

use super::{
    block::{
        HeaderPrefix, Indexed, IndexedWithPostBase, Literal, LiteralWithNameRef,
        LiteralWithPostBaseNameRef,
    },
    dynamic::{
        DynamicInsertionResult, DynamicLookupResult, DynamicTable, DynamicTableEncoder,
        Error as DynamicTableError,
    },
    parse_error::ParseError,
    prefix_int::Error as IntError,
    prefix_string::Error as StringError,
    static_::StaticTable,
    stream::{
        DecoderInstruction, Duplicate, DynamicTableSizeUpdate, HeaderAck, InsertCountIncrement,
        InsertWithNameRef, InsertWithoutNameRef, StreamCancel,
    },
    HeaderField,
};

const MAX_BUFFERED_DECODER_INSTRUCTION_BYTES: usize = 64 * 1024;

#[derive(Debug, PartialEq)]
pub enum EncoderError {
    Insertion(DynamicTableError),
    InvalidString(StringError),
    InvalidInteger(IntError),
    UnknownDecoderInstruction(u8),
    InstructionBufferTooLarge(usize),
}

impl std::error::Error for EncoderError {}

impl std::fmt::Display for EncoderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncoderError::Insertion(e) => write!(f, "dynamic table insertion: {:?}", e),
            EncoderError::InvalidString(e) => write!(f, "could not parse string: {}", e),
            EncoderError::InvalidInteger(e) => write!(f, "could not parse integer: {}", e),
            EncoderError::UnknownDecoderInstruction(e) => {
                write!(f, "got unkown decoder instruction: {}", e)
            }
            EncoderError::InstructionBufferTooLarge(size) => {
                write!(f, "decoder instruction buffer too large: {size} bytes")
            }
        }
    }
}

pub struct Encoder {
    table: DynamicTable,
    decoder_stream: BytesMut,
}

impl Encoder {
    pub fn set_max_table_capacity<W: BufMut>(
        &mut self,
        capacity: usize,
        encoder_buf: &mut W,
    ) -> Result<(), EncoderError> {
        self.table.set_max_size(capacity)?;
        DynamicTableSizeUpdate(capacity).encode(encoder_buf);
        Ok(())
    }

    pub fn set_max_blocked_streams(&mut self, blocked_streams: usize) -> Result<(), EncoderError> {
        self.table.set_max_blocked(blocked_streams)?;
        Ok(())
    }

    pub fn encode<W, T, H>(
        &mut self,
        stream_id: u64,
        block: &mut W,
        encoder_buf: &mut W,
        fields: T,
    ) -> Result<usize, EncoderError>
    where
        W: BufMut,
        T: IntoIterator<Item = H>,
        H: AsRef<HeaderField>,
    {
        let fields = fields
            .into_iter()
            .map(|field| field.as_ref().clone())
            .collect::<Vec<_>>();
        let mut encoder_instructions = Vec::new();
        {
            let mut encoder = self.table.encoder(stream_id);
            for field in &fields {
                Self::plan_field(&mut encoder, &mut encoder_instructions, field)?;
            }
        }

        let mut required_ref = 0;
        let mut block_buf = Vec::new();
        let mut encoder = self.table.encoder(stream_id);

        for field in &fields {
            if let Some(reference) = Self::encode_field_line(&mut encoder, &mut block_buf, field)? {
                required_ref = cmp::max(required_ref, reference);
            }
        }

        HeaderPrefix::new(
            required_ref,
            encoder.base(),
            encoder.total_inserted(),
            encoder.max_size(),
        )
        .encode(block);
        block.put(block_buf.as_slice());
        encoder_buf.put(encoder_instructions.as_slice());

        encoder.commit(required_ref);

        Ok(required_ref)
    }

    pub fn on_decoder_recv<R: Buf>(&mut self, read: &mut R) -> Result<(), EncoderError> {
        while read.has_remaining() {
            if self.decoder_stream.len() == MAX_BUFFERED_DECODER_INSTRUCTION_BYTES
                && !self.apply_decoder_instructions()?
            {
                return Err(EncoderError::InstructionBufferTooLarge(
                    self.decoder_stream.len().saturating_add(read.remaining()),
                ));
            }

            let available = MAX_BUFFERED_DECODER_INSTRUCTION_BYTES - self.decoder_stream.len();
            let mut chunk = read.take(available.min(read.remaining()));
            self.decoder_stream.put(&mut chunk);
            let progressed = self.apply_decoder_instructions()?;
            if !progressed
                && self.decoder_stream.len() == MAX_BUFFERED_DECODER_INSTRUCTION_BYTES
                && read.has_remaining()
            {
                return Err(EncoderError::InstructionBufferTooLarge(
                    self.decoder_stream.len().saturating_add(read.remaining()),
                ));
            }
        }

        Ok(())
    }

    fn apply_decoder_instructions(&mut self) -> Result<bool, EncoderError> {
        let mut progressed = false;
        loop {
            let (instruction, consumed) = {
                let mut buffered = Cursor::new(self.decoder_stream.as_ref());
                let Some(instruction) = Action::parse(&mut buffered)? else {
                    break;
                };
                (instruction, buffered.position() as usize)
            };
            self.decoder_stream.advance(consumed);
            progressed = true;

            match instruction {
                Action::HeaderAck(stream_id) => self.table.acknowledge_block(stream_id)?,
                Action::StreamCancel(stream_id) => match self.table.cancel_stream(stream_id) {
                    Ok(()) | Err(DynamicTableError::UnknownStreamId(_)) => {}
                    Err(error) => return Err(error.into()),
                },
                Action::ReceivedRefIncrement(increment) => {
                    self.table.update_largest_received(increment)?
                }
            }
        }
        Ok(progressed)
    }

    fn plan_field<W: BufMut>(
        table: &mut DynamicTableEncoder,
        encoder: &mut W,
        field: &HeaderField,
    ) -> Result<(), EncoderError> {
        if StaticTable::find(field).is_some() {
            return Ok(());
        }
        if !matches!(table.find(field), DynamicLookupResult::NotFound) {
            return Ok(());
        }

        Self::insert_field(table, encoder, field)?;
        Ok(())
    }

    fn encode_field_line<W: BufMut>(
        table: &mut DynamicTableEncoder,
        block: &mut W,
        field: &HeaderField,
    ) -> Result<Option<usize>, EncoderError> {
        if let Some(index) = StaticTable::find(field) {
            Indexed::Static(index).encode(block);
            return Ok(None);
        }

        match table.find(field) {
            DynamicLookupResult::Relative { index, absolute } => {
                Indexed::Dynamic(index).encode(block);
                Ok(Some(absolute))
            }
            DynamicLookupResult::PostBase { index, absolute } => {
                IndexedWithPostBase(index).encode(block);
                Ok(Some(absolute))
            }
            DynamicLookupResult::Static(index) => {
                LiteralWithNameRef::new_static(index, field.value.clone()).encode(block)?;
                Ok(None)
            }
            DynamicLookupResult::NotFound => match table.find_name(&field.name) {
                DynamicLookupResult::Static(index) => {
                    LiteralWithNameRef::new_static(index, field.value.clone()).encode(block)?;
                    Ok(None)
                }
                DynamicLookupResult::Relative { index, absolute } => {
                    LiteralWithNameRef::new_dynamic(index, field.value.clone()).encode(block)?;
                    Ok(Some(absolute))
                }
                DynamicLookupResult::PostBase { index, absolute } => {
                    LiteralWithPostBaseNameRef::new(index, field.value.clone()).encode(block)?;
                    Ok(Some(absolute))
                }
                DynamicLookupResult::NotFound => {
                    Literal::new(field.name.clone(), field.value.clone()).encode(block)?;
                    Ok(None)
                }
            },
        }
    }

    fn insert_field<W: BufMut>(
        table: &mut DynamicTableEncoder,
        encoder: &mut W,
        field: &HeaderField,
    ) -> Result<DynamicInsertionResult, EncoderError> {
        let insertion = table.insert(field)?;
        match &insertion {
            DynamicInsertionResult::Duplicated { relative, .. } => {
                Duplicate(*relative).encode(encoder);
            }
            DynamicInsertionResult::Inserted { .. } => {
                InsertWithoutNameRef::new(field.name.clone(), field.value.clone())
                    .encode(encoder)?;
            }
            DynamicInsertionResult::InsertedWithStaticNameRef { index, .. } => {
                InsertWithNameRef::new_static(*index, field.value.clone()).encode(encoder)?;
            }
            DynamicInsertionResult::InsertedWithNameRef { relative, .. } => {
                InsertWithNameRef::new_dynamic(*relative, field.value.clone()).encode(encoder)?;
            }
            DynamicInsertionResult::NotInserted(_) => {}
        }
        Ok(insertion)
    }

    #[cfg(test)]
    fn encode_field<W: BufMut>(
        table: &mut DynamicTableEncoder,
        block: &mut Vec<u8>,
        encoder: &mut W,
        field: &HeaderField,
    ) -> Result<Option<usize>, EncoderError> {
        if let Some(index) = StaticTable::find(field) {
            Indexed::Static(index).encode(block);
            return Ok(None);
        }

        if let DynamicLookupResult::Relative { index, absolute } = table.find(field) {
            Indexed::Dynamic(index).encode(block);
            return Ok(Some(absolute));
        }

        let reference = match Self::insert_field(table, encoder, field)? {
            DynamicInsertionResult::Duplicated {
                postbase, absolute, ..
            } => {
                IndexedWithPostBase(postbase).encode(block);
                Some(absolute)
            }
            DynamicInsertionResult::Inserted { postbase, absolute } => {
                IndexedWithPostBase(postbase).encode(block);
                Some(absolute)
            }
            DynamicInsertionResult::InsertedWithStaticNameRef {
                postbase, absolute, ..
            } => {
                IndexedWithPostBase(postbase).encode(block);
                Some(absolute)
            }
            DynamicInsertionResult::InsertedWithNameRef {
                postbase, absolute, ..
            } => {
                IndexedWithPostBase(postbase).encode(block);
                Some(absolute)
            }
            DynamicInsertionResult::NotInserted(lookup_result) => match lookup_result {
                DynamicLookupResult::Static(index) => {
                    LiteralWithNameRef::new_static(index, field.value.clone()).encode(block)?;
                    None
                }
                DynamicLookupResult::Relative { index, absolute } => {
                    LiteralWithNameRef::new_dynamic(index, field.value.clone()).encode(block)?;
                    Some(absolute)
                }
                DynamicLookupResult::PostBase { index, absolute } => {
                    LiteralWithPostBaseNameRef::new(index, field.value.clone()).encode(block)?;
                    Some(absolute)
                }
                DynamicLookupResult::NotFound => {
                    Literal::new(field.name.clone(), field.value.clone()).encode(block)?;
                    None
                }
            },
        };
        Ok(reference)
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self {
            table: DynamicTable::new(),
            decoder_stream: BytesMut::new(),
        }
    }
}

pub fn encode_stateless<W, T, H>(block: &mut W, fields: T) -> Result<u64, EncoderError>
where
    W: BufMut,
    T: IntoIterator<Item = H>,
    H: AsRef<HeaderField>,
{
    let mut size = 0;

    HeaderPrefix::new(0, 0, 0, 0).encode(block);
    for field in fields {
        let field = field.as_ref();

        if let Some(index) = StaticTable::find(field) {
            Indexed::Static(index).encode(block);
        } else if let Some(index) = StaticTable::find_name(&field.name) {
            LiteralWithNameRef::new_static(index, field.value.clone()).encode(block)?;
        } else {
            Literal::new(field.name.clone(), field.value.clone()).encode(block)?;
        }

        size += field.mem_size() as u64;
    }
    Ok(size)
}

#[cfg(test)]
impl From<DynamicTable> for Encoder {
    fn from(table: DynamicTable) -> Encoder {
        Encoder {
            table,
            decoder_stream: BytesMut::new(),
        }
    }
}

// Action to apply to the encoder table, given an instruction received from the decoder.
#[derive(Debug, PartialEq)]
enum Action {
    ReceivedRefIncrement(u64),
    HeaderAck(u64),
    StreamCancel(u64),
}

impl Action {
    fn parse<R: Buf>(read: &mut R) -> Result<Option<Action>, EncoderError> {
        if read.remaining() < 1 {
            return Ok(None);
        }

        let mut buf = Cursor::new(read.chunk());
        let first = buf.chunk()[0];
        let instruction = match DecoderInstruction::decode(first) {
            DecoderInstruction::Unknown => {
                return Err(EncoderError::UnknownDecoderInstruction(first))
            }
            DecoderInstruction::InsertCountIncrement => {
                InsertCountIncrement::decode(&mut buf)?.map(|x| Action::ReceivedRefIncrement(x.0))
            }
            DecoderInstruction::HeaderAck => {
                HeaderAck::decode(&mut buf)?.map(|x| Action::HeaderAck(x.0))
            }
            DecoderInstruction::StreamCancel => {
                StreamCancel::decode(&mut buf)?.map(|x| Action::StreamCancel(x.0))
            }
        };

        if instruction.is_some() {
            let pos = buf.position();
            read.advance(pos as usize);
        }

        Ok(instruction)
    }
}

pub fn set_dynamic_table_size<W: BufMut>(
    table: &mut DynamicTable,
    encoder: &mut W,
    size: usize,
) -> Result<(), EncoderError> {
    table.set_max_size(size)?;
    DynamicTableSizeUpdate(size).encode(encoder);
    Ok(())
}

impl From<DynamicTableError> for EncoderError {
    fn from(e: DynamicTableError) -> Self {
        EncoderError::Insertion(e)
    }
}

impl From<StringError> for EncoderError {
    fn from(e: StringError) -> Self {
        EncoderError::InvalidString(e)
    }
}

impl From<ParseError> for EncoderError {
    fn from(e: ParseError) -> Self {
        match e {
            ParseError::Integer(x) => EncoderError::InvalidInteger(x),
            ParseError::String(x) => EncoderError::InvalidString(x),
            ParseError::InvalidPrefix(x) => EncoderError::UnknownDecoderInstruction(x),
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use bytes::Bytes;

    use crate::{
        buf::BufList,
        qpack::tests::helpers::{build_table, build_table_with_size, TABLE_SIZE},
    };

    #[allow(clippy::type_complexity)]
    fn check_encode_field(
        init_fields: &[HeaderField],
        field: &[HeaderField],
        check: &dyn Fn(&mut Cursor<&mut Vec<u8>>, &mut Cursor<&mut Vec<u8>>),
    ) {
        let mut table = build_table();
        table.set_max_size(TABLE_SIZE).unwrap();
        check_encode_field_table(&mut table, init_fields, field, 1, check);
    }

    #[allow(clippy::type_complexity)]
    fn check_encode_field_table(
        table: &mut DynamicTable,
        init_fields: &[HeaderField],
        field: &[HeaderField],
        stream_id: u64,
        check: &dyn Fn(&mut Cursor<&mut Vec<u8>>, &mut Cursor<&mut Vec<u8>>),
    ) {
        for field in init_fields {
            table.put(field.clone()).unwrap();
        }

        let mut encoder = Vec::new();
        let mut block = Vec::new();
        let mut enc_table = table.encoder(stream_id);

        for field in field {
            Encoder::encode_field(&mut enc_table, &mut block, &mut encoder, field).unwrap();
        }

        enc_table.commit(field.len());

        let mut read_block = Cursor::new(&mut block);
        let mut read_encoder = Cursor::new(&mut encoder);
        check(&mut read_block, &mut read_encoder);
    }

    #[test]
    fn encode_static() {
        let field = HeaderField::new(":method", "GET");
        check_encode_field(&[], &[field], &|mut b, e| {
            assert_eq!(Indexed::decode(&mut b), Ok(Indexed::Static(17)));
            assert_eq!(e.get_ref().len(), 0);
        });
    }

    #[test]
    fn encode_static_nameref() {
        let field = HeaderField::new("location", "/bar");
        check_encode_field(&[], &[field], &|mut b, mut e| {
            assert_eq!(
                IndexedWithPostBase::decode(&mut b),
                Ok(IndexedWithPostBase(0))
            );
            assert_eq!(
                InsertWithNameRef::decode(&mut e),
                Ok(Some(InsertWithNameRef::new_static(12, "/bar")))
            );
        });
    }

    #[test]
    fn encode_static_nameref_indexed_in_dynamic() {
        let field = HeaderField::new("location", "/bar");
        check_encode_field(
            std::slice::from_ref(&field),
            std::slice::from_ref(&field),
            &|mut b, e| {
                assert_eq!(Indexed::decode(&mut b), Ok(Indexed::Dynamic(0)));
                assert_eq!(e.get_ref().len(), 0);
            },
        );
    }

    #[test]
    fn encode_dynamic_insert() {
        let field = HeaderField::new("foo", "bar");
        check_encode_field(&[], &[field], &|mut b, mut e| {
            assert_eq!(
                IndexedWithPostBase::decode(&mut b),
                Ok(IndexedWithPostBase(0))
            );
            assert_eq!(
                InsertWithoutNameRef::decode(&mut e),
                Ok(Some(InsertWithoutNameRef::new("foo", "bar")))
            );
        });
    }

    #[test]
    fn encode_dynamic_insert_nameref() {
        let field = HeaderField::new("foo", "bar");
        check_encode_field(
            &[field.clone(), HeaderField::new("baz", "bar")],
            &[field.with_value("quxx")],
            &|mut b, mut e| {
                assert_eq!(
                    IndexedWithPostBase::decode(&mut b),
                    Ok(IndexedWithPostBase(0))
                );
                assert_eq!(
                    InsertWithNameRef::decode(&mut e),
                    Ok(Some(InsertWithNameRef::new_dynamic(1, "quxx")))
                );
            },
        );
    }

    #[test]
    fn encode_literal() {
        let mut table = build_table();
        table.set_max_size(0).unwrap();
        let field = HeaderField::new("foo", "bar");
        check_encode_field_table(&mut table, &[], &[field], 1, &|mut b, e| {
            assert_eq!(Literal::decode(&mut b), Ok(Literal::new("foo", "bar")));
            assert_eq!(e.get_ref().len(), 0);
        });
    }

    #[test]
    fn encode_literal_nameref() {
        let mut table = build_table();
        table.set_max_size(63).unwrap();
        let field = HeaderField::new("foo", "bar");

        check_encode_field_table(
            &mut table,
            &[],
            std::slice::from_ref(&field),
            1,
            &|mut b, _| {
                assert_eq!(
                    IndexedWithPostBase::decode(&mut b),
                    Ok(IndexedWithPostBase(0))
                );
            },
        );
        check_encode_field_table(
            &mut table,
            std::slice::from_ref(&field),
            &[field.with_value("quxx")],
            2,
            &|mut b, e| {
                assert_eq!(
                    LiteralWithNameRef::decode(&mut b),
                    Ok(LiteralWithNameRef::new_dynamic(0, "quxx"))
                );
                assert_eq!(e.get_ref().len(), 0);
            },
        );
    }

    #[test]
    fn encode_literal_postbase_nameref() {
        let mut table = build_table();
        table.set_max_size(63).unwrap();
        let field = HeaderField::new("foo", "bar");
        check_encode_field_table(
            &mut table,
            &[],
            &[field.clone(), field.with_value("quxx")],
            1,
            &|mut b, mut e| {
                assert_eq!(
                    IndexedWithPostBase::decode(&mut b),
                    Ok(IndexedWithPostBase(0))
                );
                assert_eq!(
                    LiteralWithPostBaseNameRef::decode(&mut b),
                    Ok(LiteralWithPostBaseNameRef::new(0, "quxx"))
                );
                assert_eq!(
                    InsertWithoutNameRef::decode(&mut e),
                    Ok(Some(InsertWithoutNameRef::new("foo", "bar")))
                );
            },
        );
    }

    #[test]
    fn encode_with_header_block() {
        let mut table = build_table();

        for idx in 1..5 {
            table
                .put(HeaderField::new(
                    format!("foo{}", idx),
                    format!("bar{}", idx),
                ))
                .unwrap();
        }

        let mut encoder_buf = Vec::new();
        let mut block = Vec::new();
        let mut encoder = Encoder::from(table);

        let fields = vec![
            HeaderField::new(":method", "GET"),
            HeaderField::new("foo1", "bar1"),
            HeaderField::new("foo3", "new bar3"),
            HeaderField::new(":method", "staticnameref"),
            HeaderField::new("newfoo", "newbar"),
        ]
        .into_iter();

        assert_eq!(
            encoder.encode(1, &mut block, &mut encoder_buf, fields),
            Ok(7)
        );

        let mut read_block = Cursor::new(&mut block);
        let mut read_encoder = Cursor::new(&mut encoder_buf);

        assert_eq!(
            InsertWithNameRef::decode(&mut read_encoder),
            Ok(Some(InsertWithNameRef::new_dynamic(1, "new bar3")))
        );
        assert_eq!(
            InsertWithNameRef::decode(&mut read_encoder),
            Ok(Some(InsertWithNameRef::new_static(
                StaticTable::find_name(&b":method"[..]).unwrap(),
                "staticnameref"
            )))
        );
        assert_eq!(
            InsertWithoutNameRef::decode(&mut read_encoder),
            Ok(Some(InsertWithoutNameRef::new("newfoo", "newbar")))
        );

        assert_eq!(
            HeaderPrefix::decode(&mut read_block)
                .unwrap()
                .get(7, TABLE_SIZE),
            Ok((7, 7))
        );
        assert_eq!(Indexed::decode(&mut read_block), Ok(Indexed::Static(17)));
        assert_eq!(Indexed::decode(&mut read_block), Ok(Indexed::Dynamic(6)));
        assert_eq!(Indexed::decode(&mut read_block), Ok(Indexed::Dynamic(2)));
        assert_eq!(Indexed::decode(&mut read_block), Ok(Indexed::Dynamic(1)));
        assert_eq!(Indexed::decode(&mut read_block), Ok(Indexed::Dynamic(0)));
        assert_eq!(read_block.get_ref().len() as u64, read_block.position());
    }

    #[test]
    fn invalid_peer_limits_do_not_change_encoder_state_or_output() {
        let mut encoder = Encoder::default();
        let mut instructions = vec![0xaa];

        assert_eq!(
            encoder.set_max_table_capacity(1 << 30, &mut instructions),
            Err(EncoderError::Insertion(
                DynamicTableError::MaximumTableSizeTooLarge
            ))
        );
        assert_eq!(instructions, [0xaa]);
        assert_eq!(
            encoder.set_max_blocked_streams(1 << 16),
            Err(EncoderError::Insertion(
                DynamicTableError::MaxBlockedStreamsTooLarge
            ))
        );

        encoder
            .set_max_table_capacity(TABLE_SIZE, &mut instructions)
            .unwrap();
        encoder.set_max_blocked_streams(16).unwrap();
        assert_eq!(&instructions[1..], [0x3f, 0xe1, 0x1f]);
    }

    #[test]
    fn feedback_preserves_dynamic_references_across_sections() {
        let field = HeaderField::new("x-dynamic", "compressible value");
        let mut encoder = Encoder::default();
        let mut setup = Vec::new();
        encoder
            .set_max_table_capacity(TABLE_SIZE, &mut setup)
            .unwrap();
        encoder.set_max_blocked_streams(1).unwrap();

        let mut first_block = Vec::new();
        let mut first_instructions = Vec::new();
        assert_eq!(
            encoder.encode(
                0,
                &mut first_block,
                &mut first_instructions,
                [field.clone()]
            ),
            Ok(1)
        );
        assert!(!first_instructions.is_empty());

        let mut blocked_block = Vec::new();
        let mut blocked_instructions = Vec::new();
        assert_eq!(
            encoder.encode(
                4,
                &mut blocked_block,
                &mut blocked_instructions,
                [HeaderField::new("x-next", "value")]
            ),
            Ok(0)
        );
        assert!(blocked_instructions.is_empty());

        let mut feedback = Vec::new();
        InsertCountIncrement(1).encode(&mut feedback);
        HeaderAck(0).encode(&mut feedback);
        encoder.on_decoder_recv(&mut Cursor::new(feedback)).unwrap();

        let mut reused_block = Vec::new();
        let mut reused_instructions = Vec::new();
        assert_eq!(
            encoder.encode(8, &mut reused_block, &mut reused_instructions, [field]),
            Ok(1)
        );
        assert!(reused_instructions.is_empty());
        let mut reused = Cursor::new(reused_block);
        assert_eq!(
            HeaderPrefix::decode(&mut reused)
                .unwrap()
                .get(1, TABLE_SIZE),
            Ok((1, 1))
        );
        assert_eq!(Indexed::decode(&mut reused), Ok(Indexed::Dynamic(0)));
    }

    #[test]
    fn decoder_block_ack() {
        let mut table = build_table();

        let field = HeaderField::new("foo", "bar");
        check_encode_field_table(
            &mut table,
            &[],
            &[field.clone(), field.with_value("quxx")],
            2,
            &|_, _| {},
        );

        let mut buf = vec![];
        let mut encoder = Encoder::from(table);

        HeaderAck(2).encode(&mut buf);
        let mut cur = Cursor::new(&buf);
        assert_eq!(Action::parse(&mut cur), Ok(Some(Action::HeaderAck(2))));

        let mut cur = Cursor::new(&buf);
        assert_eq!(encoder.on_decoder_recv(&mut cur), Ok(()),);

        let mut cur = Cursor::new(&buf);
        assert_eq!(
            encoder.on_decoder_recv(&mut cur),
            Err(EncoderError::Insertion(DynamicTableError::UnknownStreamId(
                2
            )))
        );
    }

    #[test]
    fn decoder_stream_canceled() {
        let mut table = build_table();

        let field = HeaderField::new("foo", "bar");
        check_encode_field_table(
            &mut table,
            &[],
            &[field.clone(), field.with_value("quxx")],
            2,
            &|_, _| {},
        );

        let mut buf = vec![];

        StreamCancel(2).encode(&mut buf);
        let mut cur = Cursor::new(&buf);
        assert_eq!(Action::parse(&mut cur), Ok(Some(Action::StreamCancel(2))));

        let mut encoder = Encoder::default();
        assert_eq!(encoder.on_decoder_recv(&mut Cursor::new(buf)), Ok(()));
    }

    #[test]
    fn decoder_accept_truncated() {
        let mut buf = vec![];
        StreamCancel(2321).encode(&mut buf);

        let mut cur = Cursor::new(&buf[..2]); // trucated prefix_int
        assert_eq!(Action::parse(&mut cur), Ok(None));

        let mut cur = Cursor::new(&buf);
        assert_eq!(
            Action::parse(&mut cur),
            Ok(Some(Action::StreamCancel(2321)))
        );
    }

    #[test]
    fn decoder_unknown_stream() {
        let mut table = build_table();

        check_encode_field_table(
            &mut table,
            &[],
            &[HeaderField::new("foo", "bar")],
            2,
            &|_, _| {},
        );
        let mut encoder = Encoder::from(table);

        let mut buf = vec![];
        HeaderAck(4).encode(&mut buf);

        let mut cur = Cursor::new(&buf);
        assert_eq!(
            encoder.on_decoder_recv(&mut cur),
            Err(EncoderError::Insertion(DynamicTableError::UnknownStreamId(
                4
            )))
        );
    }

    #[test]
    fn insert_count() {
        let mut buf = vec![];
        InsertCountIncrement(4).encode(&mut buf);

        let mut cur = Cursor::new(&buf);
        assert_eq!(
            Action::parse(&mut cur),
            Ok(Some(Action::ReceivedRefIncrement(4)))
        );

        let mut encoder = Encoder::from(build_table_with_size(4));

        let mut cur = Cursor::new(&buf);
        assert_eq!(encoder.on_decoder_recv(&mut cur), Ok(()));
    }

    #[test]
    fn decoder_instruction_accepts_one_byte_buf_chunks() {
        let stream_id = 2321;
        let mut encoder = Encoder::from(build_table());
        encoder
            .encode(
                stream_id,
                &mut Vec::new(),
                &mut Vec::new(),
                &[HeaderField::new("foo", "bar")],
            )
            .unwrap();

        let mut wire = Vec::new();
        HeaderAck(stream_id).encode(&mut wire);
        let mut fragmented = BufList::new();
        for byte in wire {
            fragmented.push(Bytes::copy_from_slice(&[byte]));
        }

        assert_eq!(encoder.on_decoder_recv(&mut fragmented), Ok(()));
        assert!(!fragmented.has_remaining());
    }

    #[test]
    fn invalid_insert_count_increments_are_rejected() {
        for increment in [0, 2] {
            let mut encoder = Encoder::from(build_table_with_size(1));
            let mut wire = Vec::new();
            InsertCountIncrement(increment).encode(&mut wire);
            assert_eq!(
                encoder.on_decoder_recv(&mut Cursor::new(wire)),
                Err(EncoderError::Insertion(
                    DynamicTableError::InvalidInsertCountIncrement {
                        increment,
                        known_received: 0,
                        total_inserted: 1,
                    }
                ))
            );
        }
    }

    #[test]
    fn overflowing_insert_count_increment_is_rejected() {
        let mut encoder = Encoder::default();
        let wire = [
            0x3f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02,
        ];

        assert_eq!(
            encoder.on_decoder_recv(&mut Cursor::new(wire)),
            Err(EncoderError::InvalidInteger(IntError::Overflow))
        );
    }

    #[test]
    fn large_coalesced_decoder_instructions_are_processed_incrementally() {
        let mut encoder = Encoder::default();
        let mut instructions = Cursor::new(vec![0x40; MAX_BUFFERED_DECODER_INSTRUCTION_BYTES + 1]);

        assert_eq!(encoder.on_decoder_recv(&mut instructions), Ok(()));
        assert!(encoder.decoder_stream.is_empty());
    }
}
