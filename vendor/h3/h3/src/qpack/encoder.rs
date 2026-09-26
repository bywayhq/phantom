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
use crate::config::{QpackHuffman, QpackInsertPolicy};

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

#[derive(Clone)]
pub struct Encoder {
    table: DynamicTable,
    decoder_stream: BytesMut,
    insert_policy: QpackInsertPolicy,
    huffman: QpackHuffman,
}

impl Encoder {
    /// Creates an encoder with the given insertion and Huffman policies.
    pub fn with_policy(insert_policy: QpackInsertPolicy, huffman: QpackHuffman) -> Self {
        Self {
            insert_policy,
            huffman,
            ..Self::default()
        }
    }

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
        let mut table = self.table.clone();
        let fields = fields
            .into_iter()
            .map(|field| field.as_ref().clone())
            .collect::<Vec<_>>();
        if self.insert_policy == QpackInsertPolicy::UnmatchedNames {
            let required_ref =
                self.encode_unmatched_names(&mut table, stream_id, block, encoder_buf, &fields)?;
            self.table = table;
            return Ok(required_ref);
        }
        let always_huffman = self.huffman == QpackHuffman::Always;
        let mut encoder_instructions = Vec::new();
        {
            let mut encoder = table.encoder(stream_id);
            for field in &fields {
                Self::plan_field(
                    &mut encoder,
                    &mut encoder_instructions,
                    field,
                    always_huffman,
                )?;
            }
        }

        let mut required_ref = 0;
        let mut block_buf = Vec::new();
        let mut encoder = table.encoder(stream_id);

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
        drop(encoder);
        self.table = table;

        Ok(required_ref)
    }

    /// Encodes one field section as neqo's `Encoder::encode_header_block`
    /// does, in a single pass over the fields.
    ///
    /// Each field takes the first form that applies: a never-indexed literal
    /// when sensitive; an exact static match; an exact dynamic match; a
    /// literal with a static name reference; a literal with a dynamic name
    /// reference; an Insert With Literal Name instruction referenced with a
    /// post-base index; or a literal with a literal name. Dynamic entries the
    /// decoder has not acknowledged count only while the section may block.
    /// Once an insert fails, the rest of the section inserts nothing.
    fn encode_unmatched_names<W: BufMut>(
        &self,
        table: &mut DynamicTable,
        stream_id: u64,
        block: &mut W,
        encoder_buf: &mut W,
        fields: &[HeaderField],
    ) -> Result<usize, EncoderError> {
        let always_huffman = self.huffman == QpackHuffman::Always;
        let mut required_ref = 0;
        let mut block_buf = Vec::new();
        let mut instructions = Vec::new();
        let mut encoder = table.encoder_at_insert_count(stream_id);
        let can_block = encoder.can_block();
        let mut insert_failed = false;

        for field in fields {
            let reference = if field.sensitive {
                Self::encode_sensitive_field(&mut block_buf, field)?;
                None
            } else if let Some(index) = StaticTable::find(field) {
                Indexed::Static(index).encode(&mut block_buf);
                None
            } else {
                match encoder.find(field) {
                    DynamicLookupResult::Relative { index, absolute } => {
                        Indexed::Dynamic(index).encode(&mut block_buf);
                        Some(absolute)
                    }
                    DynamicLookupResult::PostBase { index, absolute } => {
                        IndexedWithPostBase(index).encode(&mut block_buf);
                        Some(absolute)
                    }
                    DynamicLookupResult::Static(_) | DynamicLookupResult::NotFound => {
                        Self::encode_name_reference_or_insert(
                            &mut encoder,
                            &mut block_buf,
                            &mut instructions,
                            field,
                            can_block && !insert_failed,
                            always_huffman,
                            &mut insert_failed,
                        )?
                    }
                }
            };
            if let Some(reference) = reference {
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
        encoder_buf.put(instructions.as_slice());
        encoder.commit(required_ref);
        Ok(required_ref)
    }

    /// Encodes a field with no exact match: a literal with a static name
    /// reference, then one with a dynamic name reference, then an insert
    /// when `may_insert`, and otherwise a literal with a literal name.
    fn encode_name_reference_or_insert(
        encoder: &mut DynamicTableEncoder,
        block: &mut Vec<u8>,
        instructions: &mut Vec<u8>,
        field: &HeaderField,
        may_insert: bool,
        always_huffman: bool,
        insert_failed: &mut bool,
    ) -> Result<Option<usize>, EncoderError> {
        match encoder.find_name(&field.name) {
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
                if may_insert {
                    if let Some((postbase, absolute)) = encoder.insert_literal_name(field)? {
                        InsertWithoutNameRef::new(field.name.clone(), field.value.clone())
                            .encode_with(instructions, always_huffman)?;
                        IndexedWithPostBase(postbase).encode(block);
                        return Ok(Some(absolute));
                    }
                    *insert_failed = true;
                }
                Literal::new(field.name.clone(), field.value.clone()).encode(block)?;
                Ok(None)
            }
        }
    }

    pub fn cancel_stream(&mut self, stream_id: u64) -> Result<(), EncoderError> {
        match self.table.cancel_stream(stream_id) {
            Ok(()) | Err(DynamicTableError::UnknownStreamId(_)) => Ok(()),
            Err(error) => Err(error.into()),
        }
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
        always_huffman: bool,
    ) -> Result<(), EncoderError> {
        if field.sensitive {
            return Ok(());
        }
        if StaticTable::find(field).is_some() {
            return Ok(());
        }
        if !matches!(table.find(field), DynamicLookupResult::NotFound) {
            return Ok(());
        }

        Self::insert_field(table, encoder, field, always_huffman)?;
        Ok(())
    }

    fn encode_field_line<W: BufMut>(
        table: &mut DynamicTableEncoder,
        block: &mut W,
        field: &HeaderField,
    ) -> Result<Option<usize>, EncoderError> {
        if field.sensitive {
            Self::encode_sensitive_field(block, field)?;
            return Ok(None);
        }
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

    fn encode_sensitive_field<W: BufMut>(
        block: &mut W,
        field: &HeaderField,
    ) -> Result<(), EncoderError> {
        if let Some(index) = StaticTable::find_name(&field.name) {
            LiteralWithNameRef::new_static(index, field.value.clone())
                .with_sensitive(true)
                .encode(block)?;
        } else {
            Literal::new(field.name.clone(), field.value.clone())
                .with_sensitive(true)
                .encode(block)?;
        }
        Ok(())
    }

    fn insert_field<W: BufMut>(
        table: &mut DynamicTableEncoder,
        encoder: &mut W,
        field: &HeaderField,
        always_huffman: bool,
    ) -> Result<DynamicInsertionResult, EncoderError> {
        let insertion = table.insert(field)?;
        match &insertion {
            DynamicInsertionResult::Duplicated { relative, .. } => {
                Duplicate(*relative).encode(encoder);
            }
            DynamicInsertionResult::Inserted { .. } => {
                InsertWithoutNameRef::new(field.name.clone(), field.value.clone())
                    .encode_with(encoder, always_huffman)?;
            }
            DynamicInsertionResult::InsertedWithStaticNameRef { index, .. } => {
                InsertWithNameRef::new_static(*index, field.value.clone())
                    .encode_with(encoder, always_huffman)?;
            }
            DynamicInsertionResult::InsertedWithNameRef { relative, .. } => {
                InsertWithNameRef::new_dynamic(*relative, field.value.clone())
                    .encode_with(encoder, always_huffman)?;
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
        if field.sensitive {
            Self::encode_sensitive_field(block, field)?;
            return Ok(None);
        }
        if let Some(index) = StaticTable::find(field) {
            Indexed::Static(index).encode(block);
            return Ok(None);
        }

        if let DynamicLookupResult::Relative { index, absolute } = table.find(field) {
            Indexed::Dynamic(index).encode(block);
            return Ok(Some(absolute));
        }

        let reference = match Self::insert_field(table, encoder, field, false)? {
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
            insert_policy: QpackInsertPolicy::EveryField,
            huffman: QpackHuffman::WhenShorter,
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

        if field.sensitive {
            Encoder::encode_sensitive_field(block, field)?;
        } else if let Some(index) = StaticTable::find(field) {
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
            ..Encoder::default()
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

    /// The two HTTP/3 requests of the retained Firefox 156.0.1 snapshot
    /// (`fixtures/http3/firefox/156.0.1/windows-11-26200/snapshot-1.txt`),
    /// encoded against aioquic's advertised capacity of 4096 and 16 blocked
    /// streams with no decoder feedback in between.
    const FIREFOX_NAVIGATION: &[(&str, &str)] = &[
        (":method", "GET"),
        (":scheme", "https"),
        (":authority", "server.phantom.test:55589"),
        (":path", "/next?run=fe915979825822d9"),
        (
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:156.0) Gecko/20100101 Firefox/156.0",
        ),
        (
            "accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        ),
        ("accept-language", "en-US,en;q=0.9"),
        ("accept-encoding", "gzip, deflate, br, zstd"),
        (
            "referer",
            "https://server.phantom.test:55589/?run=fe915979825822d9",
        ),
        ("upgrade-insecure-requests", "1"),
        ("sec-fetch-dest", "document"),
        ("sec-fetch-mode", "navigate"),
        ("sec-fetch-site", "same-origin"),
        ("priority", "u=0, i"),
    ];
    const FIREFOX_FETCH: &[(&str, &str)] = &[
        (":method", "GET"),
        (":scheme", "https"),
        (":authority", "server.phantom.test:55589"),
        (":path", "/fetch?run=fe915979825822d9"),
        (
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:156.0) Gecko/20100101 Firefox/156.0",
        ),
        ("accept", "*/*"),
        ("accept-language", "en-US,en;q=0.9"),
        ("accept-encoding", "gzip, deflate, br, zstd"),
        (
            "referer",
            "https://server.phantom.test:55589/next?run=fe915979825822d9",
        ),
        ("alt-used", "server.phantom.test:55589"),
        ("sec-fetch-dest", "empty"),
        ("sec-fetch-mode", "cors"),
        ("sec-fetch-site", "same-origin"),
        ("priority", "u=4"),
        ("pragma", "no-cache"),
        ("cache-control", "no-cache"),
    ];
    /// `h3.request_qpack_encoder_stream_prefix_hex`: the stream type, the
    /// table capacity, and the navigation's four inserts.
    const FIREFOX_ENCODER_STREAM: &str =
        "023fe11f6a4148b4a549275a42a13f8690e4b692d49f6a4148b4a54927\
        5a93c85f86a87dcd30d25f6a4148b4a549275906497f8840e92ac7b0d31aaf66aec31ec327d785b6007d286f";
    const FIREFOX_NAVIGATION_BLOCK: &str =
        "0583d1d75092416cee5b17ae71d493d2ba4a84dc6db6de7f519462a2\
        f94ff965b541295f0b6fbafbc26de10a47ff5f50bcd07f66a281b0dae053fae46aa43f8429a77a8102e0fb5391\
        aa71afb53cb8d7da9677b816dc5c1fda988a4ea76040080010054c26b0b29fcb016dc5c15f0eb0497ca589d34d\
        1f43aeba0c41a4c7a98f33a69a3fdf9a68fa1d75d0620d263d4c79a68fbed00177febe58f9fbed00177b5f398b\
        2d4b70ddf45abefb4005df5f10929bd9abfa5242cb40d25fa523b3e94f684c9f5da89d29ad17186105b3b96c5e\
        b9c7524f4ae92a1371b6db79f63fcb2daa094af85b7dd7de136f08523fff1f10111213";
    const FIREFOX_FETCH_BLOCK: &str =
        "0781d1d75092416cee5b17ae71d493d2ba4a84dc6db6de7f51946252a493\
        ff965b541295f0b6fbafbc26de10a47f5f50bcd07f66a281b0dae053fae46aa43f8429a77a8102e0fb5391aa71\
        afb53cb8d7da9677b816dc5c1fda988a4ea76040080010054c26b0b29fcb016dc5c1dd5f398b2d4b70ddf45abe\
        fb4005df5f10929bd9abfa5242cb40d25fa523b3e94f684c9f5dab9d29ad17186105b3b96c5eb9c7524f4ae92a\
        1371b6db79f62a2f94ff965b541295f0b6fbafbc26de10a47f1043842d35a7d7428321ec47814083b606bf11e7";

    fn hex(encoded: &str) -> Vec<u8> {
        let compact: String = encoded.split_whitespace().collect();
        (0..compact.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&compact[index..index + 2], 16).unwrap())
            .collect()
    }

    fn fields(pairs: &[(&str, &str)]) -> Vec<HeaderField> {
        pairs
            .iter()
            .map(|(name, value)| HeaderField::new(*name, *value))
            .collect()
    }

    fn neqo_encoder(capacity: usize, blocked_streams: usize) -> (Encoder, Vec<u8>) {
        let mut encoder =
            Encoder::with_policy(QpackInsertPolicy::UnmatchedNames, QpackHuffman::Always);
        let mut instructions = Vec::new();
        encoder
            .set_max_table_capacity(capacity, &mut instructions)
            .unwrap();
        encoder.set_max_blocked_streams(blocked_streams).unwrap();
        (encoder, instructions)
    }

    #[test]
    fn unmatched_names_policy_reproduces_firefox_156_sections() {
        let (mut encoder, mut encoder_stream) = neqo_encoder(4096, 16);
        encoder_stream.insert(0, 0x02);

        let mut navigation = Vec::new();
        assert_eq!(
            encoder.encode(
                0,
                &mut navigation,
                &mut encoder_stream,
                fields(FIREFOX_NAVIGATION)
            ),
            Ok(4)
        );
        assert_eq!(encoder_stream, hex(FIREFOX_ENCODER_STREAM));
        assert_eq!(navigation, hex(FIREFOX_NAVIGATION_BLOCK));

        let mut fetch = Vec::new();
        let mut fetch_instructions = Vec::new();
        assert_eq!(
            encoder.encode(
                4,
                &mut fetch,
                &mut fetch_instructions,
                fields(FIREFOX_FETCH)
            ),
            Ok(6)
        );
        assert_eq!(fetch, hex(FIREFOX_FETCH_BLOCK));

        // The fetch inserts only its two fields whose names match no entry.
        let mut read = Cursor::new(fetch_instructions.as_slice());
        assert_eq!(
            InsertWithoutNameRef::decode(&mut read),
            Ok(Some(InsertWithoutNameRef::new(
                "alt-used",
                "server.phantom.test:55589"
            )))
        );
        assert_eq!(
            InsertWithoutNameRef::decode(&mut read),
            Ok(Some(InsertWithoutNameRef::new("pragma", "no-cache")))
        );
        assert_eq!(read.position() as usize, fetch_instructions.len());
        let mut always_huffman = Vec::new();
        InsertWithoutNameRef::new("alt-used", "server.phantom.test:55589")
            .encode_with(&mut always_huffman, true)
            .unwrap();
        InsertWithoutNameRef::new("pragma", "no-cache")
            .encode_with(&mut always_huffman, true)
            .unwrap();
        assert_eq!(fetch_instructions, always_huffman);
    }

    #[test]
    fn unmatched_names_policy_does_not_reference_unacknowledged_entries_without_block_budget() {
        let (mut encoder, _) = neqo_encoder(4096, 1);
        let mut instructions = Vec::new();
        encoder
            .encode(
                0,
                &mut Vec::new(),
                &mut instructions,
                [HeaderField::new("x-first", "value")],
            )
            .unwrap();
        assert!(!instructions.is_empty());

        // Stream 0 uses the only blocked-stream slot, so stream 4 may neither
        // reference the unacknowledged entry nor insert.
        let mut block = Vec::new();
        let mut instructions = Vec::new();
        assert_eq!(
            encoder.encode(
                4,
                &mut block,
                &mut instructions,
                [
                    HeaderField::new("x-first", "value"),
                    HeaderField::new("x-second", "value"),
                ]
            ),
            Ok(0)
        );
        assert!(instructions.is_empty());
        let mut read = Cursor::new(block);
        assert_eq!(
            HeaderPrefix::decode(&mut read).unwrap().get(1, 4096),
            Ok((0, 0))
        );
        assert_eq!(
            Literal::decode(&mut read),
            Ok(Literal::new("x-first", "value"))
        );
        assert_eq!(
            Literal::decode(&mut read),
            Ok(Literal::new("x-second", "value"))
        );

        // Once the insert is acknowledged, stream 4 indexes it.
        let mut feedback = Vec::new();
        InsertCountIncrement(1).encode(&mut feedback);
        encoder.on_decoder_recv(&mut Cursor::new(feedback)).unwrap();
        let mut block = Vec::new();
        assert_eq!(
            encoder.encode(
                4,
                &mut block,
                &mut Vec::new(),
                [HeaderField::new("x-first", "value")]
            ),
            Ok(1)
        );
        let mut read = Cursor::new(block);
        assert_eq!(
            HeaderPrefix::decode(&mut read).unwrap().get(1, 4096),
            Ok((1, 1))
        );
        assert_eq!(Indexed::decode(&mut read), Ok(Indexed::Dynamic(0)));
    }

    #[test]
    fn unmatched_names_policy_stops_inserting_after_a_failed_insert() {
        // 64 bytes hold one 32-byte-overhead entry with short strings only.
        let (mut encoder, _) = neqo_encoder(64, 16);
        let mut block = Vec::new();
        let mut instructions = Vec::new();
        assert_eq!(
            encoder.encode(
                0,
                &mut block,
                &mut instructions,
                [
                    HeaderField::new("x-too-long", "a value longer than the table allows"),
                    HeaderField::new("x-a", "b"),
                ]
            ),
            Ok(0)
        );
        assert!(instructions.is_empty());
        let mut read = Cursor::new(block);
        assert_eq!(
            HeaderPrefix::decode(&mut read).unwrap().get(0, 64),
            Ok((0, 0))
        );
        assert_eq!(
            Literal::decode(&mut read),
            Ok(Literal::new(
                "x-too-long",
                "a value longer than the table allows"
            ))
        );
        assert_eq!(Literal::decode(&mut read), Ok(Literal::new("x-a", "b")));
    }

    #[test]
    fn unmatched_names_policy_never_evicts_an_unacknowledged_entry() {
        let (mut encoder, _) = neqo_encoder(64, 16);
        let mut instructions = Vec::new();
        assert_eq!(
            encoder.encode(
                0,
                &mut Vec::new(),
                &mut instructions,
                [HeaderField::new("x-a", "b")]
            ),
            Ok(1)
        );
        // Stream 0 was never acknowledged or cancelled, but even after its
        // cancellation the unacknowledged insert keeps its slot.
        encoder.cancel_stream(0).unwrap();
        let mut block = Vec::new();
        let mut instructions = Vec::new();
        assert_eq!(
            encoder.encode(
                4,
                &mut block,
                &mut instructions,
                [HeaderField::new("x-c", "d")]
            ),
            Ok(0)
        );
        assert!(instructions.is_empty());
        let mut read = Cursor::new(block);
        HeaderPrefix::decode(&mut read).unwrap();
        assert_eq!(Literal::decode(&mut read), Ok(Literal::new("x-c", "d")));
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
    fn sensitive_fields_are_literal_and_never_inserted() {
        let mut encoder = Encoder::default();
        let mut setup = Vec::new();
        encoder
            .set_max_table_capacity(TABLE_SIZE, &mut setup)
            .unwrap();
        encoder.set_max_blocked_streams(16).unwrap();

        let mut block = Vec::new();
        let mut instructions = Vec::new();
        assert_eq!(
            encoder.encode(
                0,
                &mut block,
                &mut instructions,
                [HeaderField::new("content-type", "application/json").with_sensitive(true)]
            ),
            Ok(0)
        );
        assert!(instructions.is_empty());
        let mut read = Cursor::new(block);
        assert_eq!(
            HeaderPrefix::decode(&mut read).unwrap().get(0, TABLE_SIZE),
            Ok((0, 0))
        );
        assert_eq!(
            LiteralWithNameRef::decode(&mut read),
            Ok(LiteralWithNameRef::new_static(44, "application/json").with_sensitive(true))
        );

        let sensitive = HeaderField::new("x-secret", "value").with_sensitive(true);
        let mut block = Vec::new();
        let mut instructions = Vec::new();
        assert_eq!(
            encoder.encode(4, &mut block, &mut instructions, [sensitive.clone()]),
            Ok(0)
        );
        assert!(instructions.is_empty());

        let mut read = Cursor::new(block);
        assert_eq!(
            HeaderPrefix::decode(&mut read).unwrap().get(0, TABLE_SIZE),
            Ok((0, 0))
        );
        assert_eq!(
            Literal::decode(&mut read),
            Ok(Literal::new("x-secret", "value").with_sensitive(true))
        );

        let mut block = Vec::new();
        let mut instructions = Vec::new();
        assert_eq!(
            encoder.encode(
                8,
                &mut block,
                &mut instructions,
                [HeaderField::new("x-secret", "value")]
            ),
            Ok(1)
        );
        assert!(!instructions.is_empty());

        let mut block = Vec::new();
        let mut instructions = Vec::new();
        assert_eq!(
            encoder.encode(12, &mut block, &mut instructions, [sensitive]),
            Ok(0)
        );
        assert!(instructions.is_empty());
        let mut read = Cursor::new(block);
        assert_eq!(
            HeaderPrefix::decode(&mut read).unwrap().get(1, TABLE_SIZE),
            Ok((0, 0))
        );
        assert_eq!(
            Literal::decode(&mut read),
            Ok(Literal::new("x-secret", "value").with_sensitive(true))
        );
    }

    #[test]
    fn stateless_sensitive_fields_use_never_indexed_literals() {
        let fields = [
            HeaderField::new("content-type", "application/json").with_sensitive(true),
            HeaderField::new("x-secret", "value").with_sensitive(true),
        ];
        let expected_size = fields.iter().map(HeaderField::mem_size).sum::<usize>() as u64;
        let mut block = Vec::new();
        assert_eq!(encode_stateless(&mut block, &fields), Ok(expected_size));

        let mut read = Cursor::new(block);
        assert_eq!(
            HeaderPrefix::decode(&mut read).unwrap().get(0, 0),
            Ok((0, 0))
        );
        assert_eq!(
            LiteralWithNameRef::decode(&mut read),
            Ok(LiteralWithNameRef::new_static(44, "application/json").with_sensitive(true))
        );
        assert_eq!(
            Literal::decode(&mut read),
            Ok(Literal::new("x-secret", "value").with_sensitive(true))
        );
    }

    #[test]
    fn local_stream_cancellation_is_idempotent() {
        let field = HeaderField::new("x-dynamic", "value");
        let mut encoder = Encoder::default();
        let mut setup = Vec::new();
        encoder
            .set_max_table_capacity(TABLE_SIZE, &mut setup)
            .unwrap();
        encoder.set_max_blocked_streams(1).unwrap();
        encoder
            .encode(0, &mut Vec::new(), &mut Vec::new(), [field])
            .unwrap();

        assert_eq!(encoder.cancel_stream(0), Ok(()));
        assert_eq!(encoder.cancel_stream(0), Ok(()));
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
