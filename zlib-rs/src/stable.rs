use core::{ffi::c_uint, mem::MaybeUninit};

use crate::deflate::DeflateConfig;
use crate::inflate::InflateConfig;
use crate::ReturnCode;
pub use crate::{DeflateFlush, InflateFlush};

/// Possible status results of compressing some data or successfully
/// decompressing a block of data.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Status {
    /// Indicates success.
    ///
    /// Means that more input may be needed but isn't available
    /// and/or there's more output to be written but the output buffer is full.
    Ok,

    /// Indicates that forward progress is not possible due to input or output
    /// buffers being empty.
    ///
    /// For compression it means the input buffer needs some more data or the
    /// output buffer needs to be freed up before trying again.
    ///
    /// For decompression this means that more input is needed to continue or
    /// the output buffer isn't large enough to contain the result. The function
    /// can be called again after fixing both.
    BufError,

    /// Indicates that all input has been consumed and all output bytes have
    /// been written. Decompression/compression should not be called again.
    ///
    /// For decompression with zlib streams the adler-32 of the decompressed
    /// data has also been verified.
    StreamEnd,
}

/// Errors that can occur when decompressing.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(i32)]
pub enum InflateError {
    /// Decompressing this input requires a dictionary.
    NeedDict { dict_id: u32 } = 2,
    /// The [`Inflate`] is in an inconsistent state, most likely
    /// due to an invalid configuration parameter.
    StreamError = -2,
    /// The input is not a valid deflate stream.
    DataError = -3,
    /// A memory allocation failed.
    MemError = -4,
}

impl From<InflateError> for ReturnCode {
    fn from(value: InflateError) -> Self {
        match value {
            InflateError::NeedDict { .. } => ReturnCode::NeedDict,
            InflateError::StreamError => ReturnCode::StreamError,
            InflateError::DataError => ReturnCode::DataError,
            InflateError::MemError => ReturnCode::MemError,
        }
    }
}

impl InflateError {
    pub fn as_str(self) -> &'static str {
        ReturnCode::from(self).error_message_str()
    }
}

/// The state that is used to decompress an input.
pub struct Inflate {
    inner: crate::inflate::InflateStream<'static>,
    total_in: u64,
    total_out: u64,
}

impl Inflate {
    /// Heap bytes requested for this decoder's state, history window and alignment.
    ///
    /// A successful [`Self::try_clone`] requests the same number of bytes. This
    /// excludes `size_of::<Self>()` and bookkeeping or rounding inside the system
    /// allocator. Input and output buffers are owned by the caller.
    pub fn allocation_size(&self) -> usize {
        self.inner.allocation_size()
    }

    /// Copy the decoder at its current position into an independent allocation.
    ///
    /// The copy includes the history window, buffered bits, checksum and byte counters.
    /// It does not retain input or output buffers. Resume with input starting at
    /// [`Self::total_in`] and a new output buffer; bytes not yet consumed from a previous
    /// input must be supplied again. Resetting or dropping either decoder does not
    /// affect the other.
    ///
    /// Returns [`InflateError::MemError`] if the copy cannot be allocated.
    pub fn try_clone(&self) -> Result<Self, InflateError> {
        let inner = self.inner.try_clone_owned().map_err(|code| match code {
            ReturnCode::MemError => InflateError::MemError,
            _ => unreachable!("copying an initialized decoder only fails on allocation"),
        })?;
        Ok(Self {
            inner,
            total_in: self.total_in,
            total_out: self.total_out,
        })
    }

    /// The amount of bytes consumed from the input so far.
    pub fn total_in(&self) -> u64 {
        self.total_in
    }

    /// The amount of decompressed bytes that have been written to the output thus far.
    pub fn total_out(&self) -> u64 {
        self.total_out
    }

    /// The error message if the previous operation failed.
    pub fn error_message(&self) -> Option<&'static str> {
        if self.inner.msg.is_null() {
            None
        } else {
            unsafe { core::ffi::CStr::from_ptr(self.inner.msg).to_str() }.ok()
        }
    }

    /// Create a new instance. This function allocates, and so it is recommended to re-use this
    /// state when possible, using [`Inflate::reset`] as needed.
    ///
    /// This function will:
    ///
    /// - decode a raw deflate stream when `expect_header = false` and `window_bits` is in the
    ///   range `8..=15`
    /// - decode a zlib header followed by a deflate stream when `expect_header = true` and
    ///   `window_bits` is in the range `8..=15`
    /// - decode a gzip header followed by a deflate stream when `expect_header = true` and
    ///   `window_bits` is in the range `16 + 8..=16 + 15`
    /// - decode either a zlib or a gzip header, followed by a deflate stream when
    ///   `expect_header = true` and `window_bits` is in the range `32 + 8..=32 + 15`
    ///
    /// `window_bits` can also be 0 to request that inflate use the window size in the
    /// zlib header of the compressed stream when using zlib.
    ///
    /// Note that when deflating a value of `window_bits = 8` is silently converted to
    /// `window_bits = 9` in most zlib implementations, and hence should be inflated using
    /// `window_bits = 9`.
    ///
    /// # Panics
    ///
    /// This function may panic when the `window_bits` and `expect_header` have values not listed above.
    pub fn new(expect_header: bool, window_bits: u8) -> Self {
        let config = InflateConfig {
            window_bits: if expect_header {
                i32::from(window_bits)
            } else {
                -i32::from(window_bits)
            },
        };

        Self {
            inner: crate::inflate::InflateStream::new(config),
            total_in: 0,
            total_out: 0,
        }
    }

    /// Reset the state to allow handling a new stream.
    pub fn reset(&mut self, zlib_header: bool) {
        let mut config = InflateConfig::default();

        if !zlib_header {
            config.window_bits = -config.window_bits;
        }

        self.total_in = 0;
        self.total_out = 0;

        crate::inflate::reset_with_config(&mut self.inner, config);
    }

    /// Decompress `input` and write all decompressed bytes into `output`,
    /// with `flush` defining some details about this.
    pub fn decompress(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        flush: InflateFlush,
    ) -> Result<Status, InflateError> {
        self.decompress_uninit(
            input,
            unsafe { &mut *(output as *mut _ as *mut [MaybeUninit<u8>]) },
            flush,
        )
    }

    /// Decompress `input` and write all decompressed bytes into a potentially uninitialized `output`,
    /// with `flush` defining some details about this.
    pub fn decompress_uninit(
        &mut self,
        input: &[u8],
        output: &mut [MaybeUninit<u8>],
        flush: InflateFlush,
    ) -> Result<Status, InflateError> {
        // Limit the length of the input and output to the maximum value of a c_uint. For larger
        // inputs, this will either complete or signal that more input and output is needed. The
        // caller should be able to handle this regardless.
        self.inner.avail_in = Ord::min(input.len(), c_uint::MAX as usize) as c_uint;
        self.inner.avail_out = Ord::min(output.len(), c_uint::MAX as usize) as c_uint;

        // This cast_mut is unfortunate, that is just how the types are.
        self.inner.next_in = input.as_ptr().cast_mut();
        self.inner.next_out = output.as_mut_ptr().cast();

        let start_in = self.inner.next_in;
        let start_out = self.inner.next_out;

        // SAFETY: the inflate state was properly initialized.
        let ret = unsafe { crate::inflate::inflate(&mut self.inner, flush) };

        self.total_in += (self.inner.next_in as usize - start_in as usize) as u64;
        self.total_out += (self.inner.next_out as usize - start_out as usize) as u64;

        match ret {
            ReturnCode::Ok => Ok(Status::Ok),
            ReturnCode::StreamEnd => Ok(Status::StreamEnd),
            ReturnCode::NeedDict => Err(InflateError::NeedDict {
                dict_id: self.inner.adler as u32,
            }),
            ReturnCode::ErrNo => unreachable!("the rust API does not use files"),
            ReturnCode::StreamError => Err(InflateError::StreamError),
            ReturnCode::DataError => Err(InflateError::DataError),
            ReturnCode::MemError => Err(InflateError::MemError),
            ReturnCode::BufError => Ok(Status::BufError),
            ReturnCode::VersionError => unreachable!("the rust API does not use the version"),
        }
    }

    pub fn set_dictionary(&mut self, dictionary: &[u8]) -> Result<u32, InflateError> {
        match crate::inflate::set_dictionary(&mut self.inner, dictionary) {
            ReturnCode::Ok => Ok(self.inner.adler as u32),
            ReturnCode::StreamError => Err(InflateError::StreamError),
            ReturnCode::DataError => Err(InflateError::DataError),
            other => unreachable!("set_dictionary does not return {other:?}"),
        }
    }
}

impl Drop for Inflate {
    fn drop(&mut self) {
        let _ = crate::inflate::end(&mut self.inner);
    }
}

/// Errors that can occur when compressing.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum DeflateError {
    /// The [`Deflate`] is in an inconsistent state, most likely
    /// due to an invalid configuration parameter.
    StreamError = -2,
    /// The input is not a valid deflate stream.
    DataError = -3,
    /// A memory allocation failed.
    MemError = -4,
}

impl From<DeflateError> for ReturnCode {
    fn from(value: DeflateError) -> Self {
        match value {
            DeflateError::StreamError => ReturnCode::StreamError,
            DeflateError::DataError => ReturnCode::DataError,
            DeflateError::MemError => ReturnCode::MemError,
        }
    }
}

impl DeflateError {
    pub fn as_str(self) -> &'static str {
        ReturnCode::from(self).error_message_str()
    }
}

impl From<ReturnCode> for Result<Status, DeflateError> {
    fn from(value: ReturnCode) -> Self {
        match value {
            ReturnCode::Ok => Ok(Status::Ok),
            ReturnCode::StreamEnd => Ok(Status::StreamEnd),
            ReturnCode::NeedDict => unreachable!("compression does not use dictionary"),
            ReturnCode::ErrNo => unreachable!("the rust API does not use files"),
            ReturnCode::StreamError => Err(DeflateError::StreamError),
            ReturnCode::DataError => Err(DeflateError::DataError),
            ReturnCode::MemError => Err(DeflateError::MemError),
            ReturnCode::BufError => Ok(Status::BufError),
            ReturnCode::VersionError => unreachable!("the rust API does not use the version"),
        }
    }
}

/// The state that is used to compress an input.
pub struct Deflate {
    inner: crate::deflate::DeflateStream<'static>,
    total_in: u64,
    total_out: u64,
}

impl Deflate {
    /// The number of bytes that were read from the input.
    pub fn total_in(&self) -> u64 {
        self.total_in
    }

    /// The number of compressed bytes that were written to the output.
    pub fn total_out(&self) -> u64 {
        self.total_out
    }

    /// The error message if the previous operation failed.
    pub fn error_message(&self) -> Option<&'static str> {
        if self.inner.msg.is_null() {
            None
        } else {
            unsafe { core::ffi::CStr::from_ptr(self.inner.msg).to_str() }.ok()
        }
    }

    /// Create a new instance - this allocates so should be done with care.
    ///
    /// The `window_bits` must be in the range `8..=15`, with `15` being most common.
    pub fn new(level: i32, zlib_header: bool, window_bits: u8) -> Self {
        let config = DeflateConfig {
            window_bits: if zlib_header {
                i32::from(window_bits)
            } else {
                -i32::from(window_bits)
            },
            level,
            ..DeflateConfig::default()
        };

        Self::new_with_config(config)
    }

    /// Create a new instance with the provided [`DeflateConfig`].
    ///
    /// In most cases it is recommended to use the standard [`Deflate::new`] constructor unless
    /// tweaking `mem_level` or `strategy` is desired.
    ///
    /// This allocates, so should be done with care.
    pub fn new_with_config(config: DeflateConfig) -> Self {
        Self {
            inner: crate::deflate::DeflateStream::new(config),
            total_in: 0,
            total_out: 0,
        }
    }

    /// Prepare the instance for a new stream.
    pub fn reset(&mut self) {
        self.total_in = 0;
        self.total_out = 0;

        crate::deflate::reset(&mut self.inner);
    }

    /// Compress `input` and write compressed bytes to `output`,
    /// with `flush` controlling additional characteristics.
    pub fn compress(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        flush: DeflateFlush,
    ) -> Result<Status, DeflateError> {
        self.compress_uninit(
            input,
            unsafe { &mut *(output as *mut _ as *mut [MaybeUninit<u8>]) },
            flush,
        )
    }

    /// Compress `input` and write compressed bytes to a potentially uninitialized `output`,
    /// with `flush` controlling additional characteristics.
    pub fn compress_uninit(
        &mut self,
        input: &[u8],
        output: &mut [MaybeUninit<u8>],
        flush: DeflateFlush,
    ) -> Result<Status, DeflateError> {
        // Limit the length of the input and output to the maximum value of a c_uint. For larger
        // inputs, this will either complete or signal that more input and output is needed. The
        // caller should be able to handle this regardless.
        self.inner.avail_in = Ord::min(input.len(), c_uint::MAX as usize) as c_uint;
        self.inner.avail_out = Ord::min(output.len(), c_uint::MAX as usize) as c_uint;

        // This cast_mut is unfortunate, that is just how the types are.
        self.inner.next_in = input.as_ptr().cast_mut();
        self.inner.next_out = output.as_mut_ptr().cast();

        let start_in = self.inner.next_in;
        let start_out = self.inner.next_out;

        let ret = crate::deflate::deflate(&mut self.inner, flush).into();

        self.total_in += (self.inner.next_in as usize - start_in as usize) as u64;
        self.total_out += (self.inner.next_out as usize - start_out as usize) as u64;

        // Clear these pointers so there can be no use after free.
        self.inner.next_in = core::ptr::null_mut();
        self.inner.next_out = core::ptr::null_mut();

        self.inner.avail_in = 0;
        self.inner.avail_out = 0;

        ret
    }

    /// Specifies the compression dictionary to use.
    ///
    /// Returns the Adler-32 checksum of the dictionary.
    pub fn set_dictionary(&mut self, dictionary: &[u8]) -> Result<u32, DeflateError> {
        match crate::deflate::set_dictionary(&mut self.inner, dictionary) {
            ReturnCode::Ok => Ok(self.inner.adler as u32),
            ReturnCode::StreamError => Err(DeflateError::StreamError),
            other => unreachable!("set_dictionary does not return {other:?}"),
        }
    }

    /// Dynamically updates the compression level.
    ///
    /// This can be used to switch between compression levels for different
    /// kinds of data, or it can be used in conjunction with a call to [`Deflate::reset`]
    /// to reuse the compressor.
    ///
    /// This may return an error if there wasn't enough output space to complete
    /// the compression of the available input data before changing the
    /// compression level. Flushing the stream before calling this method
    /// ensures that the function will succeed on the first call.
    pub fn set_level(&mut self, level: i32) -> Result<Status, DeflateError> {
        // Clear these pointers so there can be no use after free.
        self.inner.next_in = core::ptr::null_mut();
        self.inner.next_out = core::ptr::null_mut();

        self.inner.avail_in = 0;
        self.inner.avail_out = 0;

        match crate::deflate::params(&mut self.inner, level, Default::default()) {
            ReturnCode::Ok => Ok(Status::Ok),
            ReturnCode::StreamError => Err(DeflateError::StreamError),
            ReturnCode::BufError => Ok(Status::BufError),
            other => unreachable!("set_level does not return {other:?}"),
        }
    }
}

impl Drop for Deflate {
    fn drop(&mut self) {
        let _ = crate::deflate::end(&mut self.inner);
    }
}

#[cfg(all(test, any(feature = "rust-allocator", feature = "c-allocator")))]
mod checkpoint_tests {
    use super::*;

    fn fixture(window_bits: i32) -> (Vec<u8>, Vec<u8>) {
        let mut plain = b"0123456789abcdef".repeat(4096);
        plain.extend_from_slice(&b"fedcba9876543210".repeat(4096));
        let mut compressed = vec![0; crate::compress_bound(plain.len())];
        let (encoded, status) = crate::compress_slice(
            &mut compressed,
            &plain,
            DeflateConfig {
                window_bits,
                ..Default::default()
            },
        );
        assert_eq!(status, ReturnCode::Ok);
        let len = encoded.len();
        compressed.truncate(len);
        (plain, compressed)
    }

    fn finish(decoder: &mut Inflate, input: &[u8], output_chunk: usize) -> Vec<u8> {
        let start_in = decoder.total_in();
        let mut decoded = Vec::new();
        loop {
            let before = (decoder.total_in(), decoder.total_out());
            let offset = (decoder.total_in() - start_in) as usize;
            let mut output = vec![0; output_chunk];
            let status = decoder
                .decompress(&input[offset..], &mut output, InflateFlush::NoFlush)
                .unwrap();
            decoded.extend_from_slice(&output[..(decoder.total_out() - before.1) as usize]);
            if status == Status::StreamEnd {
                return decoded;
            }
            assert_ne!(
                before,
                (decoder.total_in(), decoder.total_out()),
                "decoder stalled"
            );
        }
    }

    #[test]
    fn checkpoint_resumes_pending_match_without_original_or_borrowed_buffers() {
        let (plain, encoded) = fixture(15);
        let mut source = Inflate::new(true, 15);
        let mut input = encoded.clone();
        let mut output = vec![0; 113];
        assert_eq!(
            source.decompress(&input, &mut output, InflateFlush::NoFlush),
            Ok(Status::Ok)
        );
        assert_eq!(output, plain[..113]);
        // A nonzero low half is the number of bytes already emitted from a pending match.
        assert!(crate::inflate::mark(&source.inner) as u32 & 0xffff > 0);
        let consumed = source.total_in() as usize;
        input.fill(0);
        drop(input);
        output.fill(0);
        drop(output);
        let mut first = source.try_clone().unwrap();
        let mut second = source.try_clone().unwrap();
        assert_eq!(
            (first.total_in(), first.total_out()),
            (source.total_in(), source.total_out())
        );
        drop(source);
        assert_eq!(finish(&mut first, &encoded[consumed..], 257), plain[113..]);
        first.reset(false);
        drop(first);
        assert_eq!(finish(&mut second, &encoded[consumed..], 997), plain[113..]);
        assert_eq!(second.total_in(), encoded.len() as u64);
        assert_eq!(second.total_out(), plain.len() as u64);
    }

    #[test]
    fn checkpoints_preserve_headers_partial_input_and_wrapped_window() {
        for (encode_bits, expect_header, decode_bits) in
            [(-15, false, 15), (15, true, 0), (31, true, 47)]
        {
            let (plain, encoded) = fixture(encode_bits);
            for input_end in [0, 1, 2, 3, 7, 15, 31, encoded.len() - 4, encoded.len()] {
                for output_end in [0, 1, 7, 113, 32769, 70001] {
                    let mut source = Inflate::new(expect_header, decode_bits);
                    let mut buffer = vec![0; output_end];
                    source
                        .decompress(&encoded[..input_end], &mut buffer, InflateFlush::NoFlush)
                        .unwrap();
                    let consumed = source.total_in() as usize;
                    let produced = source.total_out() as usize;
                    assert_eq!(&buffer[..produced], &plain[..produced]);
                    let mut restored = source.try_clone().unwrap();
                    // Advancing and resetting the source must not change the checkpoint.
                    assert_eq!(
                        finish(&mut source, &encoded[consumed..], 4096),
                        plain[produced..]
                    );
                    source.reset(false);
                    drop(source);
                    drop(buffer);
                    assert_eq!(
                        finish(&mut restored, &encoded[consumed..], 263),
                        plain[produced..]
                    );
                }
            }
        }
    }

    #[test]
    fn checkpoints_before_decode_after_reset_and_after_end_are_independent() {
        let (plain, encoded) = fixture(15);
        let source = Inflate::new(true, 15);
        let mut pristine = source.try_clone().unwrap();
        drop(source);
        assert_eq!(finish(&mut pristine, &encoded, 8192), plain);
        let mut ended = pristine.try_clone().unwrap();
        pristine.reset(false);
        drop(pristine);
        assert_eq!(
            ended.decompress(&[], &mut [0; 1], InflateFlush::NoFlush),
            Ok(Status::StreamEnd)
        );
        assert_eq!(
            (ended.total_in(), ended.total_out()),
            (encoded.len() as u64, plain.len() as u64)
        );
        ended.reset(true);
        let mut reset = ended.try_clone().unwrap();
        drop(ended);
        assert_eq!((reset.total_in(), reset.total_out()), (0, 0));
        assert_eq!(finish(&mut reset, &encoded, 4096), plain);
    }

    #[test]
    fn checkpoint_allocation_failure_leaves_source_usable() {
        unsafe extern "C" fn fail_alloc(
            opaque: *mut core::ffi::c_void,
            items: c_uint,
            size: c_uint,
        ) -> *mut core::ffi::c_void {
            // SAFETY: opaque points to requested for the duration of try_clone.
            unsafe { *opaque.cast::<usize>() = items as usize * size as usize };
            core::ptr::null_mut()
        }
        let (plain, encoded) = fixture(15);
        let mut source = Inflate::new(true, 15);
        source
            .decompress(&encoded, &mut [0; 113], InflateFlush::NoFlush)
            .unwrap();
        let consumed = source.total_in() as usize;
        let allocator = source.inner.alloc;
        let mut requested = 0usize;
        source.inner.alloc.zalloc = fail_alloc;
        source.inner.alloc.opaque = core::ptr::addr_of_mut!(requested).cast();
        let expected_size = source.allocation_size();
        assert!(matches!(source.try_clone(), Err(InflateError::MemError)));
        source.inner.alloc = allocator;
        assert_eq!(requested, expected_size);
        let mut restored = source.try_clone().unwrap();
        assert_eq!(
            finish(&mut source, &encoded[consumed..], 4096),
            plain[113..]
        );
        drop(source);
        assert_eq!(
            finish(&mut restored, &encoded[consumed..], 4096),
            plain[113..]
        );
    }

    #[test]
    fn checkpoints_preserve_dictionary_and_error_state() {
        let dictionary = b"0123456789abcdef".repeat(1024);
        let plain = dictionary.repeat(4);
        let mut compressor = Deflate::new(6, true, 15);
        let dict_id = compressor.set_dictionary(&dictionary).unwrap();
        let mut encoded = vec![0; crate::compress_bound(plain.len())];
        assert_eq!(
            compressor.compress(&plain, &mut encoded, DeflateFlush::Finish),
            Ok(Status::StreamEnd)
        );
        encoded.truncate(compressor.total_out() as usize);
        let mut source = Inflate::new(true, 15);
        assert_eq!(
            source.decompress(&encoded, &mut [0; 113], InflateFlush::NoFlush),
            Err(InflateError::NeedDict { dict_id })
        );
        let mut waiting = source.try_clone().unwrap();
        let consumed = source.total_in() as usize;
        drop(source);
        waiting.set_dictionary(&dictionary).unwrap();
        let mut ready = waiting.try_clone().unwrap();
        drop(waiting);
        drop(dictionary);
        assert_eq!(finish(&mut ready, &encoded[consumed..], 257), plain);

        let mut invalid = Inflate::new(true, 15);
        assert_eq!(
            invalid.decompress(&[0xff; 8], &mut [0; 16], InflateFlush::NoFlush),
            Err(InflateError::DataError)
        );
        let message = invalid.error_message();
        let mut restored = invalid.try_clone().unwrap();
        drop(invalid);
        assert_eq!(restored.error_message(), message);
        assert_eq!(
            restored.decompress(&[], &mut [0; 16], InflateFlush::NoFlush),
            Err(InflateError::DataError)
        );
    }
}
