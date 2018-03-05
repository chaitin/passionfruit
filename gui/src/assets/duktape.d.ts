// Type definition for Duktape 2.2.0
// http://duktape.org/guide.html#duktapebuiltins
// https://kangax.github.io/compat-table/es6/

declare var global: Global;

interface Global {
    /* ECMA script objects */
    NaN: typeof NaN;
    Infinity: typeof Infinity;
    undefined: typeof undefined;
    Object: typeof Object;
    Function: typeof Function;
    Array: typeof Array;
    String: typeof String;
    Boolean: typeof Boolean;
    Number: typeof Number;
    Date: typeof Date;
    RegExp: typeof RegExp;
    Error: typeof Error;
    EvalError: typeof EvalError;
    RangeError: typeof RangeError;
    ReferenceError: typeof ReferenceError;
    SyntaxError: typeof SyntaxError;
    TypeError: typeof TypeError;
    URIError: typeof URIError;
    Math: typeof Math;
    JSON: typeof JSON;
    ArrayBuffer: typeof ArrayBuffer;
    DataView: typeof DataView;
    Int8Array: typeof Int8Array;
    Uint8Array: typeof Uint8Array;
    Uint8ClampedArray: typeof Uint8ClampedArray;
    Int16Array: typeof Int16Array;
    Uint16Array: typeof Uint16Array;
    Int32Array: typeof Int32Array;
    Uint32Array: typeof Uint32Array;
    Float32Array: typeof Float32Array;
    Float64Array: typeof Float64Array;
    eval: typeof eval;
    parseInt: typeof parseInt;
    parseFloat: typeof parseFloat;
    isNaN: typeof isNaN;
    isFinite: typeof isFinite;
    decodeURI: typeof decodeURI;
    decodeURIComponent: typeof decodeURIComponent;
    encodeURI: typeof encodeURI;
    encodeURIComponent: typeof encodeURIComponent;
    escape: (str: string) => string;
    unescape: (str: string) => string;

    /* Post ES5 features */
    Proxy: typeof Proxy;
    Reflect: typeof Reflect;

    /* Node.js objects */
    Buffer: typeof Buffer;

    /* Additional global objects */
    global: Global;
    Duktape: typeof Duktape;
    TextEncoder: typeof TextEncoder;
    TextDecoder: typeof TextDecoder;
    performance: typeof performance;
}

/**
 * Duktape object
 */
declare module Duktape {
    /**
     * Duktape version number: (major * 10000) + (minor * 100) + patch
     */
    const version: number;

    /**
     * Cryptic, version dependent summary of most important effective options like endianness and architecture.
     */
    const env: string;

    /**
     * Get finalizer of an object.
     * @param o Object to get finalizer
     */
    function fin(o: Object): Function;

    /**
     * Set finalizer of an object.
     * @param o Object to set finalizer
     * @param finalizer Finalizer function
     */
    function fin(o: Object, finalizer: Function): void;

    /**
     * Encodes its argument value into chosen format.
     * @param format A format (Currently supported are "hex", "base64", "jx" and "jc")
     * @param value The value to encode
     */
    function enc(format: "hex" | "base64", value: any): string;

    /**
     * Encodes its argument value into chosen format.
     * @param format A format (Currently supported are "hex", "base64", "jx" and "jc")
     * @param value The value to encode
     * @param replacer A function that alters the behavior of the stringification process
     * @param space A string or number object used to insert white space
     */
    function enc(format: "jx" | "jc", value: any, replacer?: Function, space?: number): string;

    /**
     * Provides the revers function of enc()
     * @param format A format (Currently supported are "hex", "base64", "jx" and "jc")
     * @param value The value to decode
     */
    function dec(format: "hex" | "base64", value: string): any;

    /**
     * Provides the revers function of enc()
     * @param format A format (Currently supported are "hex", "base64", "jx" and "jc")
     * @param value The value to decode
     * @param reviver A function prescribes how the value originally produced by parsing is transformed
     */
    function dec(format: "jx" | "jc", value: string, reviver?: Function): any;

    /**
     * Returns an object exposing internal information related to its argument value.
     * @param o Object to inspect
     */
    function info(o: any): Duktape.ObjectInfo;

    /**
     * Get information about a call stack entry.
     * @param depth Depth in the call stack: -1 is the top (innermost) entry, -2 is the one below that etc.)
     */
    function act(depth: number): Duktape.CallStackInfo;

    /**
     * Trigger a forced mark-and-sweep collection.
     * @param flags Flags (see duktape.h)
     */
    function gc(flags?: number): void;

    /**
     * Minimize the memory allocated for a target object.
     * @param o Object to minimize
     */
    function compact(o: any): any;

    interface Pointer {
        toString(): string;
        valueOf(): any;
    }

    interface PointerConstructor {
        readonly prototype: Pointer;
        new (pointer: any): Pointer;
        (pointer: any): any;
    }
    const Pointer: PointerConstructor;

    interface Thread {
    }

    interface ThreadConstructor {
        readonly prototype: Thread;
        new (fn: Function): Thread;
        (fn: Function): Thread;

        /**
         * Resume target thread with a value.
         * @param thread A thread to resume
         * @param value A value passed to the thread
         * @param flag Flag indicating whether value is to be thrown
         */
        resume(thread: Thread, value: any, flag?: false): void;

        /**
         * Resume target thread with an error.
         * @param thread A thread to resume
         * @param value A value to be thrown to the thread
         * @param flag Flag indicating whether value is to be thrown
         */
        resume(thread: Thread, value: any, flag: true): void;

        /**
         * Yield a value from current thread.
         * @param value A value to yield
         * @param flag Flag indicating whether value is to be thrown
         */
        yield(value: any, flag?: false): void;

        /**
         * Yield a value from current thread.
         * @param value An error value to yield
         * @param flag Flag indicating whether value is to be thrown
         */
        yield(value: any, flag: true): void;

        /**
         * Get currently running Thread object.
         */
        current(): Thread;
    }
    const Thread: ThreadConstructor;

    interface Performance {
        /**
         * Provides a monotonic time in milliseconds (including fractions if available) from an unspecified origin.
         */
        now(): number;
    }

    interface ObjectInfo {
        /** Type number matching DUK_TYPE_xxx from duktape.h. */
        type: number;
        /** Internal type tag matching internal DUK_TAG_xxx defines. */
        itag: number;
        /** Heap pointer for a heap-allocated value. */
        hptr: any;
        /** Reference count. */
        refc: number;
        /** For objects, internal class number, matches internal DUK_HOBJECT_CLASS_xxx defines. */
        class: number;
        /** Byte size of main heap object allocation. */
        hbytes: number;
        /** Byte size of an object's property table. */
        pbytes: number;
        /** Byte size of Ecmascript function bytecode (instructions, constants). */
        bcbytes: number;
        /** Byte size of the current allocation of a dynamic or external buffer. */
        dbytes: number;
        /** Object entry part size in elements. */
        esize: number;
        /** Object entry part first free index (= index of next property slot to be used). */
        enext: number;
        /** Object array part size in elements, zero if no array part or array part has been abandoned (sparse array). */
        asize: number;
        /** Object hash part size in elements. */
        hsize: number;
        /** Internal thread state, matches internal DUK_HTHREAD_STATE_xxx defines. */
        tstate: number;
        /** Identifies type variants for certain types. */
        variant: number;
    }

    interface CallStackInfo {
        /** Function being executed. */
        function: Function;
        /** Program counter for Ecmascript functions. */
        pc: number;
        /** Line number for Ecmascript functions. */
        lineNumber: number;
    }
}

/*
 * Post-ES5 features
 */

interface ProxyHandler<T extends object> {
    has?(target: T, key: string): boolean;
    get?(target: T, key: string, receiver: any): any;
    set?(target: T, key: string, value: any, receiver: any): boolean;
    deleteProperty?(target: T, key: string): boolean;
    ownKeys?(target: T): string[];
}

interface ProxyConstructor {
    new <T extends object>(target: T, handler: ProxyHandler<T>): T;
}
declare var Proxy: ProxyConstructor;

declare namespace Reflect {
    function get(target: object, key: string, receiver?: any): any;
    function set(target: object, key: string, value: any, receiver?: any): boolean;
    function has(target: object, key: string): boolean;
    function deleteProperty(target: object, key: string): boolean;
    function getOwnPropertyDescriptor(target: object, key: string): PropertyDescriptor;
    function defineProperty(target: object, key: string, desc: PropertyDescriptor): boolean;
    function getPrototypeOf(target: object): object;
    function setPrototypeOf(target: object, proto: any): boolean;
    function isExtensible(target: object): boolean;
    function preventExtensions(target: object): boolean;
    function ownKeys(target: object): string[];
    function apply(target: Function, thisArg: any, args: any[]): any;
    function construct(target: Function, args: any[]): any;
}

/*
 * Node.js like objects
 */

interface Buffer extends Uint8Array {
    /**
     * Reads a unsigned 8-bit integer from buf at the specified offset
     * @param offset Where to start reading
     * @param noAssert Skip offset validation
     */
    readUInt8(offset: number, noAssert?: boolean): number;

    /**
     * Reads a signed 8-bit integer from buf at the specified offset
     * @param offset Where to start reading
     * @param noAssert Skip offset validation
     */
    readInt8(offset: number, noAssert?: boolean): number;

    /**
     * Reads a unsigned 16-bit integer from buf at the specified offset with big-endian format
     * @param offset Where to start reading
     * @param noAssert Skip offset validation
     */
    readUInt16BE(offset: number, noAssert?: boolean): number;

    /**
     * Reads a unsigned 16-bit integer from buf at the specified offset with little-endian format
     * @param offset Where to start reading
     * @param noAssert Skip offset validation
     */
    readUInt16LE(offset: number, noAssert?: boolean): number;

    /**
     * Reads a signed 16-bit integer from buf at the specified offset with big-endian format
     * @param offset Where to start reading
     * @param noAssert Skip offset validation
     */
    readInt16BE(offset: number, noAssert?: boolean): number;

    /**
     * Reads a signed 16-bit integer from buf at the specified offset with little-endian format
     * @param offset Where to start reading
     * @param noAssert Skip offset validation
     */
    readInt16LE(offset: number, noAssert?: boolean): number;

    /**
     * Reads a unsigned 32-bit integer from buf at the specified offset with big-endian format
     * @param offset Where to start reading
     * @param noAssert Skip offset validation
     */
    readUInt32BE(offset: number, noAssert?: boolean): number;

    /**
     * Reads a unsigned 32-bit integer from buf at the specified offset with little-endian format
     * @param offset Where to start reading
     * @param noAssert Skip offset validation
     */
    readUInt32LE(offset: number, noAssert?: boolean): number;

    /**
     * Reads a signed 32-bit integer from buf at the specified offset with big-endian format
     * @param offset Where to start reading
     * @param noAssert Skip offset validation
     */
    readInt32BE(offset: number, noAssert?: boolean): number;

    /**
     * Reads a signed 32-bit integer from buf at the specified offset with little-endian format
     * @param offset Where to start reading
     * @param noAssert Skip offset validation
     */
    readInt32LE(offset: number, noAssert?: boolean): number;

    /**
     * Reads a 32-bit float from buf at the specified offset with big-endian format
     * @param offset Where to start reading
     * @param noAssert Skip offset validation
     */
    readFloatBE(offset: number, noAssert?: boolean): number;

    /**
     * Reads a 32-bit float from buf at the specified offset with little-endian format
     * @param offset Where to start reading
     * @param noAssert Skip offset validation
     */
    readFloatLE(offset: number, noAssert?: boolean): number;

    /**
     * Reads a 64-bit double from buf at the specified offset with big-endian format
     * @param offset Where to start reading
     * @param noAssert Skip offset validation
     */
    readDoubleBE(offset: number, noAssert?: boolean): number;

    /**
     * Reads a 64-bit double from buf at the specified offset with little-endian format
     * @param offset Where to start reading
     * @param noAssert Skip offset validation
     */
    readDoubleLE(offset: number, noAssert?: boolean): number;

    /**
     * Reads byteLength number of bytes from buf at the specified offset with big-endian format
     * and interprets the result as an unsigned integer
     * @param offset Where to start reading
     * @param byteLength How many bytes to read
     * @param noAssert Skip offset validation
     */
    readUIntBE(offset: number, byteLength: number, noAssert?: boolean): number;

    /**
     * Reads byteLength number of bytes from buf at the specified offset with little-endian format
     * and interprets the result as an unsigned integer
     * @param offset Where to start reading
     * @param byteLength How many bytes to read
     * @param noAssert Skip offset validation
     */
    readUIntLE(offset: number, byteLength: number, noAssert?: boolean): number;

    /**
     * Reads byteLength number of bytes from buf at the specified offset with big-endian format
     * and interprets the result as a two's complement signed value (Up to 48 bits accuracy)
     * @param offset Where to start reading
     * @param byteLength How many bytes to read
     * @param noAssert Skip offset validation
     */
    readIntBE(offset: number, byteLength: number, noAssert?: boolean): number;

    /**
     * Reads byteLength number of bytes from buf at the specified offset with little-endian format
     * and interprets the result as a two's complement signed value (Up to 48 bits accuracy)
     * @param offset Where to start reading
     * @param byteLength How many bytes to read
     * @param noAssert Skip offset validation
     */
    readIntLE(offset: number, byteLength: number, noAssert?: boolean): number;

    /**
     * Writes unsigned 8-bit value to buf at the specified offset
     * @param value Number to be written to buf
     * @param offset Where to start writing
     * @param noAssert Skip value and offset validation
     * @return offset plus number of bytes written
     */
    writeUInt8(value: number, offset: number, noAssert?: boolean): number;

    /**
     * Writes signed 8-bit value to buf at the specified offset
     * @param value Number to be written to buf
     * @param offset Where to start writing
     * @param noAssert Skip value and offset validation
     * @return offset plus number of bytes written
     */
    writeInt8(value: number, offset: number, noAssert?: boolean): number;

    /**
     * Writes unsigned 16-bit value to buf at the specified offset with big-endian format
     * @param value Number to be written to buf
     * @param offset Where to start writing
     * @param noAssert Skip value and offset validation
     * @return offset plus number of bytes written
     */
    writeUInt16BE(value: number, offset: number, noAssert?: boolean): number;

    /**
     * Writes unsigned 16-bit value to buf at the specified offset with little-endian format
     * @param value Number to be written to buf
     * @param offset Where to start writing
     * @param noAssert Skip value and offset validation
     * @return offset plus number of bytes written
     */
    writeUInt16LE(value: number, offset: number, noAssert?: boolean): number;

    /**
     * Writes signed 16-bit value to buf at the specified offset with big-endian format
     * @param value Number to be written to buf
     * @param offset Where to start writing
     * @param noAssert Skip value and offset validation
     * @return offset plus number of bytes written
     */
    writeInt16BE(value: number, offset: number, noAssert?: boolean): number;

    /**
     * Writes signed 16-bit value to buf at the specified offset with little-endian format
     * @param value Number to be written to buf
     * @param offset Where to start writing
     * @param noAssert Skip value and offset validation
     * @return offset plus number of bytes written
     */
    writeInt16LE(value: number, offset: number, noAssert?: boolean): number;

    /**
     * Writes unsigned 32-bit value to buf at the specified offset with big-endian format
     * @param value Number to be written to buf
     * @param offset Where to start writing
     * @param noAssert Skip value and offset validation
     * @return offset plus number of bytes written
     */
    writeUInt32BE(value: number, offset: number, noAssert?: boolean): number;

    /**
     * Writes unsigned 32-bit value to buf at the specified offset with little-endian format
     * @param value Number to be written to buf
     * @param offset Where to start writing
     * @param noAssert Skip value and offset validation
     * @return offset plus number of bytes written
     */
    writeUInt32LE(value: number, offset: number, noAssert?: boolean): number;

    /**
     * Writes signed 32-bit value to buf at the specified offset with big-endian format
     * @param value Number to be written to buf
     * @param offset Where to start writing
     * @param noAssert Skip value and offset validation
     * @return offset plus number of bytes written
     */
    writeInt32BE(value: number, offset: number, noAssert?: boolean): number;

    /**
     * Writes signed 32-bit value to buf at the specified offset with little-endian format
     * @param value Number to be written to buf
     * @param offset Where to start writing
     * @param noAssert Skip value and offset validation
     * @return offset plus number of bytes written
     */
    writeInt32LE(value: number, offset: number, noAssert?: boolean): number;

    /**
     * Writes 32-bit float value to buf at the specified offset with big-endian format
     * @param value Number to be written to buf
     * @param offset Where to start writing
     * @param noAssert Skip value and offset validation
     * @return offset plus number of bytes written
     */
    writeFloatBE(value: number, offset: number, noAssert?: boolean): number;

    /**
     * Writes 32-bit float value to buf at the specified offset with little-endian format
     * @param value Number to be written to buf
     * @param offset Where to start writing
     * @param noAssert Skip value and offset validation
     * @return offset plus number of bytes written
     */
    writeFloatLE(value: number, offset: number, noAssert?: boolean): number;

    /**
     * Writes 64-bit double value to buf at the specified offset with big-endian format
     * @param value Number to be written to buf
     * @param offset Where to start writing
     * @param noAssert Skip value and offset validation
     * @return offset plus number of bytes written
     */
    writeDoubleBE(value: number, offset: number, noAssert?: boolean): number;

    /**
     * Writes 64-bit double value to buf at the specified offset with little-endian format
     * @param value Number to be written to buf
     * @param offset Where to start writing
     * @param noAssert Skip value and offset validation
     * @return offset plus number of bytes written
     */
    writeDoubleLE(value: number, offset: number, noAssert?: boolean): number;

    /**
     * Writes byteLength bytes of unsigned value to buf at the specified offset with big-endian format (Up to 48 bits accuracy)
     * @param value Number to be written to buf
     * @param offset Where to start writing
     * @param byteLength How many bytes to write
     * @param noAssert Skip value and offset validation
     * @return offset plus number of bytes written
     */
    writeUIntBE(value: number, offset: number, byteLength: number, noAssert?: boolean): number;

    /**
     * Writes byteLength bytes of unsigned value to buf at the specified offset with little-endian format (Up to 48 bits accuracy)
     * @param value Number to be written to buf
     * @param offset Where to start writing
     * @param byteLength How many bytes to write
     * @param noAssert Skip value and offset validation
     * @return offset plus number of bytes written
     */
    writeUIntLE(value: number, offset: number, byteLength: number, noAssert?: boolean): number;

    /**
     * Writes byteLength bytes of signed value to buf at the specified offset with big-endian format (Up to 48 bits accuracy)
     * @param value Number to be written to buf
     * @param offset Where to start writing
     * @param byteLength How many bytes to write
     * @param noAssert Skip value and offset validation
     * @return offset plus number of bytes written
     */
    writeIntBE(value: number, offset: number, byteLength: number, noAssert?: boolean): number;

    /**
     * Writes byteLength bytes of signed value to buf at the specified offset with little-endian format (Up to 48 bits accuracy)
     * @param value Number to be written to buf
     * @param offset Where to start writing
     * @param byteLength How many bytes to write
     * @param noAssert Skip value and offset validation
     * @return offset plus number of bytes written
     */
    writeIntLE(value: number, offset: number, byteLength: number, noAssert?: boolean): number;

    /**
     * Returns a JSON representation of buf
     */
    toJSON(): Object;

    /**
     * Returns true if both buf and otherBuffer have exactly the same bytes, false otherwise
     * @param otherBuffer A Buffer to compare to
     */
    equals(otherBuffer: Buffer): boolean;

    /**
     * Compares buf with target and returns a number indicating whether buf comes becore, after, or it the same
     * as target in sort order. Comparison is based on the acutual sequence of bytes in each Buffer
     * @param target A Buffer to compare to
     * @param targetStart The offset within target at which to begin comparison
     * @param targetEnd The offset with target at which to end comparison (not inclusive)
     * @param sourceStart The offset within buf at which to begin comparison
     * @param sourceEnd The offset within buf at which to end comparison (not inclusive)
     * @return 0: target is the same as buf, 1: target should come before buf when sorted, -1: target should come after buf when sorted
     */
    compare(target: Buffer, targetStart?: number, targetEnd?: number, sourceStart?: number, sourceEnd?: number): number;

    /**
     * Copies data from a region of buf to a region in target even if the target memory region overlaps with buf
     * @param target A Buffer or Uint8Array to copy into
     * @param targetStart The offset within target at which to begin copying to
     * @param sourceStart The offset within buf at which to begin copying from
     * @param sourceEnd The offset within buf at which to stop copying (not inclusive)
     * @return The number of bytes copied
     */
    copy(target: Buffer, targetStart?: number, sourceStart?: number, sourceEnd?: number): number;

    /**
     * Returns a new Buffer that references the same memory as the original,
     * but offset and cropped by the start and end indices
     * @param start Where the new Buffer will start
     * @param end Where the new Buffer will end (not inclusive)
     */
    slice(start?: number, end?: number): Buffer;

    /**
     * Writes string to buf at the offset according to the specified character encoding
     * @param string String to be written to buf
     * @param offset Where to start writing string
     * @param length How many bytes to write
     * @param encoding The character encoding of string (only "utf8" is accepted in Duktape)
     * @return Number of bytes written
     */
    write(string: string, offset?: number, length?: number, encoding?: string): number;
}

interface BufferConstructor {
    readonly prototype: Buffer;

    /**
     * Allocates a new buffer using an array of octets.
     * @param array The octets to store
     */
    new (array: Uint8Array): Buffer;

    /**
     * Copies the passed buffer data onto a new Buffer instance.
     * @param buffer The buffer to copy
     */
    new (buffer: Buffer): Buffer;

    /**
     * Allocates a new buffer containing the given string
     * @param str String to encode
     * @param encoding Encoding to use (optional)
     */
    new (str: string, encoding?: string): Buffer;

    /**
     * Returns true if the encoding is a valid encoding argument, or false otherwise.
     * @param encoding Encoding to test
     */
    isEncoding(encoding: string): boolean;

    /**
     * Tests if obj is a Buffer
     * @param obj Object to test
     */
    isBuffer(obj: any): obj is Buffer;

    /**
     * Gives the actual byte length of a string. encoding defaults to 'utf8'.
     * This is not the same as String.prototype.length since that returns
     * the number of characters in a string.
     * @param string String to encode
     * @param encoding Encoding to use (optional)
     */
    byteLength(string: string, encoding?: string): number;

    /**
     * Returns a buffer which is the result of concatenating all the buffers
     * in the list together.
     * @param list List of Buffer objects to concat
     * @param totalLength Total length of the buffers when concatenated
     */
    concat(list: Buffer[], totalLength?: number): Buffer;

    /**
     * The same as buf1.compare(buf2). Useful for sorting an Array of Buffers:
     * @param buf1
     * @param buf2
     */
    compare(buf1: Buffer, buf2: Buffer): number;
}

/**
 * Raw byte data store (based on Buffer of Node.js v0.12.1)
 */
declare const Buffer: BufferConstructor;

interface TextEncoder {
    readonly encoding: "utf-8";
    encode(input?: string): Uint8Array;
}

interface TextEncoderConstructor {
    new (): TextEncoder;
}

/**
 * Encoder for string to Uint8Array by UTF-8 encoding
 * based WHATWG Encoding API
 */
declare const TextEncoder: TextEncoderConstructor;

interface TextDecoderOptions {
    fatal: boolean;
    ignoreBOM: boolean;
}

interface TextDecodeOptions {
    stream: boolean;
}

interface TextDecoder {
    readonly encoding: "utf-8";
    readonly fatal: boolean;
    readonly ignoreBOM: boolean;
    decode(input?: ArrayBufferView | ArrayBuffer, options?: TextDecodeOptions);
}

interface TextDecoderConstructor {
    readonly prototype: TextDecoder;
    new (label?: "utf-8", options?: TextDecoderOptions): TextDecoder;
}

/**
 * Decoder for Uint8Array to string by UTF-8 encoding
 * based WHATWG Encoding API
 */
declare const TextDecoder: TextDecoderConstructor;

/**
 * Provides performance.now() from High Resolution Time Level 2
 */
declare const performance: Duktape.Performance;