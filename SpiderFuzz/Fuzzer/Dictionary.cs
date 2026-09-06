namespace SpiderFuzz.Fuzzer;

internal static class Dictionary
{
    public static readonly string[] Keywords =
    [
        "break", "case", "catch", "class", "const", "continue", "debugger",
        "default", "delete", "do", "else", "export", "extends", "finally",
        "for", "function", "if", "import", "in", "instanceof", "let", "new",
        "of", "return", "super", "switch", "this", "throw", "try", "typeof",
        "var", "void", "while", "with", "yield", "async", "await", "from",
        "static", "get", "set", "accessor",
    ];

    public static readonly string[] Builtins =
    [
        "Object", "Array", "Function", "Number", "String", "Boolean",
        "Symbol", "BigInt", "RegExp", "Error", "TypeError", "RangeError",
        "SyntaxError", "ReferenceError", "URIError", "EvalError",
        "AggregateError", "Promise", "Proxy", "Reflect",
        "Math", "JSON", "Date", "Intl", "console", "globalThis",
        "Map", "Set", "WeakMap", "WeakSet",
        "ArrayBuffer", "SharedArrayBuffer", "DataView",
        "Int8Array", "Uint8Array", "Uint8ClampedArray",
        "Int16Array", "Uint16Array", "Int32Array", "Uint32Array",
        "Float32Array", "Float64Array", "BigInt64Array", "BigUint64Array",
        "WeakRef", "FinalizationRegistry", "Atomics",
        "parseInt", "parseFloat", "isNaN", "isFinite",
        "encodeURI", "decodeURI", "encodeURIComponent", "decodeURIComponent",
        "eval", "Function", "setTimeout", "setInterval",
        "queueMicrotask", "requestAnimationFrame", "cancelAnimationFrame",
        "structuredClone", "reportError", "escape", "unescape",
        // ES2024-2026: Iterator helpers, explicit resource management,
        // half-precision typed arrays (all shipped across engines by 2025).
        "Iterator", "DisposableStack", "AsyncDisposableStack", "Float16Array",
        "SuppressedError",
    ];

    public static readonly string[] PropertyNames =
    [
        "constructor", "prototype", "__proto__", "toString", "valueOf",
        "hasOwnProperty", "isPrototypeOf", "propertyIsEnumerable",
        "toLocaleString", "__defineGetter__", "__defineSetter__",
        "__lookupGetter__", "__lookupSetter__",
        "length", "name", "arguments", "caller", "callee",
        "next", "return", "throw", "done", "value",
        "index", "input", "groups", "indices",
        "message", "cause", "stack", "fileName", "lineNumber",
        "columnNumber", "name",
        "enabled", "handle", "register", "deref", "cleanup",
        "status", "reason", "type", "detail",
        // ES2024-2026: resizable ArrayBuffer, Set-like protocol, base64/hex options.
        "size", "resizable", "maxByteLength", "growable",
        "alphabet", "lastChunkHandling", "omitPadding", "read", "written",
    ];

    public static readonly string[] MethodNames =
    [
        "apply", "bind", "call",
        "entries", "keys", "values", "from", "of", "fromEntries",
        "assign", "freeze", "seal", "preventExtensions",
        "isFrozen", "isSealed", "isExtensible", "is",
        "defineProperty", "defineProperties",
        "getOwnPropertyDescriptor", "getOwnPropertyDescriptors",
        "getOwnPropertyNames", "getOwnPropertySymbols",
        "getPrototypeOf", "setPrototypeOf", "create",
        "hasOwn", "groupBy",
        "parse", "stringify", "isRaw",
        "isArray", "of",
        "now", "random", "max", "min", "abs", "ceil", "floor", "round",
        "sqrt", "cbrt", "pow", "log", "log2", "log10",
        "sin", "cos", "tan", "asin", "acos", "atan", "atan2",
        "exp", "expm1", "log1p", "sign", "trunc", "fround",
        "clz32", "imul", "hypot",
        "fill", "find", "findIndex", "findLast", "findLastIndex",
        "includes", "indexOf", "lastIndexOf",
        "map", "filter", "reduce", "reduceRight",
        "some", "every", "flat", "flatMap",
        "slice", "splice", "concat", "reverse", "sort",
        "push", "pop", "shift", "unshift",
        "copyWithin", "at", "with",
        "charCodeAt", "charAt", "codePointAt",
        "normalize", "padStart", "padEnd", "repeat",
        "replace", "replaceAll", "match", "matchAll", "search", "split",
        "substring", "toLowerCase", "toUpperCase", "toLocaleLowerCase", "toLocaleUpperCase",
        "trim", "trimStart", "trimEnd", "trimLeft", "trimRight",
        "startsWith", "endsWith", "includes",
        "anchor", "big", "blink", "bold", "fixed", "fontcolor", "fontsize",
        "italic", "link", "small", "strike", "sub", "sup",
        "localeCompare", "toLocaleString",
        "toPrecision", "toExponential", "toFixed",
        "toString", "valueOf", "toFixed",
        "detach", "transfer", "transferToFixedLength",
        "grow", "resize",
        "getByteLength", "getByteOffset", "getFloatOffset",
        "getInt8", "getUint8", "getInt16", "getUint16",
        "getInt32", "getUint32", "getFloat32", "getFloat64",
        "setInt8", "setUint8", "setInt16", "setUint16",
        "setInt32", "setUint32", "setFloat32", "setFloat64",
        "wait", "waitAsync", "notify",
        "get", "set", "has", "deleteProperty",
        "ownKeys", "isExtensible", "preventExtensions",
        "getPrototypeOf", "setPrototypeOf",
        "apply", "construct",
        // ES2023-2026: Set methods, Uint8Array base64/hex, well-formed
        // strings, change-array-by-copy, Iterator helpers, resource
        // management, Promise.try/withResolvers/fromAsync, Atomics.pause.
        "union", "intersection", "difference", "symmetricDifference",
        "isSubsetOf", "isSupersetOf", "isDisjointFrom",
        "toBase64", "fromBase64", "toHex", "fromHex",
        "setFromBase64", "setFromHex",
        "isWellFormed", "toWellFormed",
        "toSorted", "toReversed", "toSpliced",
        "take", "drop", "toArray", "asIndexedPairs",
        "use", "adopt", "defer", "move", "dispose", "asyncDispose",
        "withResolvers", "try", "fromAsync", "pause", "escape",
    ];

    public static readonly string[] SpecialValues =
    [
        "undefined", "null", "true", "false",
        "NaN", "Infinity", "-Infinity",
        "0", "-0", "1", "-1",
        "Number.MAX_SAFE_INTEGER", "Number.MIN_SAFE_INTEGER",
        "Number.MAX_VALUE", "Number.MIN_VALUE", "Number.EPSILON",
        "Number.NaN", "Number.POSITIVE_INFINITY", "Number.NEGATIVE_INFINITY",
        "Number.MIN_NORMAL",
        "Number.MAX_SAFE_INTEGER + 1",
        "Number.MIN_SAFE_INTEGER - 1",
        "Number.MAX_VALUE * 2",
        "1/0", "0/0", "-1/0",
        "0xffffffff", "0x1fffffffffffff",
        "9007199254740991", "9007199254740992",
        "1e308", "-1e308", "5e-324",
        "2**53", "-(2**53)", "2**53 + 1",
        "0o77777777777777777", "0o100000000000000000",
        "0b111111111111111111111111111111111111111111111111111111111111111",
    ];

    public static readonly string[] StringEdgeCases =
    [
        "\"\"", "\"a\"", "\"\\0\"", "\"\\xff\"",
        "\"\\u0000\"", "\"\\u00ff\"", "\"\\u0100\"",
        "\"\\ud800\"", "\"\\udc00\"", "\"\\udfff\"",
        "\"\\ud800\\udc00\"", "\"\\ud800\\udfff\"",
        "\"\\udbff\\udfff\"",
        "\"constructor\"", "\"__proto__\"", "\"prototype\"",
        "\"toString\"", "\"valueOf\"", "\"toJSON\"",
        "\"length\"", "\"name\"", "\"arguments\"",
        "\"caller\"", "\"callee\"",
        "\"hasOwnProperty\"", "\"isPrototypeOf\"",
        "\"" + new string('A', 1024) + "\"",
        "\"" + new string('A', 65536) + "\"",
        "\"" + new string('A', 1048576) + "\"",
        "\"\\n\\r\\t\\0\\b\\f\\v\"",
        "\"\\u{1F600}\"", "\"\\u{10FFFF}\"", "\"\\u{110000}\"",
        "\"\\x00\"", "\"\\x01\"", "\"\\x7f\"",
    ];

    public static readonly string[] RegexPatterns =
    [
        "/.*/", "/./", "/(?:)/", "/(?=)/", "/(?!)/", "/(?<=)/", "/(?<!)/",
        "/(a|b)*/", "/[a-z]/", "/[^a-z]/",
        "/\\d+/", "/\\w+/", "/\\s+/",
        "/(a*)*/", "/(a+)+/", "/(a{1,100})+/",
        "/[\\x00-\\xff]/", "/[\\u0000-\\uffff]/",
        "/^(a+)+$/", "/^(a|b|ab)*$/",
        "/(?:(?:a){1}){1}/",
        "/a{99999}/", "/(?:a{0})*/",
        "/((?:a){10000})/",
        "/([a-z]*)*$/",
        "/^(a|ab)*$/",
        "/((a|ab)+)+$/",
        "/a[ab]{0,10}b/",
        "/(?:a{2,}){1,}/",
        "/(?:[a-zA-Z0-9]+)*/",
        "/\\bword\\b/",
        "/(?<name>a)/",
        "/(?<name>a)(?<name>b)/",
        "/\\p{L}+/",
        "/\\p{N}+/",
        "/\\P{L}+/",
        "/[\\p{Script=Latin}]+/",
    ];

    public static readonly string[] RegexFlags =
        ["", "g", "i", "m", "s", "u", "y", "d", "v", "gi", "gm", "gim", "gimsuy", "gv", "giv"];

    public static string RandomFrom(Random rng, string[] array)
        => array[rng.Next(array.Length)];
}
