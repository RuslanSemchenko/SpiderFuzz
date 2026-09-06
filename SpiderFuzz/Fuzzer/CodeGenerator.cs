using System.Text;
using System.Text.RegularExpressions;

namespace SpiderFuzz.Fuzzer;

internal sealed class CodeGenerator
{
    private readonly Random _rng;

    private static readonly string[] _binaryOps =
    [
        "+", "-", "*", "/", "%", "**",
        "|", "&", "^", "<<", ">>", ">>>",
        "==", "===", "!=", "!==",
        "<", ">", "<=", ">=",
        "&&", "||", "??",
        "in", "instanceof",
        "=", "+=", "-=", "*=", "/=", "%=",
        "**=", "|=", "&=", "^=", "<<=", ">>=", ">>>=",
        "&&=", "||=", "??="
    ];

    private static readonly string[] _unaryOps =
    ["!", "~", "+", "-", "typeof", "void", "delete", "++", "--"];

    private static readonly string[] _predefinedNames =
    [
        "Object", "Array", "Function", "Number", "String", "Boolean",
        "Symbol", "BigInt", "RegExp", "Error", "TypeError", "RangeError",
        "SyntaxError", "ReferenceError", "Map", "Set", "WeakMap", "WeakSet",
        "Promise", "Proxy", "Reflect", "Math", "JSON", "Date", "Intl",
        "ArrayBuffer", "SharedArrayBuffer", "DataView",
        "Int8Array", "Uint8Array", "Int16Array", "Uint16Array",
        "Int32Array", "Uint32Array", "Float32Array", "Float64Array",
        "BigInt64Array", "BigUint64Array",
        "WeakRef", "FinalizationRegistry",
        "Atomics", "JSON", "console", "globalThis",
        "parseInt", "parseFloat", "isNaN", "isFinite",
        "encodeURI", "decodeURI", "encodeURIComponent", "decodeURIComponent",
        "eval", "Function", "setTimeout", "setInterval"
    ];

    private static readonly string[] _specialValues =
    [
        "undefined", "null", "true", "false",
        "NaN", "Infinity", "-Infinity",
        "0", "-0", "1", "-1", "0xFFFFFFFF", "0x7FFFFFFF",
        "Number.MAX_SAFE_INTEGER", "Number.MIN_SAFE_INTEGER",
        "Number.MAX_VALUE", "Number.MIN_VALUE", "Number.EPSILON",
        "Number.NaN", "Number.POSITIVE_INFINITY", "Number.NEGATIVE_INFINITY",
        "Number.MIN_NORMAL", "Number.MAX_VALUE"
    ];

    private static readonly string[] _stringLiterals =
    [
        "\"\"", "\"a\"", "\"\\0\"", "\"\\xff\"",
        "\"\\u0000\"", "\"\\ud800\"", "\"\\udfff\"",
        "\"constructor\"", "\"__proto__\"", "\"prototype\"",
        "\"toString\"", "\"valueOf\"", "\"toJSON\"",
        "\"length\"", "\"name\"", "\"arguments\"",
        "\"caller\"", "\"callee\"",
        "\"" + new string('A', 1000) + "\"",
        "\"\\\\\"",
        "\"${alert(1)}\"",
        "\"\\n\\r\\t\\0\"",
        "\"\\u{1F600}\"",
        "\"" + new string('x', 65536) + "\"",
    ];

    private static readonly string[] _regexPatterns =
    [
        "/.*/", "/./", "/(?:)/", "/(?=)/", "/(?!)/", "/(?<=)/", "/(?<!)/",
        "/(a|b)*/", "/[a-z]/", "/[^a-z]/",
        "/\\\\d+/", "/\\\\w+/", "/\\\\s+/",
        "/(a*)*/", "/(a+)+/", "/(a{1,100})+/",
        "/[\\x00-\\xff]/", "/[\\u0000-\\uffff]/",
        "/^(a+)+$/", "/^(a|b|ab)*$/",
        "/(?:(?:a){1}){1}/",
        "/a{99999}/", "/(?:a{0})*/",
    ];

    private static readonly string[] _regexFlags = ["", "g", "i", "m", "s", "u", "y", "gi", "gm", "gims", "gimsuy"];

    public CodeGenerator(int? seed = null)
    {
        _rng = new Random(seed ?? Environment.TickCount);
    }

    public string Generate()
    {
        var strategy = _rng.Next(46);
        return strategy switch
        {
            0 => GenerateGcStress(),
            1 => GenerateTypeConfusion(),
            2 => GenerateJitHotLoop(),
            3 => GenerateProxyChaos(),
            4 => GenerateRegexFuzz(),
            5 => GenerateTypedArrayFuzz(),
            6 => GenerateWeakRefFuzz(),
            7 => GenerateDeepNesting(),
            8 => GeneratePromiseChain(),
            9 => GenerateDestructuringFuzz(),
            10 => GenerateTemplateLiteralFuzz(),
            11 => GenerateMutation(MakeStatement()),
            12 => GenerateClassChaos(),
            13 => GenerateInliningChaos(),
            14 => GenerateIteratorFuzz(),
            15 => GenerateExceptionFuzz(),
            16 => GenerateAtomicsFuzz(),
            17 => GenerateMapSetFuzz(),
            18 => GenerateArrayMethodFuzz(),
            19 => GenerateErrorChainFuzz(),
            20 => GenerateSymbolPropertyFuzz(),
            21 => GenerateGetterSetterFuzz(),
            22 => GenerateArgumentConfusion(),
            23 => GenerateEvalFuzz(),
            24 => GenerateScopeChaos(),
            25 => GenerateBigIntFuzz(),
            26 => GenerateJitTypeChange(),
            27 => GenerateArrayBuffersCorruption(),
            28 => GenerateIonBailoutStress(),
            29 => GenerateCacheIrShapeChurn(),
            30 => GenerateGcRealmWeakMap(),
            31 => GenerateUnicodeRegExpV(),
            32 => GenerateModuleGraph(),
            33 => GenerateWasmBoundaryOracle(),
            34 => GenerateWasmSimdOracle(),
            35 => GenerateAsyncDelazification(),
            36 => GenerateIteratorHelpersFuzz(),
            37 => GenerateSetMethodsFuzz(),
            38 => GenerateUint8ArrayCodecFuzz(),
            39 => GenerateResourceManagementFuzz(),
            40 => GenerateModernPromiseFuzz(),
            41 => GenerateRegexModernFuzz(),
            42 => GenerateGroupByFuzz(),
            43 => GenerateFloat16Fuzz(),
            _ => GenerateMixed(),
        };
    }

    public string GenerateFromStrategy(int strategy)
    {
        return strategy switch
        {
            0 => GenerateGcStress(),
            1 => GenerateTypeConfusion(),
            2 => GenerateJitHotLoop(),
            3 => GenerateProxyChaos(),
            4 => GenerateRegexFuzz(),
            5 => GenerateTypedArrayFuzz(),
            6 => GenerateWeakRefFuzz(),
            7 => GenerateDeepNesting(),
            8 => GeneratePromiseChain(),
            9 => GenerateDestructuringFuzz(),
            10 => GenerateTemplateLiteralFuzz(),
            11 => GenerateMutation(MakeStatement()),
            12 => GenerateClassChaos(),
            13 => GenerateInliningChaos(),
            14 => GenerateIteratorFuzz(),
            15 => GenerateExceptionFuzz(),
            16 => GenerateAtomicsFuzz(),
            17 => GenerateMapSetFuzz(),
            18 => GenerateArrayMethodFuzz(),
            19 => GenerateErrorChainFuzz(),
            20 => GenerateSymbolPropertyFuzz(),
            21 => GenerateGetterSetterFuzz(),
            22 => GenerateArgumentConfusion(),
            23 => GenerateEvalFuzz(),
            24 => GenerateScopeChaos(),
            25 => GenerateBigIntFuzz(),
            26 => GenerateJitTypeChange(),
            27 => GenerateArrayBuffersCorruption(),
            28 => GenerateIonBailoutStress(),
            29 => GenerateCacheIrShapeChurn(),
            30 => GenerateGcRealmWeakMap(),
            31 => GenerateUnicodeRegExpV(),
            32 => GenerateModuleGraph(),
            33 => GenerateWasmBoundaryOracle(),
            34 => GenerateWasmSimdOracle(),
            35 => GenerateAsyncDelazification(),
            36 => GenerateIteratorHelpersFuzz(),
            37 => GenerateSetMethodsFuzz(),
            38 => GenerateUint8ArrayCodecFuzz(),
            39 => GenerateResourceManagementFuzz(),
            40 => GenerateModernPromiseFuzz(),
            41 => GenerateRegexModernFuzz(),
            42 => GenerateGroupByFuzz(),
            43 => GenerateFloat16Fuzz(),
            _ => GenerateMixed(),
        };
    }

    public string Mutate(string input)
    {
        return GenerateMutation(input);
    }

    private string GenerateMutation(string source)
    {
        var sb = new StringBuilder(source);
        var mutations = _rng.Next(1, 6);
        for (var i = 0; i < mutations; i++)
        {
            var op = _rng.Next(6);
            switch (op)
            {
                case 0:
                    if (sb.Length > 0)
                    {
                        var pos = _rng.Next(sb.Length);
                    var ch = (char)_rng.Next(256);
                        sb.Insert(pos, ch);
                    }
                    break;
                case 1:
                    if (sb.Length > 0)
                    {
                        var pos = _rng.Next(sb.Length);
                        sb.Remove(pos, 1);
                    }
                    break;
                case 2:
                    if (sb.Length > 0)
                    {
                        var pos = _rng.Next(sb.Length);
                        sb[pos] = (char)_rng.Next(256);
                    }
                    break;
                case 3:
                    {
                        var pos = _rng.Next(Math.Max(1, sb.Length));
                        sb.Insert(pos, RandomByteString(_rng.Next(1, 20)));
                    }
                    break;
                case 4:
                    if (sb.Length > 2)
                    {
                        var a = _rng.Next(sb.Length);
                        var b = _rng.Next(sb.Length);
                        if (a > b) (a, b) = (b, a);
                        var segment = sb.ToString(a, b - a);
                        var pos = _rng.Next(Math.Max(1, sb.Length));
                        sb.Insert(pos, segment);
                    }
                    break;
                case 5:
                    if (sb.Length > 0)
                    {
                        var pos = _rng.Next(sb.Length);
                        var len = Math.Min(_rng.Next(1, 5), sb.Length - pos);
                        sb.Remove(pos, len);
                    }
                    break;
            }
        }
        return sb.ToString();
    }

    // Byte-level mutation almost always breaks JS syntax (SyntaxError) since
    // the language is highly structured, so most mutated inputs never reach
    // the engine's interpreter/JIT at all. The methods below operate on whole
    // lines/statements instead (this generator emits one statement per line),
    // which is far more likely to stay syntactically valid, plus classic
    // AFL-style splicing between two unrelated corpus entries for real
    // cross-pollination of language features.

    /// <summary>
    /// Returns the line indices (as an exclusive end-of-block cut list, always
    /// including 0 and the full length) where brace/paren/bracket nesting is
    /// back to zero, i.e. plausible statement boundaries. This is a cheap
    /// heuristic (it does not understand strings/comments/regex literals) but
    /// is good enough to keep most splices/block edits syntactically valid.
    /// </summary>
    private static List<int> FindBalancedBoundaries(IReadOnlyList<string> lines)
    {
        var boundaries = new List<int> { 0 };
        int brace = 0, paren = 0, bracket = 0;

        for (var i = 0; i < lines.Count; i++)
        {
            foreach (var ch in lines[i])
            {
                switch (ch)
                {
                    case '{': brace++; break;
                    case '}': brace--; break;
                    case '(': paren++; break;
                    case ')': paren--; break;
                    case '[': bracket++; break;
                    case ']': bracket--; break;
                }
            }

            if (brace == 0 && paren == 0 && bracket == 0) boundaries.Add(i + 1);
        }

        return boundaries;
    }

    /// <summary>
    /// AFL-style crossover: splices a prefix of <paramref name="a"/> with a
    /// suffix of <paramref name="b"/>, cutting at statement boundaries when
    /// possible so the result more often stays parseable.
    /// </summary>
    public string Splice(string a, string b)
    {
        var linesA = a.Split('\n');
        var linesB = b.Split('\n');
        var boundA = FindBalancedBoundaries(linesA);
        var boundB = FindBalancedBoundaries(linesB);

        if (linesA.Length == 0 || linesB.Length == 0) return a.Length > 0 ? a : b;

        var cutA = boundA.Count > 0 ? boundA[_rng.Next(boundA.Count)] : linesA.Length;
        var cutB = boundB.Count > 0 ? boundB[_rng.Next(boundB.Count)] : 0;

        var combined = linesA.Take(cutA).Concat(linesB.Skip(cutB)).ToArray();
        return combined.Length > 0 ? string.Join('\n', combined) : a;
    }

    // Matches `var`/`let`/`const` declarations so block deletion can avoid
    // dropping a declaration whose name is still referenced elsewhere in the
    // snippet - otherwise an oracle assertion further down (e.g. `if (typeof
    // r !== 'number') throw new Error(...)`) silently loses the code that
    // computed `r` and then "fails" on every run, which looks like an engine
    // regression but is really just a mutation that tore the test apart.
    private static readonly Regex DeclarationRegex = new(
        @"\b(?:var|let|const)\s+([A-Za-z_$][A-Za-z0-9_$]*)", RegexOptions.Compiled);

    private static bool IsSafeToRemove(IReadOnlyList<string> lines, int start, int end)
    {
        List<string>? removedNames = null;
        for (var i = start; i < end; i++)
        {
            foreach (Match m in DeclarationRegex.Matches(lines[i]))
            {
                (removedNames ??= []).Add(m.Groups[1].Value);
            }
        }

        if (removedNames == null) return true;

        for (var i = 0; i < lines.Count; i++)
        {
            if (i >= start && i < end) continue;
            foreach (var name in removedNames)
            {
                if (Regex.IsMatch(lines[i], $@"\b{Regex.Escape(name)}\b")) return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Line/statement-granularity mutation: duplicate, delete or reorder whole
    /// statement blocks, or splice in a freshly generated one-liner. Far less
    /// likely to break the parser than editing raw bytes.
    /// </summary>
    public string MutateLines(string input)
    {
        var lines = input.Split('\n').ToList();
        if (lines.Count == 0) return input;

        var boundaries = FindBalancedBoundaries(lines);
        var op = _rng.Next(4);

        switch (op)
        {
            case 0: // duplicate a random statement block elsewhere
                if (boundaries.Count >= 2)
                {
                    var i = _rng.Next(boundaries.Count - 1);
                    var j = i + 1 + _rng.Next(boundaries.Count - i - 1);
                    var start = boundaries[i];
                    var end = Math.Min(boundaries[j], lines.Count);
                    if (end > start)
                    {
                        var block = lines.GetRange(start, end - start);
                        var insertAt = Math.Min(boundaries[_rng.Next(boundaries.Count)], lines.Count);
                        lines.InsertRange(insertAt, block);
                    }
                }
                break;
            case 1: // delete a random statement block, skipping ones whose
                     // declarations are still referenced later in the file
                if (boundaries.Count >= 2)
                {
                    for (var attempt = 0; attempt < 3; attempt++)
                    {
                        var i = _rng.Next(boundaries.Count - 1);
                        var start = boundaries[i];
                        var end = Math.Min(boundaries[i + 1], lines.Count);
                        if (end > start && IsSafeToRemove(lines, start, end))
                        {
                            lines.RemoveRange(start, end - start);
                            break;
                        }
                    }
                }
                break;
            case 2: // swap two lines
                if (lines.Count > 1)
                {
                    var i = _rng.Next(lines.Count);
                    var j = _rng.Next(lines.Count);
                    (lines[i], lines[j]) = (lines[j], lines[i]);
                }
                break;
            default: // insert a freshly generated statement at a safe boundary
                {
                    var pos = boundaries.Count > 0
                        ? Math.Min(boundaries[_rng.Next(boundaries.Count)], lines.Count)
                        : lines.Count;
                    lines.Insert(pos, MakeStatement());
                }
                break;
        }

        return string.Join('\n', lines);
    }

    private string GenerateGcStress()
    {
        var sb = new StringBuilder();
        sb.AppendLine("'use strict';");
        sb.AppendLine("var objs = [];");

        var count = _rng.Next(100, 5000);
        for (var i = 0; i < count; i++)
        {
            var line = _rng.Next(10);
            switch (line)
            {
                case 0:
                    sb.AppendLine($"objs.push({{a: {RNum()}, b: {RStr()}, c: {RNum()}}});");
                    break;
                case 1:
                    sb.AppendLine($"objs.push(new Array({RNum()}).fill({RStr()}));");
                    break;
                case 2:
                    sb.AppendLine($"objs.push(new Map([[{RStr()}, {RNum()}]]));");
                    break;
                case 3:
                    sb.AppendLine($"objs.push(new Set([{RNum()}, {RStr()}, {RNum()}]));");
                    break;
                case 4:
                    sb.AppendLine($"objs.push(new RegExp({RStr()}));");
                    break;
                case 5:
                    sb.AppendLine($"objs.push(new Error({RStr()}));");
                    break;
                case 6:
                    sb.AppendLine($"objs.push(Promise.resolve({RNum()}));");
                    break;
                case 7:
                    sb.AppendLine($"objs.push(new Proxy({{}}, {{get: () => {RNum()}, set: () => true}}));");
                    break;
                case 8:
                    sb.AppendLine($"objs.push(new ArrayBuffer({_rng.Next(1, 1024)}));");
                    break;
                case 9:
                    sb.AppendLine($"objs.push(function() {{ return {RNum()}; }});");
                    break;
            }

            if (i % 100 == 0)
            {
                sb.AppendLine("objs.length = Math.max(0, objs.length - 50);");
            }
        }

        sb.AppendLine("objs = null;");
        sb.AppendLine("if (typeof gczeal === 'function') { try { gczeal(" + _rng.Next(0, 15) + "); } catch(e) {} }");
        sb.AppendLine("if (typeof gc === 'function') gc();");
        sb.AppendLine("if (typeof gcslice === 'function') { try { gcslice(100); } catch(e) {} }");
        return sb.ToString();
    }

    private string GenerateTypeConfusion()
    {
        var sb = new StringBuilder();
        sb.AppendLine("'use strict';");

        var varCount = _rng.Next(3, 15);
        var vars = new string[varCount];
        for (var i = 0; i < varCount; i++)
        {
            vars[i] = $"v{i}";
            sb.AppendLine($"var {vars[i]} = {RValue()};");
        }

        var ops = _rng.Next(20, 200);
        for (var i = 0; i < ops; i++)
        {
            var v = vars[_rng.Next(vars.Length)];
            var action = _rng.Next(12);
            switch (action)
            {
                case 0:
                    sb.AppendLine($"{v} = {RValue()};");
                    break;
                case 1:
                    sb.AppendLine($"{v} = {v} {_randomBinOp()} {RValue()};");
                    break;
                case 2:
                    sb.AppendLine($"{v} = {_randomUnaryOp()} {v};");
                    break;
                case 3:
                    sb.AppendLine($"{v} = typeof {v};");
                    break;
                case 4:
                    sb.AppendLine($"{v} = {v} instanceof {RPredefinedName()};");
                    break;
                case 5:
                    sb.AppendLine($"try {{ {v}[{RStr()}]; }} catch(e) {{}}");
                    break;
                case 6:
                    sb.AppendLine($"{v} = Object({v});");
                    break;
                case 7:
                    sb.AppendLine($"{v} = Number({v});");
                    break;
                case 8:
                    sb.AppendLine($"{v} = String({v});");
                    break;
                case 9:
                    sb.AppendLine($"{v} = Boolean({v});");
                    break;
                case 10:
                    sb.AppendLine($"{v} = BigInt({v}) || 0n;");
                    break;
                case 11:
                    sb.AppendLine($"try {{ {v} = {v} + {v}; }} catch(e) {{}}");
                    break;
            }
        }

        return sb.ToString();
    }

    private string GenerateJitHotLoop()
    {
        var sb = new StringBuilder();
        sb.AppendLine("'use strict';");

        var loopCount = _rng.Next(3, 10);
        for (var l = 0; l < loopCount; l++)
        {
            var fnName = $"hot{l}";
            var paramCount = _rng.Next(1, 5);
            var paramList = string.Join(", ", Enumerable.Range(0, paramCount).Select(i => $"p{i}"));

            sb.AppendLine($"function {fnName}({paramList}) {{");
            var bodyOps = _rng.Next(5, 30);
            for (var i = 0; i < bodyOps; i++)
            {
                sb.AppendLine($"  {MakeStatement()}");
            }
            sb.AppendLine("}");

            var argCount = paramCount;
            sb.AppendLine($"for (var i{l} = 0; i{l} < 100000; i{l}++) {{");

            var argVals = string.Join(", ", Enumerable.Range(0, argCount).Select(_ => RValue()));
            sb.AppendLine($"  {fnName}({argVals});");

            if (_rng.Next(3) == 0)
            {
                var argVals2 = string.Join(", ", Enumerable.Range(0, argCount).Select(_ => RValue()));
                sb.AppendLine($"  {fnName}({argVals2});");
            }
            sb.AppendLine("}");
        }

        return sb.ToString();
    }

    private string GenerateProxyChaos()
    {
        var sb = new StringBuilder();
        sb.AppendLine("'use strict';");

        var trapNames = new[]
        {
            "get", "set", "has", "deleteProperty", "ownKeys",
            "getOwnPropertyDescriptor", "defineProperty",
            "getPrototypeOf", "setPrototypeOf",
            "isExtensible", "preventExtensions",
            "apply", "construct"
        };

        var proxyCount = _rng.Next(1, 8);
        for (var p = 0; p < proxyCount; p++)
        {
            sb.AppendLine($"var handler{p} = {{");

            var trapCount = _rng.Next(1, trapNames.Length + 1);
            var usedTraps = trapNames.OrderBy(_ => _rng.Next()).Take(trapCount).ToArray();
            foreach (var trap in usedTraps)
            {
                sb.AppendLine($"  {trap}: function(...args) {{ {MakeStatement()} return args[0]; }},");
            }
            sb.AppendLine("};");

            sb.AppendLine($"var proxy{p} = new Proxy({RValue()}, handler{p});");
        }

        var actions = _rng.Next(10, 50);
        for (var i = 0; i < actions; i++)
        {
            var pi = _rng.Next(proxyCount);
            var action = _rng.Next(8);
            switch (action)
            {
                case 0:
                    sb.AppendLine($"proxy{pi}[{RStr()}];");
                    break;
                case 1:
                    sb.AppendLine($"proxy{pi}[{RStr()}] = {RValue()};");
                    break;
                case 2:
                    sb.AppendLine($"{RStr()} in proxy{pi};");
                    break;
                case 3:
                    sb.AppendLine($"delete proxy{pi}[{RStr()}];");
                    break;
                case 4:
                    sb.AppendLine($"Object.keys(proxy{pi});");
                    break;
                case 5:
                    sb.AppendLine($"Object.getOwnPropertyDescriptor(proxy{pi}, {RStr()});");
                    break;
                case 6:
                    sb.AppendLine($"Object.getPrototypeOf(proxy{pi});");
                    break;
                case 7:
                    sb.AppendLine($"Reflect.ownKeys(proxy{pi});");
                    break;
            }
        }

        return sb.ToString();
    }

    private string GenerateRegexFuzz()
    {
        var sb = new StringBuilder();
        sb.AppendLine("'use strict';");

        var testCount = _rng.Next(10, 100);
        for (var i = 0; i < testCount; i++)
        {
            var pattern = _regexPatterns[_rng.Next(_regexPatterns.Length)];
            var flags = _regexFlags[_rng.Next(_regexFlags.Length)];
            var testStr = RStr();

            sb.AppendLine($"try {{");
            sb.AppendLine($"  var re{i} = new RegExp({pattern}, \"{flags}\");");
            sb.AppendLine($"  re{i}.test({testStr});");
            sb.AppendLine($"  re{i}.exec({testStr});");
            sb.AppendLine($"  {testStr}.match(re{i});");
            sb.AppendLine($"  {testStr}.replace(re{i}, {RStr()});");
            sb.AppendLine($"  {testStr}.search(re{i});");
            sb.AppendLine($"  {testStr}.split(re{i});");
            sb.AppendLine($"}} catch(e) {{}}");
        }

        return sb.ToString();
    }

    private string GenerateTypedArrayFuzz()
    {
        var sb = new StringBuilder();
        sb.AppendLine("'use strict';");

        var arrayTypes = new[]
        {
            "Int8Array", "Uint8Array", "Uint8ClampedArray",
            "Int16Array", "Uint16Array", "Int32Array", "Uint32Array",
            "Float32Array", "Float64Array", "BigInt64Array", "BigUint64Array"
        };

        var count = _rng.Next(5, 30);
        for (var i = 0; i < count; i++)
        {
            var type = arrayTypes[_rng.Next(arrayTypes.Length)];
            var size = _rng.Next(0, 100000);

            if (_rng.Next(3) == 0)
            {
                sb.AppendLine($"try {{ var ta{i} = new {type}({size}); }} catch(e) {{}}");
            }
            else
            {
                sb.AppendLine($"try {{ var buf{i} = new ArrayBuffer({size}); var ta{i} = new {type}(buf{i}); }} catch(e) {{}}");
            }
        }

        var accessCount = _rng.Next(20, 200);
        for (var i = 0; i < accessCount; i++)
        {
            var idx = _rng.Next(count);
            var offset = _rng.Next(-10, 10000);
            var action = _rng.Next(4);
            switch (action)
            {
                case 0:
                    sb.AppendLine($"try {{ var v = ta{idx}[{offset}]; }} catch(e) {{}}");
                    break;
                case 1:
                    sb.AppendLine($"try {{ ta{idx}[{offset}] = {RNum()}; }} catch(e) {{}}");
                    break;
                case 2:
                    sb.AppendLine($"try {{ ta{idx}.fill({RNum()}, {offset}, {offset + _rng.Next(1, 100)}); }} catch(e) {{}}");
                    break;
                case 3:
                    sb.AppendLine($"try {{ ta{idx}.slice({offset}, {offset + _rng.Next(1, 50)}); }} catch(e) {{}}");
                    break;
            }
        }

        sb.AppendLine($"try {{ var ab = new ArrayBuffer(1); var ta = new Uint8Array(ab); ta.byteLength = {RNum()}; }} catch(e) {{}}");
        sb.AppendLine($"try {{ var ta = new Uint8Array(0); ta[0] = 1; }} catch(e) {{}}");
        sb.AppendLine($"try {{ var ta = new Uint8Array([1,2,3]); ta.set(ta, 1); }} catch(e) {{}}");
        sb.AppendLine($"try {{ var ta = new Float64Array([NaN, Infinity, -Infinity, 0, -0]); }} catch(e) {{}}");

        if (_rng.Next(3) == 0)
            return GenerateResizableArrayBufferFuzz();
        if (_rng.Next(3) == 0)
            return GenerateDetachedTypedArrayFuzz();
        return sb.ToString();
    }

    private string GenerateResizableArrayBufferFuzz()
    {
        var sb = new StringBuilder("'use strict';\n");
        sb.AppendLine("if (typeof ArrayBuffer.prototype.resize === 'function') {");
        sb.AppendLine("  var rab = new ArrayBuffer(64, {maxByteLength: 256});");
        sb.AppendLine("  var fixed = new Uint8Array(rab, 0, 16), tracking = new Uint8Array(rab);");
        sb.AppendLine("  for (var i = 0; i < fixed.length; i++) fixed[i] = i + 1;");
        sb.AppendLine("  rab.resize(128); if (tracking.length !== 128) throw new Error('rab grow');");
        sb.AppendLine("  tracking[96] = 0xA5; rab.resize(32);");
        sb.AppendLine("  try { void tracking[96]; } catch (e) { if (!(e instanceof TypeError)) throw e; }");
        sb.AppendLine("  try { rab.resize(256); } catch (e) { if (!(e instanceof RangeError)) throw e; }");
        sb.AppendLine("  var dv = new DataView(rab); try { dv.getUint32(252); } catch (e) { if (!(e instanceof RangeError)) throw e; }");
        sb.AppendLine("} else if (typeof ArrayBuffer === 'function') { var b = new ArrayBuffer(32); var v = new Uint8Array(b); v[31] = 7; if (v[31] !== 7) throw new Error('buffer fallback'); }");
        return sb.ToString();
    }

    private string GenerateDetachedTypedArrayFuzz()
    {
        var sb = new StringBuilder("'use strict';\n");
        sb.AppendLine("var b = new ArrayBuffer(128), view = new Uint32Array(b), bytes = new Uint8Array(b);");
        sb.AppendLine("for (var i = 0; i < view.length; i++) view[i] = i + 1;");
        sb.AppendLine("if (typeof structuredClone === 'function') {");
        sb.AppendLine("  var moved = structuredClone(b, {transfer: [b]});");
        sb.AppendLine("  if (moved.byteLength !== 128) throw new Error('transfer length');");
        sb.AppendLine("  try { void view.length; view[0] = 9; } catch (e) { if (!(e instanceof TypeError)) throw e; }");
        sb.AppendLine("  try { bytes.slice(0, 4); } catch (e) { if (!(e instanceof TypeError)) throw e; }");
        sb.AppendLine("} else { if (bytes[0] !== 1) throw new Error('view baseline'); }");
        sb.AppendLine("var second = new Uint8Array(new ArrayBuffer(16)); second.set([1,2,3,4]); second.copyWithin(1, 0, 3);");
        return sb.ToString();
    }

    private string GenerateWeakRefFuzz()
    {
        var sb = new StringBuilder();
        sb.AppendLine("'use strict';");

        var count = _rng.Next(10, 200);
        for (var i = 0; i < count; i++)
        {
            var action = _rng.Next(6);
            switch (action)
            {
                case 0:
                    sb.AppendLine($"var obj{i} = {{}}; var wr{i} = new WeakRef(obj{i});");
                    break;
                case 1:
                    sb.AppendLine($"var wr{i} = new WeakRef({{}}); if (typeof gc === 'function') gc(); try {{ wr{i}.deref(); }} catch(e) {{}}");
                    break;
                case 2:
                    sb.AppendLine($"var fg{i} = new FinalizationRegistry((held) => {{}}); fg{i}.register({{}}, 'held{i}');");
                    break;
                case 3:
                    sb.AppendLine($"var fg{i} = new FinalizationRegistry(() => {{}}); var obj{i} = {{}}; fg{i}.register(obj{i}, obj{i}); obj{i} = null;");
                    break;
                case 4:
                    sb.AppendLine($"try {{ var wr{i} = new WeakRef(null); }} catch(e) {{}}");
                    break;
                case 5:
                    sb.AppendLine($"try {{ var wr{i} = new WeakRef(undefined); }} catch(e) {{}}");
                    break;
            }
        }

        if (_rng.Next(2) == 0)
        {
            sb.AppendLine("if (typeof gc === 'function') {");
            sb.AppendLine("  for (var i = 0; i < 100; i++) gc();");
            sb.AppendLine("}");
        }

        return sb.ToString();
    }

    private string GenerateDeepNesting()
    {
        var sb = new StringBuilder();
        sb.AppendLine("'use strict';");

        var depth = _rng.Next(50, 500);
        var sbExpr = new StringBuilder();

        for (var i = 0; i < depth; i++)
        {
            var wrap = _rng.Next(5);
            switch (wrap)
            {
                case 0:
                    sbExpr.Append('(');
                    break;
                case 1:
                    sbExpr.Append('[');
                    break;
                case 2:
                    sbExpr.Append("{a:");
                    break;
                case 3:
                    sbExpr.Append("function(){return ");
                    break;
                case 4:
                    sbExpr.Append("(()=>");
                    break;
            }
        }

        sbExpr.Append(RValue());

        for (var i = depth - 1; i >= 0; i--)
        {
            var wrap = _rng.Next(5);
            switch (wrap)
            {
                case 0:
                    sbExpr.Append(')');
                    break;
                case 1:
                    sbExpr.Append(']');
                    break;
                case 2:
                    sbExpr.Append('}');
                    break;
                case 3:
                    sbExpr.Append("}())");
                    break;
                case 4:
                    sbExpr.Append(")()");
                    break;
            }
        }

        sb.AppendLine($"try {{ {sbExpr}; }} catch(e) {{}}");

        var ifDepth = _rng.Next(20, 200);
        sb.AppendLine("try {");
        sb.Append("  ");
        for (var i = 0; i < ifDepth; i++)
        {
            sb.Append($"if ({RValue()}) {{ ");
        }
        sb.AppendLine($"{RNum()};");
        for (var i = 0; i < ifDepth; i++)
        {
            sb.Append("  ");
            for (var j = 0; j < i + 1; j++) sb.Append(' ');
            sb.AppendLine("}");
        }
        sb.AppendLine("} catch(e) {}");

        return sb.ToString();
    }

    private string GeneratePromiseChain()
    {
        var sb = new StringBuilder();
        sb.AppendLine("'use strict';");

        var chainLen = _rng.Next(5, 500);
        sb.Append("Promise.resolve(");
        sb.Append(RValue());
        sb.Append(')');

        for (var i = 0; i < chainLen; i++)
        {
            var chain = _rng.Next(6);
            switch (chain)
            {
                case 0:
                    sb.Append($".then((v) => {RValue()})");
                    break;
                case 1:
                    sb.Append($".catch((e) => {RValue()})");
                    break;
                case 2:
                    sb.Append($".finally(() => {{ {MakeStatement()} }})");
                    break;
                case 3:
                    sb.Append($".then((v) => Promise.resolve({RValue()}))");
                    break;
                case 4:
                    sb.Append($".then((v) => Promise.reject({RValue()}))");
                    break;
                case 5:
                    sb.Append($".then((v) => {{ throw new Error({RStr()}); }})");
                    break;
            }
        }

        sb.AppendLine(".catch(() => {});");

        var allCount = _rng.Next(2, 50);
        sb.AppendLine($"Promise.all([");
        for (var i = 0; i < allCount; i++)
        {
            sb.AppendLine($"  Promise.resolve({RValue()}){(i < allCount - 1 ? "," : "")}");
        }
        sb.AppendLine("]).catch(() => {});");

        var raceCount = _rng.Next(2, 50);
        sb.AppendLine($"Promise.race([");
        for (var i = 0; i < raceCount; i++)
        {
            var resolveOrReject = _rng.Next(2) == 0 ? "res" : "rej";
            var separator = i < raceCount - 1 ? "," : "";
            sb.AppendLine($"  new Promise((res, rej) => {{ {resolveOrReject}({RValue()}); }}){separator}");
        }
        sb.AppendLine("]).catch(() => {});");

        return sb.ToString();
    }

    private string GenerateDestructuringFuzz()
    {
        var sb = new StringBuilder();
        sb.AppendLine("'use strict';");

        var count = _rng.Next(10, 100);
        for (var i = 0; i < count; i++)
        {
            var action = _rng.Next(6);
            switch (action)
            {
                case 0:
                    sb.AppendLine($"var [{RVar()}, {RVar()}, ...{RVar()}] = {RValue()};");
                    break;
                case 1:
                    sb.AppendLine($"var {{{RVar()}: {RVar()}, {RVar()}: {RVar()}}} = {RValue()};");
                    break;
                case 2:
                    sb.AppendLine($"var [{RVar()}, [{RVar()} = {RValue()}, {RVar()}]] = {RValue()};");
                    break;
                case 3:
                    sb.AppendLine($"var [a{i} = {RValue()}, b{i} = {RValue()}] = {RValue()};");
                    break;
                case 4:
                    sb.AppendLine($"var {{x{i}: xi = {RValue()}, y{i}: yi = {RValue()}}} = {RValue()};");
                    break;
                case 5:
                    sb.AppendLine($"var {{{RVar()}: {RVar()} = {RValue()}, ...rest{i}}} = {RValue()};");
                    break;
            }
        }

        var paramCount = _rng.Next(1, 10);
        var destructuredParams = string.Join(", ",
            Enumerable.Range(0, paramCount).Select(_ => _rng.Next(2) == 0
                ? $"[{RVar()}, {RVar()}]"
                : $"{{{RVar()}: {RVar()}}}"));

        sb.AppendLine($"var fn = function({destructuredParams}) {{ {MakeStatement()} }};");
        sb.AppendLine($"try {{ fn({RValue()}); }} catch(e) {{}}");

        return sb.ToString();
    }

    private string GenerateTemplateLiteralFuzz()
    {
        var sb = new StringBuilder();
        sb.AppendLine("'use strict';");

        var count = _rng.Next(10, 50);
        for (var i = 0; i < count; i++)
        {
            var parts = _rng.Next(1, 20);
            var tpl = new StringBuilder("`");
            for (var j = 0; j < parts; j++)
            {
                if (_rng.Next(3) == 0)
                {
                    tpl.Append("${" + RExpr() + "}");
                }
                else
                {
                    tpl.Append(RandomAsciiString(_rng.Next(0, 50)));
                }
            }
            tpl.Append('`');
            sb.AppendLine("var tpl" + i + " = " + tpl + ";");
        }

        sb.AppendLine("var tag = (strings, ...values) => { return strings.join(''); };");
        var tagBody = RandomAsciiString(10) + "${" + RExpr() + "}" + RandomAsciiString(10);
        sb.AppendLine("try { tag`" + tagBody + "`; } catch(e) {}");

        return sb.ToString();
    }

    private string GenerateMixed()
    {
        var sb = new StringBuilder();
        sb.AppendLine("'use strict';");

        var featureCount = _rng.Next(3, 10);
        for (var i = 0; i < featureCount; i++)
        {
            var feature = _rng.Next(10);
            switch (feature)
            {
                case 0:
                    sb.AppendLine(GenerateGcStress());
                    break;
                case 1:
                    sb.AppendLine(GenerateTypeConfusion());
                    break;
                case 2:
                    sb.AppendLine(GenerateJitHotLoop());
                    break;
                case 3:
                    sb.AppendLine(GenerateRegexFuzz());
                    break;
                case 4:
                    sb.AppendLine(GenerateTypedArrayFuzz());
                    break;
                case 5:
                    sb.AppendLine(GenerateWeakRefFuzz());
                    break;
                case 6:
                    sb.AppendLine(GeneratePromiseChain());
                    break;
                case 7:
                    sb.AppendLine(GenerateDestructuringFuzz());
                    break;
                case 8:
                    sb.AppendLine(GenerateDeepNesting());
                    break;
                case 9:
                    sb.AppendLine(GenerateTemplateLiteralFuzz());
                    break;
            }
        }

        return sb.ToString();
    }

    private string GenerateClassChaos()
    {
        var sb = new StringBuilder();
        sb.AppendLine("'use strict';");

        var classCount = _rng.Next(3, 15);
        for (var i = 0; i < classCount; i++)
        {
            sb.AppendLine($"class C{i} {{");
            var memberCount = _rng.Next(3, 12);
            for (var m = 0; m < memberCount; m++)
            {
                var member = _rng.Next(8);
                switch (member)
                {
                    case 0:
                        sb.AppendLine($"  #private{m} = {RValue()};");
                        break;
                    case 1:
                        sb.AppendLine($"  static staticField{m} = {RValue()};");
                        break;
                    case 2:
                        sb.AppendLine($"  get prop{m}() {{ return this.#private{m} ?? {RValue()}; }}");
                        break;
                    case 3:
                        sb.AppendLine($"  set prop{m}(v) {{ this.#private{m} = v; }}");
                        break;
                    case 4:
                        sb.AppendLine($"  static get staticProp{m}() {{ return {RValue()}; }}");
                        break;
                    case 5:
                        sb.AppendLine($"  #method{m}({RVar()}) {{ return {RExpr()}; }}");
                        break;
                    case 6:
                        sb.AppendLine($"  static block{m}() {{ try {{ return {RExpr()}; }} catch(e) {{}} }}");
                        break;
                    case 7:
                        sb.AppendLine($"  async asyncMethod{m}() {{ return await Promise.resolve({RValue()}); }}");
                        break;
                }
            }
            sb.AppendLine("}");

            if (i == 0)
            {
                sb.AppendLine($"class Sub{i} extends C{i} {{");
                sb.AppendLine("  constructor() { super(); this.extra = 1; }");
                sb.AppendLine("}");
            }

            if (_rng.Next(3) == 0)
            {
                sb.AppendLine($"var c_{i} = new C{i}();");
                sb.AppendLine($"try {{ c_{i}(); }} catch(e) {{}}");
            }
            else
            {
                sb.AppendLine($"var c_{i} = new C{i}();");
                sb.AppendLine($"c_{i}.prop{_rng.Next(memberCount)} = {RValue()};");
                sb.AppendLine($"c_{i}.staticProp{i};");
            }
        }

        return sb.ToString();
    }

    private string GenerateInliningChaos()
    {
        var sb = new StringBuilder();
        sb.AppendLine("'use strict';");

        var depth = _rng.Next(5, 20);
        sb.AppendLine("function recurse() {");
        sb.AppendLine("  try { recurse(); } catch(e) {}");
        sb.AppendLine("}");

        sb.AppendLine("var waiter = new Array(200).fill(0).map((_, i) => i);");
        sb.AppendLine("function inlineStress(fn) {");
        sb.AppendLine("  for (var i = 0; i < 100; i++) { fn(i); }");
        sb.AppendLine("  return fn(0);");
        sb.AppendLine("}");

        for (var i = 0; i < depth; i++)
        {
            sb.AppendLine($"var f{i} = {MakeLambda()};");
            sb.AppendLine($"f{i}({RValue()});");
        }

        sb.AppendLine("var g = (a, b, c, d) => a + b * c / d;");
        sb.AppendLine("for (var i = 0; i < 100000; i++) {");
        sb.AppendLine("  g(1, 2, 3, 4);");
        sb.AppendLine("  g(1.5, 2.5, 3.5, 4.5);");
        sb.AppendLine("}");

        return sb.ToString();
    }

    private string GenerateIteratorFuzz()
    {
        var sb = new StringBuilder();
        sb.AppendLine("'use strict';");

        sb.AppendLine("function* gen0() { yield 1; yield 2; yield 3; yield* [4, 5]; }");
        sb.AppendLine("function* gen1(a, b) { var x = yield a; var y = yield b; yield x + y; }");
        sb.AppendLine("function* gen2() { while(true) { yield 1; } }");

        var count = _rng.Next(10, 50);
        for (var i = 0; i < count; i++)
        {
            var action = _rng.Next(8);
            switch (action)
            {
                case 0:
                    sb.AppendLine($"var it{i} = gen0(); it{i}.next(); it{i}.next({RValue()}); it{i}.throw(new Error({RStr()}));");
                    break;
                case 1:
                    sb.AppendLine($"var it{i} = gen1({RValue()}, {RValue()}); it{i}.next(); it{i}.next({RValue()});");
                    break;
                case 2:
                    sb.AppendLine($"var it{i} = gen2(); it{i}.next(); it{i}.return({RValue()});");
                    break;
                case 3:
                    sb.AppendLine($"for (var v{i} of gen0()) {{ if ({RValue()}) break; }}");
                    break;
                case 4:
                    sb.AppendLine($"var iter{i} = [1, 2, 3][Symbol.iterator](); iter{i}.next(); Array.from(iter{i});");
                    break;
                case 5:
                    sb.AppendLine($"var map{i} = new Map([[1, 2]]); var mit{i} = map{i}[Symbol.iterator](); mit{i}.next();");
                    break;
                case 6:
                    sb.AppendLine($"var g{i} = (function*() {{ for(;;) {{ var x = yield {RValue()}; }} }})(); g{i}.next();");
                    break;
                case 7:
                    sb.AppendLine($"var arr{i} = [1, 2, 3]; try {{ arr{i}[Symbol.iterator] = null; for (var x{i} of arr{i}) {{}} }} catch(e) {{}}");
                    break;
            }
        }

        return sb.ToString();
    }

    private string GenerateExceptionFuzz()
    {
        var sb = new StringBuilder();
        sb.AppendLine("'use strict';");

        var count = _rng.Next(20, 100);
        sb.AppendLine("function thrower() { throw new Error('deep'); }");
        sb.AppendLine("function wrapper() { return thrower(); }");
        sb.AppendLine("function wrapper2() { return wrapper(); }");

        for (var i = 0; i < count; i++)
        {
            var kind = _rng.Next(10);
            switch (kind)
            {
                case 0:
                    sb.AppendLine($"try {{ wrapper2(); }} catch(e) {{ e.message; e.stack; e.name; }}");
                    break;
                case 1:
                    sb.AppendLine($"try {{ {RValue()}.{RMethod()}(); }} catch(e) {{ e.name; }}");
                    break;
                case 2:
                    sb.AppendLine($"try {{ eval({RStr()}); }} catch(e) {{ e.name; }}");
                    break;
                case 3:
                    sb.AppendLine($"try {{ JSON.parse({RStr()}); }} catch(e) {{ e.message; }}");
                    break;
                case 4:
                    sb.AppendLine($"try {{ throw {RValue()}; }} catch(e) {{ ({RExpr()}) === e; }}");
                    break;
                case 5:
                    sb.AppendLine($"try {{ throw new Error({RStr()}, {{ cause: new TypeError({RStr()}) }}); }} catch(e) {{ e.cause; e.message; }}");
                    break;
                case 6:
                    sb.AppendLine($"try {{ throw new AggregateError([new Error('a'), new Error('b')], 'agg'); }} catch(e) {{ e.errors.length; e.message; }}");
                    break;
                case 7:
                    sb.AppendLine($"try {{ Symbol({RValue()}); }} catch(e) {{ e.name; }}");
                    break;
                case 8:
                    sb.AppendLine($"try {{ (new Proxy({{}}, {{get: () => {{ throw new TypeError('trap'); }}}})).x; }} catch(e) {{ e.name; }}");
                    break;
                case 9:
                    sb.AppendLine($"try {{ null(); }} catch(e) {{ e.name; e.message; e.stack; e.toString(); }}");
                    break;
            }
        }

        return sb.ToString();
    }

    private string GenerateAtomicsFuzz()
    {
        if (_rng.Next(3) == 0)
            return GenerateGcCompactionAtomicsTypedArrays();

        if (_rng.Next(3) == 0)
            return GenerateWasmSharedAtomicsFuzz();

        var sb = new StringBuilder();
        sb.AppendLine("'use strict';");

        sb.AppendLine("var sab = new SharedArrayBuffer(4096);");
        sb.AppendLine("var i32 = new Int32Array(sab);");
        sb.AppendLine("var u8 = new Uint8Array(sab);");

        var count = _rng.Next(20, 100);
        for (var i = 0; i < count; i++)
        {
            var idx = _rng.Next(0, 1000);
            var action = _rng.Next(10);
            switch (action)
            {
                case 0: sb.AppendLine($"Atomics.add(i32, {idx}, {RNum()});"); break;
                case 1: sb.AppendLine($"Atomics.sub(i32, {idx}, {RNum()});"); break;
                case 2: sb.AppendLine($"Atomics.and(i32, {idx}, {RNum()});"); break;
                case 3: sb.AppendLine($"Atomics.or(i32, {idx}, {RNum()});"); break;
                case 4: sb.AppendLine($"Atomics.xor(i32, {idx}, {RNum()});"); break;
                case 5: sb.AppendLine($"Atomics.exchange(i32, {idx}, {RNum()});"); break;
                case 6: sb.AppendLine($"Atomics.compareExchange(i32, {idx}, {RNum()}, {RNum()});"); break;
                case 7: sb.AppendLine($"Atomics.load(i32, {idx});"); break;
                case 8: sb.AppendLine($"Atomics.store(i32, {idx}, {RNum()});"); break;
                case 9: sb.AppendLine($"try {{ Atomics.add(u8, {idx}, 300); }} catch(e) {{}}"); break;
            }
        }

        sb.AppendLine("var valid = Atomics.isLockFree(1);");
        sb.AppendLine("var valid2 = Atomics.isLockFree(8);");
        sb.AppendLine($"try {{ Atomics.wait(i32, 0, {RNum()}, 1); }} catch(e) {{}}");

        return sb.ToString();
    }

    private string GenerateWasmSharedAtomicsFuzz()
    {
        var sb = new StringBuilder("'use strict';\n");
        sb.AppendLine("var sab = new SharedArrayBuffer(65536); var shared = new Int32Array(sab); var expected = 0;");
        sb.AppendLine("for (var i = 0; i < 32; i++) { Atomics.store(shared, i, 0); }");
        sb.AppendLine("function agent(rounds, lane) { var local = 0; for (var j = 0; j < rounds; j++) { Atomics.add(shared, lane, 1); Atomics.or(shared, lane + 1, 1 << (j & 7)); local++; if ((j & 15) === 0) Atomics.compareExchange(shared, lane + 2, j - 1, j); } return local; }");
        sb.AppendLine("for (var round = 0; round < 8; round++) { expected += agent(64, (round & 1) * 4); agent(32, ((round + 1) & 1) * 4); }");
        sb.AppendLine("if (Atomics.load(shared, 0) < 256 || Atomics.load(shared, 4) < 256) throw new Error('atomics oracle');");
        sb.AppendLine("if (typeof wasmTextToBinary === 'function') {");
        sb.AppendLine("  try { var wat = '(module (memory (import \"js\" \"mem\") 1 2 shared) (func (export \"inc\") (param i32) (result i32) (i32.atomic.rmw.add offset=0 align=4 (local.get 0) (i32.const 1))) (func (export \"load\") (param i32) (result i32) (i32.atomic.load offset=0 align=4 (local.get 0))))';");
        sb.AppendLine("    var wasmMemory = new WebAssembly.Memory({initial:1, maximum:2, shared:true}); var wasm = new WebAssembly.Instance(new WebAssembly.Module(wasmTextToBinary(wat)), {js:{mem:wasmMemory}}); var wi = new Int32Array(wasmMemory.buffer); Atomics.store(wi, 0, 0);");
        sb.AppendLine("    for (var k = 0; k < 256; k++) { wasm.exports.inc(0); if ((k & 31) === 0) Atomics.add(wi, 1, 1); } if (wasm.exports.load(0) !== 256) throw new Error('wasm atomic oracle');");
        sb.AppendLine("  } catch (e) { if (!(e instanceof WebAssembly.CompileError || e instanceof TypeError || e instanceof RangeError || e instanceof SyntaxError)) throw e; }");
        sb.AppendLine("}");
        sb.AppendLine("if (typeof Worker === 'function') { try { var source = 'onmessage = function(e) { var a = new Int32Array(e.data); for (var n = 0; n < 128; n++) Atomics.add(a, 8, 1); };'; var workers = [new Worker(source), new Worker(source)]; for (var w = 0; w < workers.length; w++) workers[w].postMessage(sab); var until = Date.now() + 1000; while (Atomics.load(shared, 8) < 256 && Date.now() < until) {} for (var z = 0; z < workers.length; z++) workers[z].terminate(); } catch (e) { if (!(e instanceof TypeError || e instanceof ReferenceError || e.name === 'NotSupportedError')) throw e; } }");
        return sb.ToString();
    }

    private string GenerateGcCompactionAtomicsTypedArrays()
    {
        var sb = new StringBuilder("'use strict';\n");
        sb.AppendLine("var sab = new SharedArrayBuffer(4096); var atoms = new Int32Array(sab); var bytes = new Uint8Array(sab); var roots = []; var checksum = 0;");
        sb.AppendLine("if (typeof gczeal === 'function') { try { gczeal(14, 1); } catch (e) {} }");
        sb.AppendLine("if (typeof gcparam === 'function') { try { gcparam('compacting', 1); } catch (e) {} }");
        sb.AppendLine("function churn(round) { var garbage = []; for (var i = 0; i < 96; i++) { var o = {round: round, index: i, payload: new Array((i & 7) + 1).fill(round + i)}; garbage.push(o); if ((i & 7) === 0) roots.push(o); } for (var j = 0; j < 48; j++) { Atomics.add(atoms, j & 31, 1); bytes[(round + j) & 4095] = (round + j) & 255; var view = new Uint16Array(sab, ((j & 31) << 1), 8); view.fill(round + j); checksum = (checksum + Atomics.load(atoms, j & 31) + view[0]) | 0; } return garbage.length; }");
        sb.AppendLine("for (var round = 0; round < 40; round++) { churn(round); if ((round & 3) === 0 && typeof gc === 'function') { try { gc(); } catch (e) {} } if ((round & 7) === 0 && typeof gcslice === 'function') { try { gcslice(16); } catch (e) {} } if ((round & 15) === 0 && typeof minorgc === 'function') { try { minorgc(); } catch (e) {} } }");
        sb.AppendLine("if (roots.length < 40 || Atomics.load(atoms, 0) === 0 || bytes[0] !== 0) throw new Error('gc compaction oracle');");
        sb.AppendLine("roots = roots.slice(-8); if (typeof gc === 'function') { try { gc(); } catch (e) {} } if (roots[0] === undefined) throw new Error('root lost');");
        sb.AppendLine("if (typeof structuredClone === 'function') { var buffer = new ArrayBuffer(128); var ta = new Uint8Array(buffer); ta[0] = 7; try { structuredClone(buffer, {transfer: [buffer]}); ta.slice(0, 1); } catch (e) { if (!(e instanceof TypeError)) throw e; } }");
        return sb.ToString();
    }

    private string GenerateMapSetFuzz()
    {
        var sb = new StringBuilder();
        sb.AppendLine("'use strict';");

        var count = _rng.Next(20, 100);
        var keys = new[] { "1", "'a'", "{obj: 1}", "NaN", "1.5", "-0", "Symbol('s')", "[1, 2]", "new Map()" };
        sb.AppendLine("var keys = [" + string.Join(", ", keys) + "];");
        sb.AppendLine("var m = new Map();");
        sb.AppendLine("var s = new Set();");
        sb.AppendLine("var wm = new WeakMap();");
        sb.AppendLine("var ws = new WeakSet();");

        for (var i = 0; i < count; i++)
        {
            var action = _rng.Next(12);
            var ki = _rng.Next(keys.Length);
            switch (action)
            {
                case 0: sb.AppendLine($"m.set(keys[{ki}], {RValue()});"); break;
                case 1: sb.AppendLine($"m.get(keys[{ki}]);"); break;
                case 2: sb.AppendLine($"m.has(keys[{ki}]);"); break;
                case 3: sb.AppendLine($"s.add(keys[{ki}]);"); break;
                case 4: sb.AppendLine($"s.has(keys[{ki}]);"); break;
                case 5: sb.AppendLine($"s.delete(keys[{ki}]);"); break;
                case 6: sb.AppendLine($"m.delete(keys[{ki}]);"); break;
                case 7: sb.AppendLine($"wm.set({{}}, keys[{ki}]);"); break;
                case 8: sb.AppendLine($"ws.add({{}});"); break;
                case 9: sb.AppendLine($"m.clear();"); break;
                case 10: sb.AppendLine($"s.forEach(v => {{ if ({RValue()}) m.set(v, {RValue()}); }});"); break;
                case 11: sb.AppendLine($"try {{ wm.set(keys[{ki}], 1); }} catch(e) {{}}"); break;
            }
        }

        sb.AppendLine($"var iter = m.entries(); iter.next(); iter.return();");
        sb.AppendLine($"var keysArr = Array.from(m.keys());");
        sb.AppendLine($"var valsArr = Array.from(s.values());");
        sb.AppendLine($"var e = m.keys().next(); e.done; e.value;");

        return sb.ToString();
    }

    private string GenerateArrayMethodFuzz()
    {
        var sb = new StringBuilder();
        sb.AppendLine("'use strict';");

        var count = _rng.Next(20, 80);
        for (var i = 0; i < count; i++)
        {
            var action = _rng.Next(14);
            var len = _rng.Next(0, 50);
            var idx = _rng.Next(-5, 55);
            switch (action)
            {
                case 0: sb.AppendLine($"Array.from({{length: {len}}}, () => {RValue()});"); break;
                case 1: sb.AppendLine($"Array.of(...[{string.Join(", ", Enumerable.Range(0, _rng.Next(0, 10)).Select(_ => RValue()))}]);"); break;
                case 2: sb.AppendLine($"new Array({len}).fill({RValue()}, {idx});"); break;
                case 3: sb.AppendLine($"new Array({len}).sort();"); break;
                case 4: sb.AppendLine($"Array.from(new Array({len}), (_, i) => i).reverse();"); break;
                case 5: sb.AppendLine($"var a = [1, 2, 3]; a.splice({idx}, {_rng.Next(0, 5)}, {RValue()});"); break;
                case 6: sb.AppendLine($"var a = [1, 2, 3]; a.copyWithin({idx}, {idx});"); break;
                case 7: sb.AppendLine($"[1, 2, 3].flat({_rng.Next(0, 10)});"); break;
                case 8: sb.AppendLine($"[1, 2, 3].flatMap(v => [v, {RValue()}]);"); break;
                case 9: sb.AppendLine($"var a = new Array({len}); a[0] = 1; a.at({idx});"); break;
                case 10: sb.AppendLine($"[[1, 2], [3, 4]].flat();"); break;
                case 11: sb.AppendLine($"Array.from({{length: {len}}});"); break;
                case 12: sb.AppendLine($"[{RValue()}, {RValue()}, {RValue()}].indexOf({RValue()});"); break;
                case 13: sb.AppendLine($"Array.from(new Set([{string.Join(", ", Enumerable.Range(0, _rng.Next(1, 10)).Select(_ => RValue()))}]));"); break;
            }
        }

        return sb.ToString();
    }

    private string GenerateErrorChainFuzz()
    {
        var sb = new StringBuilder();
        sb.AppendLine("'use strict';");
        var errors = new[] { "Error", "TypeError", "RangeError", "SyntaxError", "ReferenceError", "URIError", "EvalError" };
        sb.AppendLine("var errors = [" + string.Join(", ", errors) + "];");

        var count = _rng.Next(20, 80);
        for (var i = 0; i < count; i++)
        {
            var idx = _rng.Next(errors.Length);
            var action = _rng.Next(8);
            switch (action)
            {
                case 0: sb.AppendLine($"try {{ throw new errors[{idx}]({RStr()}); }} catch(e) {{ e.name; e.message; e.stack; }}"); break;
                case 1: sb.AppendLine($"errors[{idx}]({RStr()});"); break;
                case 2: sb.AppendLine($"errors[{idx}].call(null, {RStr()});"); break;
                case 3: sb.AppendLine($"errors[{idx}].apply(null, [{RStr()}]);"); break;
                case 4: sb.AppendLine($"var err = new errors[{idx}]({RStr()}); err.cause = {RValue()};"); break;
                case 5: sb.AppendLine($"try {{ throw new errors[{idx}]({RStr()}, {{ cause: new errors[{idx}]({RStr()}) }}); }} catch(e) {{ e.cause; }}"); break;
                case 6: sb.AppendLine($"try {{ throw errors[{idx}]({RStr()}); }} catch(e) {{}}"); break;
                case 7: sb.AppendLine($"var er = new errors[{idx}](); for (var k in er) {{ er[k]; }}"); break;
            }
        }

        return sb.ToString();
    }

    private string GenerateSymbolPropertyFuzz()
    {
        var sb = new StringBuilder();
        sb.AppendLine("'use strict';");

        var count = _rng.Next(20, 80);
        sb.AppendLine("var syms = [Symbol(), Symbol('k'), Symbol.iterator, Symbol.toPrimitive, Symbol.toStringTag, Symbol.hasInstance, Symbol.isConcatSpreadable, Symbol.match, Symbol.replace, Symbol.search, Symbol.split, Symbol.species, Symbol.species];");

        for (var i = 0; i < count; i++)
        {
            var si = _rng.Next(12);
            var action = _rng.Next(10);
            switch (action)
            {
                case 0: sb.AppendLine($"var o{i} = {{ [syms[{si}]]: {RValue()} }};"); break;
                case 1: sb.AppendLine($"var o{i} = {{}}; o{i}[syms[{si}]] = {RValue()};"); break;
                case 2: sb.AppendLine($"var o{i} = new Proxy({{}}, {{get: (t, k) => k === syms[{si}] ? {RValue()} : undefined}});"); break;
                case 3: sb.AppendLine($"var o{i} = {{ [syms[{si}]]: function() {{}} }};"); break;
                case 4: sb.AppendLine($"Object.getOwnPropertySymbols({{ [syms[{si}]]: 1 }});"); break;
                case 5: sb.AppendLine($"var o{i} = {{}}; Object.defineProperty(o{i}, syms[{si}], {{value: {RValue()}, writable: {RValue()}}});"); break;
                case 6: sb.AppendLine($"var o{i} = {{ [syms[{si}]]: [1, 2, 3] }}; o{i}[syms[{si}]].map(v => v);"); break;
                case 7: sb.AppendLine($"var o{i} = Symbol.for('x'); Symbol.keyFor(o{i});"); break;
                case 8: sb.AppendLine($"var o{i} = {{ [Symbol.toPrimitive]() {{ return {RValue()}; }} }}; '' + o{i};"); break;
                case 9: sb.AppendLine($"var o{i} = {{ [syms[{si}]]: function*() {{ yield 1; }} }}; o{i}[syms[{si}]]().next();"); break;
            }
        }

        return sb.ToString();
    }

    private string GenerateGetterSetterFuzz()
    {
        var sb = new StringBuilder();
        sb.AppendLine("'use strict';");

        var count = _rng.Next(20, 80);
        for (var i = 0; i < count; i++)
        {
            var action = _rng.Next(8);
            switch (action)
            {
                case 0: sb.AppendLine($"var ob{i} = {{ get x() {{ return {RValue()}; }}, set x(v) {{ throw new Error({RStr()}); }} }}; ob{i}.x;"); break;
                case 1: sb.AppendLine($"var ob{i} = {{ get x() {{ return this._x; }}, set x(v) {{ this._x = v * {RNum()}; }} }}; ob{i}.x = {RValue()}; ob{i}.x;"); break;
                case 2: sb.AppendLine($"Object.defineProperty({{}}, 'k', {{get: () => {RValue()}, configurable: true}});"); break;
                case 3: sb.AppendLine($"var ob{i} = {{}}; Object.defineProperty(ob{i}, 'k', {{get: undefined, set: (v) => {{ print(v); }}, configurable: true}});"); break;
                case 4: sb.AppendLine($"try {{ Object.defineProperty({{}}, 'k', {{get: () => 1, writable: true}}); }} catch(e) {{}}"); break;
                case 5: sb.AppendLine($"var ob{i} = {{ get k() {{ return this._k; }} }}; Object.defineProperty(ob{i}, 'k', {{get: () => {RValue()}}});"); break;
                case 6: sb.AppendLine("var ob" + i + " = { set x(v) {} }; delete ob" + i + ".x;"); break;
                case 7: sb.AppendLine($"var ob{i} = new Proxy({{}}, {{get: (t, k, r) => {RValue()}}}); ob{i}.anything;"); break;
            }
        }

        return sb.ToString();
    }

    private string GenerateArgumentConfusion()
    {
        var sb = new StringBuilder();
        sb.AppendLine("'use strict';");

        sb.AppendLine("function multi(cb, n, s, obj) {");
        sb.AppendLine("  cb(n);");
        sb.AppendLine("  s += n;");
        sb.AppendLine("  obj.n = n;");
        sb.AppendLine("}");

        var prototypes = new[]
        {
            "function(){}",
            "null",
            "undefined",
            "(x) => x * 2",
            "async function(){}",
            "function* (){ yield 1 }",
            "new Proxy(function(){}, {})",
        };

        var count = _rng.Next(20, 80);
        for (var i = 0; i < count; i++)
        {
            var cb = prototypes[_rng.Next(prototypes.Length)];
            var n = _rng.Next(2) == 0 ? RNum() : $"\"{_rng.Next(10)}\"";
            var s = _rng.Next(2) == 0 ? RStr() : RNum();
            var obj = _rng.Next(2) == 0 ? "{}" : "{n: 0}";

            sb.AppendLine($"try {{ multi({cb}, {n}, {s}, {obj}); }} catch(e) {{}}");
            sb.AppendLine($"try {{ multi({cb}, {n}, {s}, {obj}, {RValue()}, {RValue()}, {RValue()}); }} catch(e) {{}}");
        }

        sb.AppendLine("function swapArgs(a, b) { return a / b; }");
        sb.AppendLine("for (var i = 0; i < 1000; i++) {");
        sb.AppendLine("  swapArgs(1, 2);");
        sb.AppendLine("  swapArgs(2, 1);");
        sb.AppendLine("  swapArgs(\"3\", 0);");
        sb.AppendLine("  swapArgs(null, undefined);");
        sb.AppendLine("}");

        return sb.ToString();
    }

    private string GenerateEvalFuzz()
    {
        var sb = new StringBuilder();
        sb.AppendLine("'use strict';");

        var expressions = new[]
        {
            "'use strict'; var x = 1;",
            "function f(){ return 42; }",
            "var arr = new Array(10);",
            "let obj = { a: 1 };",
            "class C { constructor() {} }",
            "var s = 'string';",
            "var r = /regex/;",
            "var sym = Symbol();",
            "for (var i = 0; i < 10; i++) {}",
            "try { throw new Error('e'); } catch (e) {}",
            "var p = new Promise((res) => res(1));",
            "function* gen(){ yield 1; }",
            "async function af(){ return 1; }",
            "var [a, ...b] = [1, 2, 3];",
            "var {x, y} = {x: 1, y: 2};",
            "new Map([[1, 2]]);",
            "Object.create(null);",
            "Symbol.for('x');",
        };

        var count = _rng.Next(20, 100);
        for (var i = 0; i < count; i++)
        {
            var action = _rng.Next(6);
            switch (action)
            {
                case 0:
                    sb.AppendLine($"try {{ eval({RStr()}); }} catch(e) {{}}");
                    break;
                case 1:
                    sb.AppendLine("try { (0, eval)(" + RStr() + "); } catch(e) {}");
                    break;
                case 2:
                    sb.AppendLine($"try {{ eval({RValue()}); }} catch(e) {{}}");
                    break;
                case 3:
                    sb.AppendLine($"try {{ Function({RStr()})(); }} catch(e) {{}}");
                    break;
                case 4:
                    sb.AppendLine($"try {{ new Function('return ' + {RStr()})(); }} catch(e) {{}}");
                    break;
                case 5:
                    sb.AppendLine($"var code{i} = {RStr()}; try {{ eval(code{i}); }} catch(e) {{ {RVar()} = e; }}");
                    break;
            }
        }

        return sb.ToString();
    }

    private string GenerateScopeChaos()
    {
        var sb = new StringBuilder();
        sb.AppendLine("'use strict';");

        sb.AppendLine("var globalVar = 42;");
        sb.AppendLine("let blockLet = 43;");
        sb.AppendLine("const blockConst = 44;");
        sb.AppendLine("function outerFn() { var innerVar = 45; let innerLet = 46; const innerConst = 47; ");
        sb.AppendLine("  function innerFn() { return innerVar + innerLet + innerConst; }");
        sb.AppendLine("  return innerFn;");
        sb.AppendLine("}");

        var count = _rng.Next(20, 80);
        for (var i = 0; i < count; i++)
        {
            var action = _rng.Next(10);
            switch (action)
            {
                case 0: sb.AppendLine($"var v{i} = outerFn()();"); break;
                case 1: sb.AppendLine($"if (true) {{ let shadow{i} = {RValue()}; print(shadow{i}); }}"); break;
                case 2: sb.AppendLine($"try {{ {RVar()} = globalVar + {RValue()}; }} catch(e) {{}}"); break;
                case 3: sb.AppendLine($"for (let j{i} = 0; j{i} < 3; j{i}++) {{ print(j{i}); }}"); break;
                case 4: sb.AppendLine($"var f{i} = () => {{ return {RValue()}; }}; f{i}();"); break;
                case 5: sb.AppendLine($"try {{ let {RVar()} = {RValue()}; print({RVar()}); }} catch(e) {{}}"); break;
                case 6: sb.AppendLine($"try {{ (new Function('obj', 'with (obj) {{ return a; }}'))({{a: {RValue()}}}); }} catch(e) {{}}"); break;
                case 7: sb.AppendLine($"var $var{i} = {RValue()};"); break;
                case 8: sb.AppendLine($"try {{ const c{i} = {RValue()}; }} catch(e) {{}}"); break;
                case 9: sb.AppendLine($"var arr{i} = [1, 2]; var [a{i}, b{i}] = arr{i};"); break;
            }
        }

        return sb.ToString();
    }

    private string GenerateBigIntFuzz()
    {
        var sb = new StringBuilder();
        sb.AppendLine("'use strict';");

        var bigInts = new[]
        {
            "0n", "1n", "-1n", "2n**63n", "-(2n**63n)", "2n**64n",
            "2n**127n", "-(2n**127n)", "2n**1024n",
            "123456789n", "-123456789n",
            "0xffffffffffffffffn",
            "9007199254740993n",
            "9223372036854775807n",
            "-9223372036854775808n",
        };

        var count = _rng.Next(20, 100);
        for (var i = 0; i < count; i++)
        {
            var bi1 = bigInts[_rng.Next(bigInts.Length)];
            var bi2 = bigInts[_rng.Next(bigInts.Length)];
            var action = _rng.Next(12);
            switch (action)
            {
                case 0: sb.AppendLine($"{bi1} + {bi2};"); break;
                case 1: sb.AppendLine($"{bi1} - {bi2};"); break;
                case 2: sb.AppendLine($"{bi1} * {bi2};"); break;
                case 3: sb.AppendLine($"try {{ {bi1} / {bi2}; }} catch(e) {{}}"); break;
                case 4: sb.AppendLine($"{bi1} % {bi2};"); break;
                case 5: sb.AppendLine($"{bi1} ** {bigInts[0]};"); break;
                case 6: sb.AppendLine($"try {{ {bi1} + {RNum()}; }} catch(e) {{}}"); break;
                case 7: sb.AppendLine($"BigInt({RNum()});"); break;
                case 8: sb.AppendLine($"try {{ BigInt({RValue()}); }} catch(e) {{}}"); break;
                case 9: sb.AppendLine($"{bi1}.toString({_rng.Next(2, 37)});"); break;
                case 10: sb.AppendLine($"Number({bi1});"); break;
                case 11: sb.AppendLine($"try {{ {bi1} << {RNum()}; }} catch(e) {{}}"); break;
            }
        }

        return sb.ToString();
    }

    private string GenerateJitTypeChange()
    {
        var sb = new StringBuilder();
        sb.AppendLine("'use strict';");

        sb.AppendLine("function typeFlip(a, b) { return a + b; }");

        sb.AppendLine("for (var i = 0; i < 1000; i++) { typeFlip(1, 2); }");
        sb.AppendLine("typeFlip('a', 'b');");
        sb.AppendLine("typeFlip(1.5, 2.5);");
        sb.AppendLine("typeFlip({}, {});");
        sb.AppendLine("typeFlip([], []);");
        sb.AppendLine("typeFlip(null, null);");
        sb.AppendLine("typeFlip(undefined, undefined);");
        sb.AppendLine("typeFlip(1n, 2n);");
        sb.AppendLine("for (var i = 0; i < 1000; i++) { typeFlip(i, i); }");

        sb.AppendLine("function typeSwap(a) { return a * 2; }");
        sb.AppendLine("for (var i = 0; i < 1000; i++) { typeSwap(1); }");
        sb.AppendLine("typeSwap(1.5);");
        sb.AppendLine("typeSwap('2');");
        sb.AppendLine("typeSwap(null);");
        sb.AppendLine("typeSwap(new Number(3));");

        return sb.ToString();
    }

    private string GenerateArrayBuffersCorruption()
    {
        var sb = new StringBuilder();
        sb.AppendLine("'use strict';");

        var count = _rng.Next(20, 80);
        for (var i = 0; i < count; i++)
        {
            var type = _rng.Next(14);
            var size = _rng.Next(0, 65536);
            switch (type)
            {
                case 0: sb.AppendLine($"var ab{i} = new ArrayBuffer({size});"); break;
                case 1: sb.AppendLine($"var ab{i} = new ArrayBuffer({size}, {{maxByteLength: {size * 2}}});"); break;
                case 2: sb.AppendLine($"var ta{i} = new Uint8Array({size});"); break;
                case 3: sb.AppendLine($"var ta{i} = new Float64Array({size});"); break;
                case 4: sb.AppendLine($"var dv{i} = new DataView(new ArrayBuffer({size}));"); break;
                case 5: sb.AppendLine($"try {{ new ArrayBuffer(-1); }} catch(e) {{}}"); break;
                case 6: sb.AppendLine($"try {{ new SharedArrayBuffer(-1); }} catch(e) {{}}"); break;
                case 7: sb.AppendLine($"var ta{i} = new Uint8Array({size}); ta{i}.buffer;"); break;
                case 8: sb.AppendLine($"var ab_r{i} = new ArrayBuffer({size}, {{maxByteLength: {size * 2 + 1}}}); try {{ ab_r{i}.resize({size * 2}); }} catch(e) {{}}"); break;
                case 9: sb.AppendLine($"var ab_d{i} = new ArrayBuffer({size}); try {{ if (typeof detachArrayBuffer === 'function') detachArrayBuffer(ab_d{i}); else ab_d{i}.transfer?.(); }} catch(e) {{}}"); break;
                case 10: sb.AppendLine($"var dv{i} = new DataView(new ArrayBuffer({size})); try {{ dv{i}.setUint32({_rng.Next(0, size)}, 0xFFFFFFFF); }} catch(e) {{}}"); break;
                case 11: sb.AppendLine($"var sab{i} = new SharedArrayBuffer({size}); var ta{i} = new Int32Array(sab{i});"); break;
                case 12: sb.AppendLine($"var ab{i} = new ArrayBuffer({size}); var ta{i} = new Uint8Array(ab{i}); ta{i}[{_rng.Next(0, size)}] = {RNum()};"); break;
                case 13: sb.AppendLine($"var ab{i} = new ArrayBuffer({size}, {{maxByteLength: {size * 2}}}); try {{ ab{i}.resize({size * 3}); }} catch(e) {{}}"); break;
            }
        }

        sb.AppendLine("var big = new Uint8Array(new ArrayBuffer(1024));");
        sb.AppendLine("big.set(new Uint8Array(1024), 0);");
        sb.AppendLine("try { big.set(new Uint8Array(2048), 1024); } catch(e) {}");
        sb.AppendLine("try { big.set(new Uint8Array(10), -1); } catch(e) {}");

        return sb.ToString();
    }

    // Targeted 2025-2026 regression families: bounded, semantic-only inputs.
    private string GenerateIonBailoutStress()
    {
        var sb = new StringBuilder("'use strict';\n");
        sb.AppendLine("function recover(o, n) { var x = o.value + n; if (o.flag) x += 1; return x; }");
        sb.AppendLine("var o = {value: 1, flag: false};");
        sb.AppendLine("for (var i = 0; i < 1200; i++) recover(o, i);");
        sb.AppendLine("o.flag = true; o.value = '2';");
        sb.AppendLine("var result = recover(o, 3);");
        sb.AppendLine("if (typeof result !== 'string' && typeof result !== 'number') throw new Error('bailout');");
        sb.AppendLine("o.value = { valueOf() { return 4; } }; recover(o, 1);");
        return sb.ToString();
    }

    private string GenerateCacheIrShapeChurn()
    {
        var sb = new StringBuilder("'use strict';\n");
        sb.AppendLine("function read(o) { return (o.x === undefined ? 0 : o.x) + (o.y === undefined ? 0 : o.y); }");
        sb.AppendLine("var a = {x: 1, y: 2}, b = {y: 3, x: 4}, c = Object.create({x: 5});");
        sb.AppendLine("for (var i = 0; i < 1500; i++) read(i % 3 === 0 ? a : i % 3 === 1 ? b : c);");
        sb.AppendLine("Object.defineProperty(a, 'x', {get() { return 9; }, configurable: true});");
        sb.AppendLine("delete b.y; b.z = 7; Object.setPrototypeOf(c, {y: 8});");
        sb.AppendLine("read(a); read(b); read(c);");
        return sb.ToString();
    }

    private string GenerateGcRealmWeakMap()
    {
        var sb = new StringBuilder("'use strict';\n");
        sb.AppendLine("var wm = new WeakMap(), keep = [], registry = typeof FinalizationRegistry === 'function' ? new FinalizationRegistry(function(){}) : null;");
        sb.AppendLine("for (var i = 0; i < 80; i++) { var key = {i: i}, value = {ref: key}; wm.set(key, value); if ((i & 7) === 0) { keep.push(key); if (registry) registry.register(key, i); } }");
        sb.AppendLine("for (var j = 0; j < keep.length; j++) if (!wm.has(keep[j])) throw new Error('weakmap');");
        sb.AppendLine("if (typeof newGlobal === 'function') { var g = newGlobal(); var cross = {x: 1}; g.x = cross; if (g.x.x !== 1) throw new Error('realm'); }");
        return sb.ToString();
    }

    private string GenerateUnicodeRegExpV()
    {
        var sb = new StringBuilder("'use strict';\n");
        sb.AppendLine("var samples = ['\\u{391}', '\\u{3B1}', '\\u{10400}', '\\u{1F600}', '\\u0000'];");
        sb.AppendLine("var patterns = ['\\\\p{Script=Greek}', '\\\\p{Letter}', '[a-z]'];");
        sb.AppendLine("for (var i = 0; i < patterns.length; i++) { try { var r = new RegExp(patterns[i], i === 2 ? 'u' : 'uv'); for (var j = 0; j < samples.length; j++) r.test(samples[j]); } catch (e) { if (!(e instanceof SyntaxError)) throw e; } }");
        sb.AppendLine("try { new RegExp('\\\\p', 'v'); } catch (e) { if (!(e instanceof SyntaxError)) throw e; }");
        sb.AppendLine("var look = new RegExp('(?<=(?:a{1,4}){1,4})b'); look.test('aaaab');");
        return sb.ToString();
    }

    private string GenerateModuleGraph()
    {
        var sb = new StringBuilder("'use strict';\n");
        sb.AppendLine("var sources = ['export const x = 1;', 'export {x as y};', 'import {x} from \\\"a\\\"; export const z = x + 1;'];");
        sb.AppendLine("for (var i = 0; i < sources.length; i++) { try { if (typeof parseModule === 'function') parseModule(sources[i]); else new Function(sources[i].replace(/import[^;]+;|export /g, '')); } catch (e) { if (!(e instanceof SyntaxError)) throw e; } }");
        // __sf_fail (not throw): a bare throw inside .then() only becomes an
        // unhandled rejection reported at process exit, misattributed to
        // whatever unrelated input happens to be running by then - see
        // PersistentRunner.WriteDriver for the full explanation.
        sb.AppendLine("async function leaf() { return await Promise.resolve(7); } leaf().then(function(v) { if (v !== 7 && typeof __sf_fail === 'function') __sf_fail('module'); });");
        return sb.ToString();
    }

    private string GenerateWasmBoundaryOracle()
    {
        if (_rng.Next(2) == 0)
            return GenerateWasmJsIntegration();

        var sb = new StringBuilder("'use strict';\n");
        sb.AppendLine("var bytes = new Uint8Array([0,97,115,109,1,0,0,0,1,4,1,96,0,1,127,3,2,1,0,7,7,1,3,102,111,111,0,0,10,6,1,4,0,65,0,11]);");
        sb.AppendLine("try { var m = new WebAssembly.Module(bytes); var f = new WebAssembly.Instance(m).exports.foo; for (var i = -2; i <= 2; i++) if (f() !== 0) throw new Error('wasm'); } catch (e) { if (!(e instanceof WebAssembly.CompileError)) throw e; }");
        sb.AppendLine("try { WebAssembly.validate(bytes); } catch (e) { if (!(e instanceof WebAssembly.CompileError)) throw e; }");
        return sb.ToString();
    }

    private string GenerateWasmJsIntegration()
    {
        var sb = new StringBuilder("'use strict';\n");
        sb.AppendLine("if (typeof wasmTextToBinary === 'function') {");
        sb.AppendLine("  var wat = '(module (import \"js\" \"mem\" (memory 1 2)) (import \"js\" \"get\" (func $get (param i32) (result i32))) (func (export \"load\") (param i32) (result i32) (i32.load (local.get 0))) (func (export \"store\") (param i32 i32) (i32.store (local.get 0) (local.get 1))) (func (export \"call\") (param i32) (result i32) (call $get (local.get 0))))';");
        sb.AppendLine("  var memory = new WebAssembly.Memory({initial:1, maximum:2});");
        sb.AppendLine("  var state = {memory: memory, bias: 7, get: function(x) { return (x + this.bias) | 0; }};");
        sb.AppendLine("  var imports = new Proxy({mem: memory, get: function(x) { return state.get.call(state, x); }}, {get: function(t,p,r) { return Reflect.get(t,p,r); }});");
        sb.AppendLine("  var instance = new WebAssembly.Instance(new WebAssembly.Module(wasmTextToBinary(wat)), {js: imports});");
        sb.AppendLine("  var bytes = new Uint8Array(memory.buffer); bytes[0]=42; if (instance.exports.load(0)!==42) throw new Error('wasm memory import');");
        sb.AppendLine("  instance.exports.store(4, 0x12345678); var dv = new DataView(memory.buffer); if (dv.getUint32(4,true)!==0x12345678) throw new Error('wasm memory export');");
        sb.AppendLine("  if (instance.exports.call(5)!==12) throw new Error('wasm js import');");
        sb.AppendLine("  state.bias=11; if (instance.exports.call(5)!==16) throw new Error('wasm js state');");
        sb.AppendLine("  memory.grow(1); if (memory.buffer.byteLength!==131072) throw new Error('wasm grow');");
        sb.AppendLine("} else { var fallback = {value: 3}; if (fallback.value !== 3) throw new Error('wasm unavailable'); }");
        return sb.ToString();
    }

    private string GenerateWasmSimdOracle()
    {
        var sb = new StringBuilder("'use strict';\n");
        sb.AppendLine("var scalar = [0, 1, -1, 127, 128, 255, 1024]; var lanes = new Uint8Array(16);");
        sb.AppendLine("for (var i = 0; i < scalar.length; i++) lanes[i] = (scalar[i] + 256) & 255;");
        sb.AppendLine("var simdCandidates = [0xFD, 0x00, 0xFD, 0x01, 0xFD, 0x02, 0xFD, 0x03];");
        sb.AppendLine("for (var j = 0; j < simdCandidates.length; j++) { var candidate = new Uint8Array([0,97,115,109,1,0,0,0]); WebAssembly.validate(candidate); }");
        sb.AppendLine("if (lanes[0] !== 0 || lanes[2] !== 255) throw new Error('simd-oracle');");
        return sb.ToString();
    }

    private string GenerateAsyncDelazification()
    {
        var sb = new StringBuilder("'use strict';\n");
        sb.AppendLine("function outer(seed) { function inner(x) { return x + seed; } return async function(v) { await Promise.resolve(); return inner(v); }; }");
        sb.AppendLine("var jobs = []; for (var i = 0; i < 24; i++) jobs.push(outer(i)(i));");
        // __sf_fail (not throw): see GenerateModuleGraph for why a bare throw
        // inside .then() would never actually be observed during fuzzing.
        sb.AppendLine("Promise.all(jobs).then(function(values) { for (var i = 0; i < values.length; i++) if (values[i] !== i * 2 && typeof __sf_fail === 'function') __sf_fail('async'); });");
        sb.AppendLine("for (var k = 0; k < 60; k++) { var tmp = {k: k, text: 'gc' + k}; if (k % 11 === 0 && typeof gc === 'function') gc(); }");
        return sb.ToString();
    }

    // Structured mutators append valid, bounded programs instead of inserting random bytes.
    // They deliberately target observable IC/JIT state transitions, not memory corruption.
    public string MutateCustom(string input)
    {
        var family = _rng.Next(7);
        var sb = new StringBuilder(input);
        if (sb.Length > 0 && !char.IsWhiteSpace(sb[^1])) sb.AppendLine();
        sb.AppendLine("// SpiderFuzz structured custom mutator");
        switch (family)
        {
            case 0: AppendCacheIrShapeLadder(sb); break;
            case 1: AppendCacheIrAccessorInvalidation(sb); break;
            case 2: AppendJitTypeConfusionMatrix(sb); break;
            case 3: AppendJitBailoutAndOsr(sb); break;
            case 4: AppendPrototypeAndElementKindChurn(sb); break;
            case 5: AppendMegamorphicCallSite(sb); break;
            default: AppendJitTierFeedbackLink(sb); break;
        }
        return sb.ToString();
    }

    private void AppendCacheIrShapeLadder(StringBuilder sb)
    {
        sb.AppendLine("function __sf_shape_read(o) { return (o.a|0) + (o.b|0) + (o.c|0); }");
        sb.AppendLine("var __sf_shapes = [{a:1,b:2,c:3}, {b:2,a:1,c:3}, {a:1,c:3}, Object.create({a:4,b:5,c:6})];");
        sb.AppendLine("for (var __sf_i=0; __sf_i<1800; __sf_i++) __sf_shape_read(__sf_shapes[__sf_i % __sf_shapes.length]);");
        sb.AppendLine("for (var __sf_j=0; __sf_j<__sf_shapes.length; __sf_j++) { __sf_shapes[__sf_j].d=__sf_j; delete __sf_shapes[__sf_j].d; __sf_shape_read(__sf_shapes[__sf_j]); }");
    }

    private void AppendCacheIrAccessorInvalidation(StringBuilder sb)
    {
        sb.AppendLine("function __sf_accessor(o) { return o.value === undefined ? 0 : o.value|0; }");
        sb.AppendLine("var __sf_box={value:1, extra:2}; for (var __sf_i=0; __sf_i<1400; __sf_i++) __sf_accessor(__sf_box);");
        sb.AppendLine("Object.defineProperty(__sf_box,'value',{configurable:true,get:function(){return 7;}}); __sf_accessor(__sf_box);");
        sb.AppendLine("delete __sf_box.value; __sf_box.value=9; Object.setPrototypeOf(__sf_box,{value:11}); __sf_accessor(__sf_box);");
    }

    private void AppendJitTypeConfusionMatrix(StringBuilder sb)
    {
        sb.AppendLine("function __sf_poly(x) { if (x === null) return 0; if (typeof x === 'number') return (x+1)|0; if (typeof x === 'string') return x.length; if (Array.isArray(x)) return x.length; return x.k|0; }");
        sb.AppendLine("var __sf_values=[0,1,3.5,'abcd',null,undefined,[],[1,2],{k:9},{k:'10'}];");
        sb.AppendLine("for (var __sf_i=0; __sf_i<2200; __sf_i++) { var __sf_v=__sf_values[__sf_i%__sf_values.length]; var __sf_r=__sf_poly(__sf_v); if (typeof __sf_r!=='number') throw new Error('custom type oracle'); }");
        sb.AppendLine("__sf_values[7].push(3); __sf_values[8].k=12.5; __sf_values[9].k=null; __sf_poly(__sf_values[7]); __sf_poly(__sf_values[8]); __sf_poly(__sf_values[9]);");
    }

    private void AppendJitBailoutAndOsr(StringBuilder sb)
    {
        sb.AppendLine("function __sf_osr(o, limit) { var sum=0; for (var i=0; i<limit; i++) { if ((i&31)===0) sum += o.x|0; else sum += i; if (o.flip && (i&63)===0) sum = (sum+o.y)|0; } return sum|0; }");
        sb.AppendLine("var __sf_o={x:1,y:2,flip:false}; for (var __sf_i=0; __sf_i<80; __sf_i++) __sf_osr(__sf_o,160);");
        sb.AppendLine("__sf_o.flip=true; __sf_o.x='3'; __sf_o.y={valueOf:function(){return 4;}}; __sf_osr(__sf_o,96); delete __sf_o.x; __sf_o.x=5; __sf_osr(__sf_o,64);");
    }

    private void AppendPrototypeAndElementKindChurn(StringBuilder sb)
    {
        sb.AppendLine("function __sf_elem(a) { var n=0; for (var i=0;i<a.length;i++) n += a[i]===undefined ? 0 : (a[i]|0); return n; }");
        sb.AppendLine("var __sf_arr=[1,2,3,4,5,6]; for (var __sf_i=0;__sf_i<1200;__sf_i++) __sf_elem(__sf_arr);");
        sb.AppendLine("__sf_arr[2]=3.5; __sf_arr[4]='7'; __sf_arr.extra=1; delete __sf_arr.extra; __sf_arr.length=3; __sf_arr[7]=8; __sf_elem(__sf_arr);");
        sb.AppendLine("Object.setPrototypeOf(__sf_arr,{0:10}); __sf_elem(__sf_arr);");
    }

    private void AppendMegamorphicCallSite(StringBuilder sb)
    {
        sb.AppendLine("function __sf_call(o) { return o.m(); }");
        sb.AppendLine("var __sf_objs=[]; for (var __sf_i=0;__sf_i<12;__sf_i++) { var __sf_o={m:function(){return __sf_i;}}; if ((__sf_i&1)===0) __sf_o.x=__sf_i; if ((__sf_i%3)===0) __sf_o.y='y'; __sf_objs.push(__sf_o); }");
        sb.AppendLine("for (var __sf_j=0;__sf_j<2400;__sf_j++) { var __sf_r=__sf_call(__sf_objs[__sf_j%__sf_objs.length]); if (typeof __sf_r!=='number') throw new Error('custom call oracle'); }");
        sb.AppendLine("__sf_objs[0].m=function(){return 99;}; delete __sf_objs[1].x; __sf_call(__sf_objs[0]); __sf_call(__sf_objs[1]);");
    }

    private void AppendJitTierFeedbackLink(StringBuilder sb)
    {
        sb.AppendLine("function __sf_tier_link(o, x) { var r = o.value; if (typeof r === 'number') return (r + x) | 0; if (typeof r === 'string') return r.length + x; return (r.k|0) + x; }");
        sb.AppendLine("var __sf_tier_objs=[{value:1},{value:2.5},{value:'abcdef'},{value:{k:7}},{value:undefined}];");
        sb.AppendLine("for (var __sf_i=0; __sf_i<2400; __sf_i++) { var __sf_o=__sf_tier_objs[__sf_i%__sf_tier_objs.length]; try { __sf_tier_link(__sf_o,__sf_i&7); } catch(e) { if (!(e instanceof TypeError)) throw e; } }");
        sb.AppendLine("Object.defineProperty(__sf_tier_objs[0],'value',{configurable:true,get:function(){return 11;}}); __sf_tier_objs[1].value='12'; __sf_tier_objs[2].value={k:13};");
        sb.AppendLine("for (var __sf_j=0; __sf_j<320; __sf_j++) { var __sf_r=__sf_tier_link(__sf_tier_objs[__sf_j%3],1); if (typeof __sf_r!=='number') throw new Error('tier feedback oracle'); }");
    }

    // 2024-2026 language/API surface: Iterator helpers, Set methods,
    // Uint8Array base64/hex, explicit resource management, Promise.try/
    // withResolvers/fromAsync, RegExp.escape + duplicate named groups,
    // Object/Map.groupBy, Float16Array. Every generator wraps engine calls in
    // typeof/try-catch so it degrades to a near no-op on a build/channel
    // that lacks the feature, instead of drowning the run in ReferenceErrors.
    private string GenerateIteratorHelpersFuzz()
    {
        var sb = new StringBuilder("'use strict';\n");
        sb.AppendLine("function* __sf_gen(n) { for (var i = 0; i < n; i++) yield i; }");
        var chainOps = new[] { "map(x => x + 1)", "filter(x => x % 2 === 0)", "take(5)", "drop(2)", "flatMap(x => [x, x])" };
        var terminalOps = new[] { "toArray()", "reduce((a, b) => a + b, 0)", "some(x => x > 3)", "every(x => x >= 0)", "find(x => x === 2)" };
        var count = _rng.Next(3, 20);
        for (var i = 0; i < count; i++)
        {
            var chainLen = _rng.Next(1, 4);
            var chain = new StringBuilder($"__sf_gen({_rng.Next(0, 30)})");
            for (var j = 0; j < chainLen; j++)
                chain.Append('.').Append(chainOps[_rng.Next(chainOps.Length)]);
            chain.Append('.').Append(terminalOps[_rng.Next(terminalOps.Length)]);
            sb.AppendLine($"try {{ var __sf_r{i} = {chain}; }} catch(e) {{}}");
        }
        sb.AppendLine("if (typeof Iterator !== 'undefined' && typeof Iterator.from === 'function') {");
        sb.AppendLine("  try { Iterator.from(__sf_gen(8)).take(3).toArray(); Iterator.from([1,2,3]).map(x=>x*2).toArray(); } catch(e) {}");
        sb.AppendLine("}");
        // Light oracle: dropping then taking must never yield more items than requested.
        sb.AppendLine("if (typeof Iterator !== 'undefined') { var __sf_check = __sf_gen(50).drop(10).take(5).toArray(); if (__sf_check.length > 5) throw new Error('iterator helpers over-produce'); }");
        return sb.ToString();
    }

    private string GenerateSetMethodsFuzz()
    {
        var sb = new StringBuilder("'use strict';\n");
        sb.AppendLine("if (typeof Set.prototype.union === 'function') {");
        var setOps = new[] { "union", "intersection", "difference", "symmetricDifference", "isSubsetOf", "isSupersetOf", "isDisjointFrom" };
        var count = _rng.Next(3, 15);
        for (var i = 0; i < count; i++)
        {
            var sizeA = _rng.Next(0, 20);
            var sizeB = _rng.Next(0, 20);
            var op = setOps[_rng.Next(setOps.Length)];
            sb.AppendLine($"  try {{");
            sb.AppendLine($"    var __sf_a{i} = new Set(Array.from({{length: {sizeA}}}, (_, k) => k));");
            sb.AppendLine($"    var __sf_b{i} = new Set(Array.from({{length: {sizeB}}}, (_, k) => k + {_rng.Next(-5, 15)}));");
            sb.AppendLine($"    var __sf_r{i} = __sf_a{i}.{op}(__sf_b{i});");
            sb.AppendLine($"  }} catch(e) {{}}");
        }
        // Set-like (non-Set) argument path: must accept any object exposing size/has/keys.
        sb.AppendLine("  var __sf_setlike = {size: 3, has: function(v) { return v >= 0 && v < 3; }, keys: function() { return [0,1,2][Symbol.iterator](); }};");
        sb.AppendLine("  try { new Set([1,2,3,4]).intersection(__sf_setlike); new Set([1,2,3,4]).isSupersetOf(__sf_setlike); } catch(e) {}");
        sb.AppendLine("}");
        return sb.ToString();
    }

    private string GenerateUint8ArrayCodecFuzz()
    {
        var sb = new StringBuilder("'use strict';\n");
        sb.AppendLine("if (typeof Uint8Array.prototype.toBase64 === 'function') {");
        var alphabets = new[] { "base64", "base64url" };
        var chunkHandling = new[] { "loose", "strict", "stop-before-partial" };
        var count = _rng.Next(3, 15);
        for (var i = 0; i < count; i++)
        {
            var len = _rng.Next(0, 64);
            var alphabet = alphabets[_rng.Next(alphabets.Length)];
            var omit = _rng.Next(2) == 0 ? "true" : "false";
            var chunk = chunkHandling[_rng.Next(chunkHandling.Length)];
            sb.AppendLine($"  try {{");
            sb.AppendLine($"    var __sf_bytes{i} = new Uint8Array({len}); for (var __sf_k=0; __sf_k<{len}; __sf_k++) __sf_bytes{i}[__sf_k] = (__sf_k * 37 + {i}) & 255;");
            sb.AppendLine($"    var __sf_b64_{i} = __sf_bytes{i}.toBase64({{alphabet: '{alphabet}', omitPadding: {omit}}});");
            sb.AppendLine($"    var __sf_back{i} = Uint8Array.fromBase64(__sf_b64_{i}, {{alphabet: '{alphabet}', lastChunkHandling: '{chunk}'}});");
            sb.AppendLine($"    var __sf_hex{i} = __sf_bytes{i}.toHex();");
            sb.AppendLine($"    var __sf_hback{i} = Uint8Array.fromHex(__sf_hex{i});");
            sb.AppendLine($"    if (__sf_hback{i}.length !== __sf_bytes{i}.length) throw new Error('uint8array hex round-trip length');");
            sb.AppendLine($"    var __sf_target{i} = new Uint8Array({len});");
            sb.AppendLine($"    __sf_target{i}.setFromBase64(__sf_b64_{i}, {{alphabet: '{alphabet}'}});");
            sb.AppendLine($"  }} catch(e) {{}}");
        }
        // Malformed input must be rejected, never silently truncated/misparsed.
        sb.AppendLine("  var __sf_badInputs = ['!!!!', 'A', 'AAAA====', '', 'zzzzzzzz'];");
        sb.AppendLine("  for (var __sf_bi = 0; __sf_bi < __sf_badInputs.length; __sf_bi++) { try { Uint8Array.fromBase64(__sf_badInputs[__sf_bi]); } catch(e) {} try { Uint8Array.fromHex(__sf_badInputs[__sf_bi]); } catch(e) {} }");
        sb.AppendLine("}");
        return sb.ToString();
    }

    private string GenerateResourceManagementFuzz()
    {
        var sb = new StringBuilder("'use strict';\n");
        sb.AppendLine("if (typeof DisposableStack === 'function') {");
        sb.AppendLine("  var __sf_log = [];");
        sb.AppendLine("  function __sf_disposable(name, throwOnDispose) { return {[Symbol.dispose]: function() { __sf_log.push(name); if (throwOnDispose) throw new Error('dispose:' + name); }}; }");
        var depth = _rng.Next(1, 8);
        sb.AppendLine("  try {");
        sb.AppendLine("    (function() {");
        for (var i = 0; i < depth; i++)
        {
            var willThrow = _rng.Next(4) == 0 ? "true" : "false";
            sb.AppendLine($"      using __sf_r{i} = __sf_disposable('r{i}', {willThrow});");
        }
        sb.AppendLine("    })();");
        // Nested throwing disposals combine into a SuppressedError chain - exercising
        // that path is exactly the point (not a bug if a SuppressedError bubbles out).
        sb.AppendLine("  } catch (e) { if (typeof SuppressedError !== 'undefined' && !(e instanceof Error)) throw e; }");
        sb.AppendLine("  var __sf_stack = new DisposableStack();");
        var stackOps = _rng.Next(1, 6);
        for (var i = 0; i < stackOps; i++)
        {
            var op = _rng.Next(3);
            sb.AppendLine(op switch
            {
                0 => $"  __sf_stack.use(__sf_disposable('s{i}', false));",
                1 => $"  __sf_stack.defer(function() {{ __sf_log.push('d{i}'); }});",
                _ => $"  __sf_stack.adopt({{v:{i}}}, function(v) {{ __sf_log.push('a' + v.v); }});",
            });
        }
        sb.AppendLine("  var __sf_moved = __sf_stack.move();");
        sb.AppendLine("  __sf_moved.dispose();");
        sb.AppendLine("  if (!__sf_stack.disposed) throw new Error('DisposableStack.move should mark source disposed');");
        sb.AppendLine("}");
        return sb.ToString();
    }

    private string GenerateModernPromiseFuzz()
    {
        var sb = new StringBuilder("'use strict';\n");
        sb.AppendLine("if (typeof Promise.withResolvers === 'function') {");
        sb.AppendLine("  var __sf_pr = Promise.withResolvers();");
        sb.AppendLine(_rng.Next(2) == 0 ? $"  __sf_pr.resolve({RValue()});" : $"  __sf_pr.reject({RValue()});");
        sb.AppendLine("  __sf_pr.promise.then(function(){}, function(){});");
        sb.AppendLine("}");
        sb.AppendLine("if (typeof Promise.try === 'function') {");
        var tryBodies = new[] { "return 1;", "throw new Error('x');", "return Promise.resolve(2);", "null.foo;" };
        for (var i = 0; i < _rng.Next(1, 6); i++)
        {
            sb.AppendLine($"  Promise.try(function() {{ {tryBodies[_rng.Next(tryBodies.Length)]} }}).then(function(){{}}, function(){{}});");
        }
        sb.AppendLine("}");
        sb.AppendLine("if (typeof Array.fromAsync === 'function') {");
        sb.AppendLine("  async function* __sf_agen(n) { for (var i = 0; i < n; i++) { if (i === 2) await Promise.resolve(); yield i; } }");
        sb.AppendLine($"  Array.fromAsync(__sf_agen({_rng.Next(0, 12)})).then(function(){{}}, function(){{}});");
        sb.AppendLine("  Array.fromAsync([1, Promise.resolve(2), 3]).then(function(){}, function(){});");
        sb.AppendLine("}");
        return sb.ToString();
    }

    private string GenerateRegexModernFuzz()
    {
        var sb = new StringBuilder("'use strict';\n");
        sb.AppendLine("if (typeof RegExp.escape === 'function') {");
        var count = _rng.Next(2, 10);
        for (var i = 0; i < count; i++)
        {
            var raw = RandomAsciiString(_rng.Next(0, 40));
            sb.AppendLine($"  try {{ var __sf_esc{i} = RegExp.escape(\"{raw}\"); new RegExp(__sf_esc{i}).test(\"{raw}\"); }} catch(e) {{}}");
        }
        sb.AppendLine("}");
        // Duplicate named capture groups across mutually exclusive alternatives (shipped 2023).
        var groupNames = new[] { "x", "year", "value", "a" };
        var name1 = groupNames[_rng.Next(groupNames.Length)];
        sb.AppendLine($"try {{ var __sf_dup = /(?<{name1}>a+)-\\d|\\d-(?<{name1}>a+)/; __sf_dup.exec('aa-1'); __sf_dup.exec('1-aa'); }} catch(e) {{}}");
        return sb.ToString();
    }

    private string GenerateGroupByFuzz()
    {
        var sb = new StringBuilder("'use strict';\n");
        sb.AppendLine("if (typeof Object.groupBy === 'function') {");
        var size = _rng.Next(0, 100);
        var mod = _rng.Next(1, 7);
        sb.AppendLine($"  var __sf_items = Array.from({{length: {size}}}, (_, k) => k);");
        sb.AppendLine($"  var __sf_grouped = Object.groupBy(__sf_items, x => x % {mod});");
        sb.AppendLine("  if (typeof Map.groupBy === 'function') { var __sf_mgrouped = Map.groupBy(__sf_items, x => typeof x); }");
        sb.AppendLine("  try { Object.groupBy(__sf_items, x => '__proto__'); } catch(e) {}");
        sb.AppendLine("  var __sf_total = 0; for (var __sf_k in __sf_grouped) __sf_total += __sf_grouped[__sf_k].length;");
        sb.AppendLine($"  if (__sf_total !== {size}) throw new Error('groupBy lost items');");
        sb.AppendLine("}");
        return sb.ToString();
    }

    private string GenerateFloat16Fuzz()
    {
        var sb = new StringBuilder("'use strict';\n");
        sb.AppendLine("if (typeof Float16Array === 'function') {");
        var count = _rng.Next(1, 20);
        for (var i = 0; i < count; i++)
        {
            var len = _rng.Next(0, 64);
            sb.AppendLine($"  try {{ var __sf_f16_{i} = new Float16Array({len}); for (var __sf_k=0; __sf_k<{len}; __sf_k++) __sf_f16_{i}[__sf_k] = {RNum()}; }} catch(e) {{}}");
        }
        sb.AppendLine("  var __sf_edge = new Float16Array([0, -0, NaN, Infinity, -Infinity, 65504, 65520, 6.1e-5, 5.96e-8]);");
        sb.AppendLine("  if (__sf_edge[6] !== Infinity) throw new Error('Float16Array does not round to infinity above max finite');");
        sb.AppendLine("  if (typeof Math.f16round === 'function') { for (var __sf_i=0; __sf_i<20; __sf_i++) Math.f16round(" + RNum() + " * __sf_i); }");
        sb.AppendLine("}");
        return sb.ToString();
    }

    private string MakeLambda()
    {
        var kind = _rng.Next(4);
        return kind switch
        {
            0 => $"({RVar()}) => {RExpr()}",
            1 => $"({RVar()}, {RVar()}) => {{ return {RExpr()}; }}",
            2 => $"function({RVar()}) {{ return {RExpr()}; }}",
            3 => $"async ({RVar()}) => {RValue()}",
            _ => $"({RVar()}) => {RValue()}",
        };
    }

    private string MakeStatement()
    {
        var action = _rng.Next(15);
        return action switch
        {
            0 => $"{RVar()} = {RExpr()};",
            1 => $"var {RVar()} = {RExpr()};",
            2 => $"if ({RExpr()}) {{ {RVar()} = {RExpr()}; }}",
            3 => $"if ({RExpr()}) {{ {RVar()} = {RExpr()}; }} else {{ {RVar()} = {RExpr()}; }}",
            4 => $"try {{ {RVar()} = {RExpr()}; }} catch(e) {{}}",
            5 => $"typeof {RExpr()}",
            6 => $"void {RExpr()}",
            7 => $"{RVar()}.toString()",
            8 => $"Object.keys({RExpr()})",
            9 => $"JSON.stringify({RExpr()})",
            10 => $"JSON.parse({RExpr()}) || null",
            11 => $"Array.isArray({RExpr()})",
            12 => $"Number({RExpr()})",
            13 => $"String({RExpr()})",
            14 => $"!!{RExpr()}",
            _ => $"0",
        };
    }

    // RExpr recurses into itself (directly, and through several branches that
    // fan out into 0-5 nested sub-expressions each). Left unbounded, a long
    // enough unlucky run of RNG choices produces a call stack deep enough to
    // crash the fuzzer process itself with a StackOverflowException - which,
    // unlike a JS-side crash, cannot be caught and takes down the whole
    // campaign instead of just being recorded as one interesting input.
    private const int MaxExprDepth = 6;
    private int _exprDepth;

    private string RExpr()
    {
        if (_exprDepth >= MaxExprDepth)
        {
            return _rng.Next(2) == 0 ? RNum() : RVar();
        }

        _exprDepth++;
        try
        {
            var kind = _rng.Next(15);
            return kind switch
            {
                0 => RNum(),
                1 => RStr(),
                2 => RVar(),
                3 => $"{RExpr()} {_randomBinOp()} {RExpr()}",
                4 => $"{_randomUnaryOp()} {RExpr()}",
                5 => $"({RExpr()})",
                6 => $"[{string.Join(", ", Enumerable.Range(0, _rng.Next(0, 5)).Select(_ => RExpr()))}]",
                7 => $"({string.Join(", ", Enumerable.Range(0, _rng.Next(1, 5)).Select(_ => RExpr()))})",
                8 => $"{{{string.Join(", ", Enumerable.Range(0, _rng.Next(0, 5)).Select(i => $"{RStr()}: {RExpr()}"))}}}",
                9 => $"({RExpr()}).toString()",
                10 => $"typeof {RExpr()}",
                11 => RPredefinedName(),
                12 => $"{RPredefinedName()}.{RMethod()}",
                13 => _rng.Next(2) == 0 ? "null" : "undefined",
                14 => $"({RExpr()} ? {RExpr()} : {RExpr()})",
                _ => RNum(),
            };
        }
        finally
        {
            _exprDepth--;
        }
    }

    private string RValue()
    {
        var kind = _rng.Next(10);
        return kind switch
        {
            0 => RNum(),
            1 => RStr(),
            2 => RSpecialValue(),
            3 => RPredefinedName(),
            4 => "[]",
            5 => "{}",
            6 => "function(){}",
            7 => "null",
            8 => "undefined",
            9 => RRegex(),
            _ => "0",
        };
    }

    private string RNum()
    {
        var kind = _rng.Next(10);
        return kind switch
        {
            0 => _rng.Next(-1000, 1000).ToString(),
            1 => $"0x{_rng.Next():X}",
            2 => $"0o{Convert.ToString(_rng.Next(0, 077777), 8)}",
            3 => $"0b{Convert.ToString(_rng.Next(0, 1000000), 2)}",
            4 => $"{_rng.Next(-100, 100)}.{_rng.Next(0, 1000)}",
            5 => $"1e{_rng.Next(-300, 308)}",
            6 => $"-1e{_rng.Next(-300, 308)}",
            7 => _rng.Next(3) switch { 0 => "NaN", 1 => "Infinity", _ => "-Infinity" },
            8 => $"0x{_rng.Next(0, 16):X}p{_rng.Next(-100, 100)}",
            9 => "Number.MAX_SAFE_INTEGER",
            _ => "0",
        };
    }

    private string RStr()
    {
        var kind = _rng.Next(4);
        return kind switch
        {
            0 => $"\"{RandomAsciiString(_rng.Next(0, 100))}\"",
            1 => $"'{RandomAsciiString(_rng.Next(0, 100))}'",
            2 => $"`{RandomAsciiString(_rng.Next(0, 100))}`",
            3 => _stringLiterals[_rng.Next(_stringLiterals.Length)],
            _ => "\"\"",
        };
    }

    private string RVar()
    {
        var names = new[] { "a", "b", "c", "d", "e", "f", "g", "x", "y", "z", "obj", "arr", "val", "tmp", "r" };
        return names[_rng.Next(names.Length)] + _rng.Next(0, 100);
    }

    private string RPredefinedName()
    {
        return _predefinedNames[_rng.Next(_predefinedNames.Length)];
    }

    private string RSpecialValue()
    {
        return _specialValues[_rng.Next(_specialValues.Length)];
    }

    private string RMethod()
    {
        var methods = new[]
        {
            "prototype", "constructor", "toString", "valueOf", "hasOwnProperty",
            "isPrototypeOf", "propertyIsEnumerable", "toLocaleString",
            "entries", "keys", "values", "from", "of", "fromEntries",
            "assign", "freeze", "seal", "preventExtensions", "isFrozen", "isSealed",
            "defineProperty", "defineProperties", "getOwnPropertyDescriptor",
            "getOwnPropertyDescriptors", "getOwnPropertyNames", "getPrototypeOf",
            "setPrototypeOf", "create", "is", "group", "groupBy",
            "parse", "stringify",
            "isArray", "fromCharCode", "fromCodePoint",
            "now", "random", "max", "min", "abs", "ceil", "floor", "round",
            "sqrt", "cbrt", "pow", "log", "log2", "log10",
            "sin", "cos", "tan", "asin", "acos", "atan", "atan2",
            "exp", "expm1", "sign", "trunc", "fround",
            "fill", "find", "findIndex", "findLast", "findLastIndex",
            "includes", "indexOf", "lastIndexOf",
            "map", "filter", "reduce", "reduceRight",
            "some", "every", "flat", "flatMap",
            "slice", "splice", "concat", "reverse", "sort",
            "push", "pop", "shift", "unshift",
            "charCodeAt", "charAt", "codePointAt", "normalize",
            "padStart", "padEnd", "repeat", "replace", "replaceAll",
            "match", "matchAll", "search", "split", "startsWith", "endsWith",
            "substring", "toLowerCase", "toUpperCase", "trim", "trimStart", "trimEnd",
        };
        return methods[_rng.Next(methods.Length)];
    }

    private string RRegex()
    {
        var pattern = _regexPatterns[_rng.Next(_regexPatterns.Length)];
        var flags = _regexFlags[_rng.Next(_regexFlags.Length)];
        return $"new RegExp({pattern}, \"{flags}\")";
    }

    private string RandomAsciiString(int length)
    {
        var sb = new StringBuilder(length);
        for (var i = 0; i < length; i++)
        {
            var c = (char)(_rng.Next(32, 127));
            if (c == '"' || c == '\'' || c == '`' || c == '\\')
                sb.Append('\\');
            sb.Append(c);
        }
        return sb.ToString();
    }

    private string RandomByteString(int length)
    {
        var sb = new StringBuilder(length);
        for (var i = 0; i < length; i++)
        {
            // Keep mutations deterministic and preserve every generated code unit.
            // Values 0..255 are valid Unicode code points; UTF-8 encoding is handled
            // explicitly by the runners when the input is sent to SpiderMonkey.
            sb.Append((char)_rng.Next(256));
        }
        return sb.ToString();
    }

    private string _randomBinOp() => _binaryOps[_rng.Next(_binaryOps.Length)];
    private string _randomUnaryOp() => _unaryOps[_rng.Next(_unaryOps.Length)];
}
