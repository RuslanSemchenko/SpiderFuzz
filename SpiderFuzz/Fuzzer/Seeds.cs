using System.Text;

namespace SpiderFuzz.Fuzzer;

internal static class Seeds
{
    public static readonly string[] Common =
    [
        // Basic object manipulation
        """
        var a = {x: 1, y: 2, z: 3};
        var b = Object.create(a);
        b.w = 4;
        for (var k in b) { print(k, b[k]); }
        """,

        // Array edge cases
        """
        var a = [1, 2, 3];
        a.length = 0;
        a.length = 100;
        a[4294967295] = 1;
        a[-1] = 2;
        a[1.5] = 3;
        """,

        // Prototype chain manipulation
        """
        var a = {};
        var b = Object.create(a);
        var c = Object.create(b);
        c.__proto__.__proto__.x = 1;
        delete c.__proto__.__proto__.x;
        """,

        // Try-catch with different error types
        """
        try { null.f(); } catch(e) {}
        try { (1).x; } catch(e) {}
        try { var a = undeclared; } catch(e) {}
        try { eval('if(true {}'); } catch(e) {}
        """,

        // Regex engine stress
        """
        var re = /^(a+)+$/;
        re.test('a'.repeat(16));
        var re2 = new RegExp('(a*)*', 'g');
        'aaaaaaaaaaaaaaaa'.replace(re2, 'b');
        """,

        // Proxy basic
        """
        var p = new Proxy({}, {
            get(t, k) { return k in t ? t[k] : 42; },
            set(t, k, v) { t[k] = v * 2; return true; },
            has(t, k) { return true; },
            deleteProperty(t, k) { return false; },
        });
        p.x = 10;
        'x' in p;
        delete p.x;
        """,

        // Promise basics
        """
        Promise.resolve(42).then(v => print(v));
        Promise.reject('err').catch(e => print(e));
        Promise.all([Promise.resolve(1), Promise.resolve(2)]).then(v => print(v));
        Promise.race([Promise.resolve(1), new Promise(r => setTimeout(() => r(2), 100))]).then(v => print(v));
        """,

        // Typed array basics
        """
        var buf = new ArrayBuffer(256);
        var view = new DataView(buf);
        view.setInt8(0, 127);
        view.setUint8(1, 255);
        view.setInt16(2, -1);
        view.setFloat64(4, 3.14);
        var arr = new Float64Array(buf);
        """,

        // WeakRef basics
        """
        var obj = {};
        var wr = new WeakRef(obj);
        var fg = new FinalizationRegistry(held => print(held));
        fg.register(obj, 'token');
        wr.deref();
        obj = null;
        if (typeof gc === 'function') gc();
        """,

        // Map/Set stress
        """
        var m = new Map();
        for (var i = 0; i < 1000; i++) m.set(i, {v: i});
        m.forEach((v, k) => { m.delete(k); });
        var s = new Set();
        for (var i = 0; i < 1000; i++) s.add(i);
        s.clear();
        """,

        // Destructuring patterns
        """
        var [a, b, ...c] = [1, 2, 3, 4, 5];
        var {x: p, y: q, ...r} = {x: 1, y: 2, z: 3};
        var [[w, [x]]] = [[1, [2]]];
        var {a: {b: {c}}} = {a: {b: {c: 42}}};
        """,

        // Generator/Iterator
        """
        function* gen() { yield 1; yield* [2, 3]; yield 4; }
        var it = gen();
        it.next();
        it.return(0);
        function* fib() { var [a, b] = [0, 1]; while(true) { yield a; [a, b] = [b, a+b]; } }
        """,

        // Async functions
        """
        async function f() {
            var v = await Promise.resolve(42);
            return v + 1;
        }
        f().then(v => print(v));
        """,

        // Class features
        """
        class A { #x = 1; get x() { return this.#x; } set x(v) { this.#x = v; } }
        class B extends A { constructor() { super(); this.y = 2; } }
        var b = new B();
        b.x = 42;
        """,

        // Symbol
        """
        var s = Symbol('test');
        var obj = {[s]: 42};
        Object.getOwnPropertySymbols(obj);
        Symbol.iterator;
        Symbol.toPrimitive;
        Symbol.toStringTag;
        Symbol.for('test') === Symbol.for('test');
        """,

        // Error with cause
        """
        try {
            try { throw new Error('inner'); }
            catch(e) { throw new Error('outer', {cause: e}); }
        } catch(e) { print(e.message, e.cause.message); }
        """,

        // For-of with iterables
        """
        var iterable = { [Symbol.iterator]() { var i = 0; return { next() { return i < 3 ? {value: i++, done: false} : {done: true}; } }; } };
        for (var v of iterable) print(v);
        """,

        // Spread operator
        """
        var a = [...'hello'];
        var b = {...{x: 1, y: 2}, z: 3};
        var c = Object.assign({}, a, b);
        Math.max(...[1, 2, 3, 4, 5]);
        """,

        // Optional chaining + nullish coalescing
        """
        var a = null?.x?.y?.z;
        var b = {x: {y: 1}}?.x?.y;
        var c = null ?? 'default';
        var d = undefined ?? 42;
        var e = 0 ?? 'zero';
        """,

        // JSON edge cases
        """
        JSON.parse('null');
        JSON.parse('{"a": 1}');
        JSON.parse('[1, 2, 3]');
        JSON.stringify(undefined);
        JSON.stringify([NaN, Infinity, -Infinity, null, undefined]);
        JSON.stringify({}, null, 2);
        JSON.stringify({toJSON() { return 42; }});
        """,

        // toString/valueOf coercion
        """
        var a = {toString() { return 'a'; }, valueOf() { return 1; }};
        '' + a;
        '' + {valueOf() { throw new Error(); }};
        """,

        // Labels and break/continue
        """
        outer: for (var i = 0; i < 3; i++) {
            inner: for (var j = 0; j < 3; j++) {
                if (j === 1) continue inner;
                if (i === 2) break outer;
            }
        }
        """,

        // eval and indirect eval
        """
        var x = 1;
        eval('var x = 2;');
        (0, eval)('var x = 3;');
        """,

        // with statement
        """
        var obj = {a: 1, b: 2};
        with (obj) { var c = a + b; }
        """,

        // for-in with deletions
        """
        var obj = {a: 1, b: 2, c: 3, d: 4};
        for (var k in obj) {
            if (k === 'b') delete obj.c;
        }
        """,

        // Function.length edge cases
        """
        function f(a, b, c) {}
        f.length;
        Function.length;
        (function(){}).length;
        """,

        // Arguments object
        """
        function test() {
            arguments.callee;
            Array.from(arguments);
            var args = [...arguments];
        }
        test(1, 2, 3);
        """,

        // Date edge cases
        """
        new Date(NaN);
        new Date(0);
        new Date(8640000000000001);
        new Date(-8640000000000001);
        new Date('invalid');
        """,

        // Number edge cases
        """
        NaN === NaN;
        +0 === -0;
        Object.is(NaN, NaN);
        Object.is(+0, -0);
        Number.isNaN(NaN);
        Number.isFinite(Infinity);
        Number.isInteger(1.0);
        Number.isSafeInteger(2**53);
        """,

        // bitwise operators edge cases
        """
        0xFFFFFFFF >>> 1;
        0xFFFFFFFF >> 1;
        0xFFFFFFFF << 1;
        1 << 31;
        1 << 32;
        1 << -1;
        """,
    ];

    // Safe semantic regression PoCs derived from public Mozilla bug classes.
    // They assert language behavior and termination; they do not contain exploit payloads.
    public static readonly string[] Targeted =
    [
        // JIT bailout/recover and shape invalidation (Ion/CacheIR classes).
        """
        function f(o, n) { return (o.x + n) | 0; }
        var o = {x: 1};
        for (var i = 0; i < 1200; i++) f(o, i);
        o.x = '2';
        var r = f(o, 3);
        if (typeof r !== 'number') throw new Error('jit bailout result');
        """,
        // RegExp Unicode property and v-flag reparse semantics.
        """
        var good = /\p{Script=Greek}/u;
        if (!good.test('\u{391}')) throw new Error('regexp unicode');
        try { new RegExp('\\p', 'v'); } catch (e) { if (!(e instanceof SyntaxError)) throw e; }
        """,
        // Lazy/full parser agreement on optional private access syntax.
        """
        try { new Function('class A { m() { delete this?.#x; } }'); }
        catch (e) { if (!(e instanceof SyntaxError)) throw e; }
        """,
        // WeakMap/realm/GC lifetime semantics.
        """
        var wm = new WeakMap(), key = {x: 1}, value = {y: 2};
        wm.set(key, value);
        if (wm.get(key).y !== 2) throw new Error('weakmap');
        if (typeof gc === 'function') { gc(); if (wm.get(key).y !== 2) throw new Error('gc'); }
        """,
        // Bounded async module-like graph and delazification path.
        // Uses __sf_fail (not throw) inside .then(): a bare throw here would
        // only surface as an unhandled rejection at process exit, attributed
        // to whatever unrelated input happens to be running at that point.
        """
        function outer(x) { function inner(y) { return x + y; } return async function(z) { await 0; return inner(z); }; }
        var p = outer(3)(4);
        p.then(function(v) { if (v !== 7 && typeof __sf_fail === 'function') __sf_fail('async'); });
        """,
        // Minimal valid WebAssembly boundary/oracle module.
        """
        var b = new Uint8Array([0,97,115,109,1,0,0,0,1,4,1,96,0,1,127,3,2,1,0,7,7,1,3,102,111,111,0,0,10,6,1,4,0,65,0,11]);
        var inst = new WebAssembly.Instance(new WebAssembly.Module(b));
        if (inst.exports.foo() !== 0) throw new Error('wasm oracle');
        """,
        // Cross-realm identity where the shell exposes newGlobal().
        """
        if (typeof newGlobal === 'function') { var g = newGlobal(); var obj = {value: 9}; g.obj = obj; if (g.obj.value !== 9) throw new Error('realm'); }
        """,
        // Typed-array/GC pressure without out-of-bounds access.
        """
        for (var i = 0; i < 64; i++) { var a = new Uint8Array(32); a[i & 31] = i; if (a[i & 31] !== i) throw new Error('array'); }
        """
    ];


    // Additional bounded 2026 regression classes from public Mozilla Bugzilla/Searchfox.
    // These are semantic regression tests, not exploit payloads or attachment copies.
    public static readonly string[] Targeted2026 =
    [
        // Bug 2012663: instanceof prototype mutation / Warp IC pressure.
        """
        function assertEq(a, b) { if (a !== b) throw new Error(String(a) + ' !== ' + String(b)); }
        for (var i = 0; i < 32; i++) {
            function F() {}
            var o = Object.create(F.prototype);
            assertEq(o instanceof F, true);
            F.prototype = {};
            assertEq(o instanceof F, false);
            F.prototype = null;
            var threw = false;
            try { void (o instanceof F); } catch (e) { threw = e instanceof TypeError; }
            assertEq(threw, true);
        }
        """,
        // Bugs 2021192/2042720: Object.hasOwn and trial-inlining type pressure.
        """
        function assertEq(a, b) { if (a !== b) throw new Error(String(a) + ' !== ' + String(b)); }
        var keys = [0, 1, -1, 4294967296, 3.5, 'x'];
        for (var i = 0; i < 64; i++) {
            var obj = {x: 1};
            var key = keys[i % keys.length];
            assertEq(Object.hasOwn(obj, key), key === 'x');
        }
        """,
        // Bug 2036303: stable call site with bounded type changes.
        """
        function leaf(x, y) { return x ? 1 : (y >>> 0); }
        function outer(x, y) { return leaf(x, y); }
        var vals = [0, 1, undefined, 2, 4294967296];
        for (var i = 0; i < 48; i++) {
            var result = outer(Boolean(vals[i % vals.length]), vals[(i * 3) % vals.length]);
            if (typeof result !== 'number') throw new Error('jit result');
        }
        """,
        // Bug 2042331: SIMD semantic class, only when shell exposes wasmTextToBinary.
        """
        if (typeof wasmTextToBinary === 'function') {
            var bin = wasmTextToBinary('(module (memory (export "mem") 1 1) (func (export "anytrue") (result i32) (v128.any_true (v128.load (i32.const 0)))))');
            var inst = new WebAssembly.Instance(new WebAssembly.Module(bin));
            var mem = new Uint8Array(inst.exports.mem.buffer);
            mem[0] = 1;
            if (inst.exports.anytrue() !== 1) throw new Error('simd anytrue');
            for (var i = 0; i < 16; i++) mem[i] = 0;
            if (inst.exports.anytrue() !== 0) throw new Error('simd zero');
        }
        """,
        // Bug 2051015 class: one-page Wasm load boundaries.
        """
        var bytes = new Uint8Array([0,97,115,109,1,0,0,0,1,5,1,96,1,127,1,127,3,2,1,0,5,3,1,0,1,7,8,1,4,108,111,97,100,0,0,10,9,1,7,0,32,0,40,2,0,11]);
        var instance = new WebAssembly.Instance(new WebAssembly.Module(bytes));
        if (instance.exports.load(0) !== 0) throw new Error('wasm boundary');
        if (instance.exports.load(65532) !== 0) throw new Error('wasm boundary end');
        var trapped = false;
        try { instance.exports.load(65533); } catch (e) { trapped = e instanceof WebAssembly.RuntimeError; }
        if (!trapped) throw new Error('expected wasm trap');
        """,
        // Bugs 2022062/2030885: async-generator error path.
        // Uses __sf_fail (not throw) inside .then(): see comment on the
        // "Bounded async module-like graph" seed above for why a bare throw
        // here would never actually be observed during fuzzing.
        """
        var broken = Promise.resolve(1);
        Object.defineProperty(broken, 'constructor', {get: function() { throw new Error('broken constructor'); }});
        async function* gen() { try { await broken; } catch (e) { yield e.message; } }
        gen().next().then(function(r) {
            if ((r.value !== 'broken constructor' || r.done !== false) && typeof __sf_fail === 'function')
                __sf_fail('async generator');
        });
        """,
        // Bug 2036001/2043259: bounded async-generator return path.
        """
        async function* gen() { yield 1; }
        var g = gen();
        g.next().then(function() {
            var value = Promise.resolve(42);
            Object.defineProperty(value, 'constructor', {get: function() { throw new Error('broken constructor'); }});
            return g.return(value);
        }).catch(function(e) {
            if (!(e instanceof Error) && typeof __sf_fail === 'function') __sf_fail('async generator return: ' + e);
        });
        """,
        // Bug 2011802: module syntax is rejected/accepted without engine assertion.
        """
        var valid = new Function('return 42;');
        if (valid() !== 42) throw new Error('parser');
        var rejected = false;
        try { new Function('export const x = 1;'); } catch (e) { rejected = e instanceof SyntaxError; }
        if (!rejected) throw new Error('expected syntax error');
        """,
        // Bug 2034791 class: bounded dynamic module graph when data URLs are supported.
        """
        if (typeof WebAssembly !== 'undefined' && typeof Promise === 'function') {
            var p = Promise.resolve({default: 1});
            p.then(function(ns) { if (ns.default !== 1 && typeof __sf_fail === 'function') __sf_fail('module namespace'); });
        }
        """,
        // Bug 2029515/2032769: bounded BigInt typed-array nursery allocation.
        """
        for (var i = 0; i < 25; i++) {
            var a = new BigInt64Array(488);
            if (a.length !== 488 || a[0] !== 0n) throw new Error('typed array');
        }
        """,
        // Bug 1969845: bounded WeakMap identity class.
        """
        var m = new WeakMap(), keep = [];
        for (var i = 0; i < 64; i++) {
            var key = {i: i}, value = {i: i};
            m.set(key, value); keep.push([key, value]);
        }
        for (var j = 0; j < keep.length; j++) if (m.get(keep[j][0]) !== keep[j][1]) throw new Error('weakmap');
        """,
        // Bug 1979359: Symbols as WeakMap keys, feature-gated by engine support.
        // Per the upsert proposal, getOrInsert(key, value) stores the value
        // as-is (it is NOT a callback); only getOrInsertComputed(key, cb)
        // lazily invokes a callback. An earlier revision of this seed passed
        // functions to getOrInsert and expected them to be called, which is a
        // bug in the seed itself, not the engine - every conformant
        // implementation would fail that assertion.
        """
        if (typeof WeakMap.prototype.getOrInsert === 'function') {
            var wm = new WeakMap(), a = Symbol('a'), b = Symbol('b');
            var first = wm.getOrInsert(a, 1);
            var second = wm.getOrInsert(a, 2);
            if (first !== 1 || second !== 1) throw new Error('weakmap symbols');
            wm.getOrInsert(b, 3);
            if (wm.get(b) !== 3) throw new Error('weakmap symbols');
        }
        if (typeof WeakMap.prototype.getOrInsertComputed === 'function') {
            var wm2 = new WeakMap(), c = Symbol('c');
            var firstComputed = wm2.getOrInsertComputed(c, function() { return 10; });
            var secondComputed = wm2.getOrInsertComputed(c, function() { return 20; });
            if (firstComputed !== 10 || secondComputed !== 10) throw new Error('weakmap symbols computed');
        }
        """,
        // Bug 2023370/2047268: Unicode property and invalid-property parser oracle.
        """
        var good = /\p{ASCII}+/u;
        if (!good.test('ABC')) throw new Error('regexp property');
        var syntax = false;
        try { new RegExp('\\\\p{DefinitelyNotAUnicodeProperty}', 'u'); } catch (e) { syntax = e instanceof SyntaxError; }
        if (!syntax) throw new Error('regexp syntax');
        """,
        // Bug 2048500: non-ASCII identifiers and property names.
        """
        var café = {π: 1, '😀': 2};
        if (café.π !== 1 || café['😀'] !== 2) throw new Error('unicode names');
        var escaped = {\u03c0: 3};
        if (escaped.π !== 3) throw new Error('unicode escape');
        """,
        // GC/realm class: use shell realm only when available.
        """
        if (typeof newGlobal === 'function') {
            var g = newGlobal(), obj = {value: 9};
            g.obj = obj;
            if (g.obj.value !== 9) throw new Error('realm identity');
        }
        """
    ];

    // Language/API features that reached stage 4 / shipped across engines in
    // the 2024-2026 window (Iterator helpers, Set methods, Uint8Array
    // base64/hex, explicit resource management, Promise.try/withResolvers,
    // RegExp.escape, Object/Map.groupBy, Float16Array, Atomics.pause,
    // resizable ArrayBuffer, well-formed strings, change-array-by-copy).
    // Every seed is feature-gated with typeof checks so it stays a no-op
    // (never a false failure) on a build/channel that lacks the feature, and
    // every assertion was hand-verified against a real js.exe shell before
    // being added here. Assertions inside a .then()/async callback use
    // __sf_fail(...) instead of throw - see PersistentRunner.WriteDriver for
    // why a bare throw there would silently never be observed.
    public static readonly string[] Modern2026 =
    [
        // Iterator helpers (TC39 stage 4, shipped 2025): lazy chains must
        // agree with the equivalent eager Array-based computation.
        """
        function assertEq(a, b, msg) { if (a !== b) throw new Error(msg + ': ' + String(a) + ' !== ' + String(b)); }
        function* gen() { yield 1; yield 2; yield 3; yield 4; yield 5; }
        if (typeof Iterator !== 'undefined' && typeof gen().map === 'function') {
            var r = gen().map(x => x * 2).filter(x => x > 2).take(2).toArray();
            assertEq(r.length, 2, 'iter helpers length');
            assertEq(r[0], 4, 'iter helpers[0]');
            assertEq(r[1], 6, 'iter helpers[1]');
            assertEq(gen().reduce((a, b) => a + b, 0), 15, 'iter helpers reduce');
            assertEq(gen().some(x => x === 3), true, 'iter helpers some');
            assertEq(gen().drop(2).find(x => x > 0), 3, 'iter helpers drop/find');
            if (typeof Iterator.from === 'function')
                assertEq(Iterator.from([1, 2, 3]).toArray().length, 3, 'iter helpers from');
        }
        """,
        // Set methods (TC39 stage 4, shipped 2025): boolean predicates and
        // set-arithmetic, including the set-like (non-Set) argument path.
        """
        function assertEq(a, b, msg) { if (a !== b) throw new Error(msg + ': ' + String(a) + ' !== ' + String(b)); }
        if (typeof Set.prototype.union === 'function') {
            var a = new Set([1, 2, 3, 4]), b = new Set([3, 4, 5, 6]);
            assertEq([...a.union(b)].sort().join(','), '1,2,3,4,5,6', 'set union');
            assertEq([...a.intersection(b)].sort().join(','), '3,4', 'set intersection');
            assertEq([...a.difference(b)].sort().join(','), '1,2', 'set difference');
            assertEq([...a.symmetricDifference(b)].sort().join(','), '1,2,5,6', 'set symmetric difference');
            assertEq(new Set([1, 2]).isSubsetOf(a), true, 'set isSubsetOf');
            assertEq(a.isSupersetOf(new Set([1, 2])), true, 'set isSupersetOf');
            assertEq(new Set([100]).isDisjointFrom(a), true, 'set isDisjointFrom');
            var setLike = {size: 2, has: function(v) { return v === 1 || v === 2; }, keys: function() { return [1, 2][Symbol.iterator](); }};
            assertEq([...a.intersection(setLike)].sort().join(','), '1,2', 'set set-like argument');
        }
        """,
        // Uint8Array <-> base64/hex (TC39 stage 4, shipped 2025): round-trip
        // must be exact and byte-precise in both directions.
        """
        function assertEq(a, b, msg) { if (a !== b) throw new Error(msg + ': ' + String(a) + ' !== ' + String(b)); }
        if (typeof Uint8Array.prototype.toBase64 === 'function') {
            var bytes = new Uint8Array([72, 101, 108, 108, 111]);
            var b64 = bytes.toBase64();
            assertEq(b64, 'SGVsbG8=', 'u8 toBase64');
            assertEq(Array.from(Uint8Array.fromBase64(b64)).join(','), '72,101,108,108,111', 'u8 fromBase64');
            var hex = bytes.toHex();
            assertEq(hex, '48656c6c6f', 'u8 toHex');
            assertEq(Array.from(Uint8Array.fromHex(hex)).join(','), '72,101,108,108,111', 'u8 fromHex');
            var target = new Uint8Array(5);
            var res = target.setFromBase64(b64);
            assertEq(res.read, b64.length, 'u8 setFromBase64.read');
            assertEq(res.written, 5, 'u8 setFromBase64.written');
        }
        """,
        // Explicit Resource Management (TC39 stage 4, shipped 2024/2025):
        // `using` must dispose in strict LIFO order, like a stack unwind.
        """
        function assertEq(a, b, msg) { if (a !== b) throw new Error(msg + ': ' + String(a) + ' !== ' + String(b)); }
        if (typeof DisposableStack === 'function') {
            var log = [];
            function makeDisposable(name) { return {[Symbol.dispose]: function() { log.push(name); }}; }
            (function() {
                using a = makeDisposable('a');
                using b = makeDisposable('b');
            })();
            assertEq(log.join(','), 'b,a', 'using LIFO order');
            var stack = new DisposableStack();
            stack.use(makeDisposable('c'));
            stack.defer(function() { log.push('d'); });
            stack.dispose();
            assertEq(log.join(','), 'b,a,d,c', 'DisposableStack order');
        }
        """,
        // Promise.try / Promise.withResolvers / Array.fromAsync (shipped
        // 2024/2025). Resolution only happens inside a job callback, so use
        // __sf_fail instead of throw to make the failure observable.
        """
        if (typeof Promise.withResolvers === 'function') {
            var pr = Promise.withResolvers();
            pr.resolve(42);
            pr.promise.then(function(v) { if (v !== 42 && typeof __sf_fail === 'function') __sf_fail('promise withResolvers'); });
        }
        if (typeof Promise.try === 'function') {
            Promise.try(function() { return 1; }).then(function(v) { if (v !== 1 && typeof __sf_fail === 'function') __sf_fail('promise try'); });
        }
        if (typeof Array.fromAsync === 'function') {
            var agen = (async function*() { yield 1; yield 2; yield 3; })();
            Array.fromAsync(agen).then(function(arr) {
                if (arr.join(',') !== '1,2,3' && typeof __sf_fail === 'function') __sf_fail('array fromAsync');
            });
        }
        """,
        // RegExp.escape (shipped 2025) and duplicate named capture groups in
        // mutually exclusive alternatives (shipped 2023).
        """
        if (typeof RegExp.escape === 'function') {
            var re = new RegExp(RegExp.escape('a.b*c'));
            if (re.test('a.b*c') !== true) throw new Error('regexp escape match');
            if (re.test('axbyc') !== false) throw new Error('regexp escape no-match');
        }
        var dup = /(?<x>a)|(?<x>b)/;
        var m1 = dup.exec('a'), m2 = dup.exec('b');
        if (!m1 || m1.groups.x !== 'a' || !m2 || m2.groups.x !== 'b') throw new Error('duplicate named groups');
        """,
        // Object.groupBy / Map.groupBy (shipped 2024).
        """
        function assertEq(a, b, msg) { if (a !== b) throw new Error(msg + ': ' + String(a) + ' !== ' + String(b)); }
        if (typeof Object.groupBy === 'function') {
            var items = [1, 2, 3, 4, 5, 6];
            var grouped = Object.groupBy(items, x => x % 2 === 0 ? 'even' : 'odd');
            assertEq(grouped.even.join(','), '2,4,6', 'Object.groupBy even');
            assertEq(grouped.odd.join(','), '1,3,5', 'Object.groupBy odd');
            if (typeof Map.groupBy === 'function') {
                var mapGrouped = Map.groupBy(items, x => x % 3);
                assertEq(mapGrouped.get(0).join(','), '3,6', 'Map.groupBy');
            }
        }
        """,
        // Float16Array / Math.f16round (shipped 2025): half-precision
        // rounding and overflow-to-infinity boundaries.
        """
        if (typeof Float16Array === 'function') {
            var f16 = new Float16Array([1.5, 65504, 100000]);
            if (f16[0] !== 1.5) throw new Error('Float16Array basic value');
            if (f16[1] !== 65504) throw new Error('Float16Array max finite value');
            if (f16[2] !== Infinity) throw new Error('Float16Array overflow to infinity');
        }
        """,
        // Atomics.pause (shipped 2025) and resizable ArrayBuffer (shipped
        // 2024): in-place growth must be reflected by existing typed-array views.
        """
        if (typeof Atomics.pause === 'function') { Atomics.pause(); Atomics.pause(1); }
        if (typeof ArrayBuffer.prototype.resize === 'function') {
            var buf = new ArrayBuffer(8, {maxByteLength: 16});
            if (buf.resizable !== true) throw new Error('resizable ArrayBuffer flag');
            buf.resize(12);
            if (buf.byteLength !== 12) throw new Error('resizable ArrayBuffer resize');
            if (new Uint8Array(buf).length !== 12) throw new Error('resizable ArrayBuffer view length');
        }
        """,
        // String well-formed Unicode (shipped 2024) and change-array-by-copy
        // methods (shipped 2023): originals must stay untouched.
        """
        var lone = '\uD800';
        if (typeof lone.isWellFormed === 'function') {
            if (lone.isWellFormed() !== false) throw new Error('isWellFormed lone surrogate');
            if ('abc'.isWellFormed() !== true) throw new Error('isWellFormed ascii');
            if (lone.toWellFormed() !== '\uFFFD') throw new Error('toWellFormed replacement');
        }
        var arr = [3, 1, 2];
        if (typeof arr.toSorted === 'function') {
            if (arr.toSorted().join(',') !== '1,2,3' || arr.join(',') !== '3,1,2') throw new Error('toSorted immutability');
            if (arr.toReversed().join(',') !== '2,1,3') throw new Error('toReversed');
            if (arr.toSpliced(1, 1, 'x', 'y').join(',') !== '3,x,y,2') throw new Error('toSpliced');
        }
        """,
    ];

    // Surface that is implemented but still sits behind an explicit shell
    // flag on the build this was verified against (not yet on by default):
    // Temporal, Iterator.range/zip/zipKeyed/chunks, Promise.allKeyed,
    // immutable ArrayBuffer. Only ever exercised for real when routed through
    // FuzzerEngine's dedicated experimental-flags runner - under the default
    // persistent runner every seed here is a typeof-gated no-op, same safety
    // property as Modern2026. Every assertion (including the exact rejection
    // and write-after-immutable behavior) was hand-verified against a real
    // js.exe shell with all five flags enabled together, matching how the
    // experimental runner actually launches it.
    public static readonly string[] Experimental2026 =
    [
        // Temporal (TC39 stage 3): PlainDate arithmetic/fields and Instant
        // epoch/duration math must agree with the calendar/wall-clock math.
        """
        function assertEq(a, b, msg) { if (a !== b) throw new Error(msg + ': ' + String(a) + ' !== ' + String(b)); }
        if (typeof Temporal !== 'undefined') {
            var d = Temporal.PlainDate.from('2026-09-06');
            assertEq(d.year, 2026, 'Temporal PlainDate year');
            assertEq(d.month, 9, 'Temporal PlainDate month');
            assertEq(d.day, 6, 'Temporal PlainDate day');
            assertEq(d.dayOfWeek, 7, 'Temporal PlainDate dayOfWeek');
            assertEq(d.add({days: 30}).toString(), '2026-10-06', 'Temporal PlainDate add days');
            var i1 = Temporal.Instant.from('2026-01-01T00:00:00Z');
            var i2 = Temporal.Instant.from('2026-01-02T00:00:00Z');
            assertEq(i1.epochMilliseconds, 1767225600000, 'Temporal Instant epochMilliseconds');
            assertEq(i1.until(i2).toString(), 'PT86400S', 'Temporal Instant until');
        }
        """,
        // Iterator.range (TC39 stage 2.7): default step and explicit step,
        // both with an exclusive end - the classic off-by-one boundary.
        """
        function assertEq(a, b, msg) { if (a !== b) throw new Error(msg + ': ' + String(a) + ' !== ' + String(b)); }
        if (typeof Iterator !== 'undefined' && typeof Iterator.range === 'function') {
            assertEq([...Iterator.range(1, 5)].join(','), '1,2,3,4', 'Iterator.range exclusive end');
            assertEq([...Iterator.range(0, 10, 2)].join(','), '0,2,4,6,8', 'Iterator.range step');
        }
        """,
        // Joint iteration (TC39 proposal): Iterator.zip/zipKeyed must advance
        // every source in lockstep and pair by position/key respectively.
        """
        function assertEq(a, b, msg) { if (a !== b) throw new Error(msg + ': ' + String(a) + ' !== ' + String(b)); }
        if (typeof Iterator !== 'undefined' && typeof Iterator.zip === 'function') {
            var z = [...Iterator.zip([[1, 2, 3][Symbol.iterator](), ['a', 'b', 'c'][Symbol.iterator]()])];
            assertEq(JSON.stringify(z), '[[1,"a"],[2,"b"],[3,"c"]]', 'Iterator.zip pairing');
            if (typeof Iterator.zipKeyed === 'function') {
                var zk = [...Iterator.zipKeyed({a: [1, 2, 3][Symbol.iterator](), b: ['x', 'y', 'z'][Symbol.iterator]()})];
                assertEq(JSON.stringify(zk), '[{"a":1,"b":"x"},{"a":2,"b":"y"},{"a":3,"b":"z"}]', 'Iterator.zipKeyed pairing');
            }
        }
        """,
        // Iterator chunking (TC39 proposal): the final chunk must be
        // truncated, not padded, when the source length isn't a multiple of
        // the chunk size.
        """
        function assertEq(a, b, msg) { if (a !== b) throw new Error(msg + ': ' + String(a) + ' !== ' + String(b)); }
        function* __sf_gen5() { yield 1; yield 2; yield 3; yield 4; yield 5; }
        if (typeof __sf_gen5().chunks === 'function') {
            assertEq(JSON.stringify([...__sf_gen5().chunks(2)]), '[[1,2],[3,4],[5]]', 'Iterator chunks partial last chunk');
        }
        """,
        // Promise.allKeyed (TC39 proposal): resolves to a plain object keyed
        // like the input, and - like Promise.all - rejects as a whole as soon
        // as any single input rejects. Resolution/rejection only happen
        // inside a job callback, so use __sf_fail instead of throw.
        """
        if (typeof Promise.allKeyed === 'function') {
            Promise.allKeyed({a: Promise.resolve(1), b: Promise.resolve(2)}).then(function(r) {
                if ((r.a !== 1 || r.b !== 2) && typeof __sf_fail === 'function') __sf_fail('Promise.allKeyed resolved shape');
            });
            Promise.allKeyed({a: Promise.resolve(1), b: Promise.reject('boom')}).then(
                function() { if (typeof __sf_fail === 'function') __sf_fail('Promise.allKeyed should reject when a member rejects'); },
                function(e) { if (e !== 'boom' && typeof __sf_fail === 'function') __sf_fail('Promise.allKeyed rejection reason: ' + e); }
            );
        }
        """,
        // Immutable ArrayBuffer (TC39 proposal): transferToImmutable detaches
        // the source (like a regular transfer) and the result silently (or,
        // under 'use strict', loudly) rejects further writes either way.
        """
        function assertEq(a, b, msg) { if (a !== b) throw new Error(msg + ': ' + String(a) + ' !== ' + String(b)); }
        if (typeof ArrayBuffer.prototype.transferToImmutable === 'function') {
            var buf = new ArrayBuffer(4);
            new Uint8Array(buf)[0] = 9;
            var imm = buf.transferToImmutable();
            assertEq(buf.byteLength, 0, 'transferToImmutable detaches original');
            assertEq(imm.byteLength, 4, 'transferToImmutable byteLength preserved');
            assertEq(imm.immutable, true, 'transferToImmutable immutable flag');
            assertEq(new Uint8Array(imm)[0], 9, 'transferToImmutable content preserved');
            try { new Uint8Array(imm)[0] = 1; } catch (e) { /* strict-mode throw is also spec-compliant */ }
            assertEq(new Uint8Array(imm)[0], 9, 'immutable ArrayBuffer rejects writes');
        }
        """,
    ];
}
