using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;

namespace ProctorAIDetective.Core
{
    /// <summary>
    /// Thrown when input is not well-formed JSON. Carries the 1-based line and column of the
    /// offending character so a user who hand-edits signatures.json can find their mistake.
    /// </summary>
    public sealed class JsonParseException : Exception
    {
        public int Line { get; private set; }
        public int Column { get; private set; }

        public JsonParseException(string message, int line, int column)
            : base(string.Format(CultureInfo.InvariantCulture,
                   "JSON error at line {0}, column {1}: {2}", line, column, message))
        {
            Line = line;
            Column = column;
        }
    }

    public enum JsonKind
    {
        Null = 0,
        Bool = 1,
        Number = 2,
        String = 3,
        Array = 4,
        Object = 5
    }

    /// <summary>
    /// One node of a parsed JSON document. Deliberately forgiving on READ: asking an object for
    /// a key it does not have, or indexing past the end of an array, returns
    /// <see cref="Missing"/> rather than throwing. That is what lets the signature loader walk a
    /// hand-edited file without a try/catch around every field access, which is the difference
    /// between "one typo disables detection" and "one typo drops one field".
    /// </summary>
    public sealed class JsonValue
    {
        private JsonKind _kind;
        private bool _missing;
        private bool _bool;
        private double _num;
        private long _int;
        private bool _hasInt;
        private string _str = "";
        private List<JsonValue>? _items;
        private List<KeyValuePair<string, JsonValue>>? _members;
        private Dictionary<string, int>? _index;

        private static readonly JsonValue s_null = MakeNull(false);
        private static readonly JsonValue s_missing = MakeNull(true);
        private static readonly JsonValue s_true = MakeBool(true);
        private static readonly JsonValue s_false = MakeBool(false);
        private static readonly string[] s_noKeys = new string[0];
        private static readonly JsonValue[] s_noItems = new JsonValue[0];

        private JsonValue() { }

        /// <summary>The JSON literal null.</summary>
        public static JsonValue Null { get { return s_null; } }

        /// <summary>
        /// Returned for an absent key or an out-of-range index. Reports <see cref="IsNull"/>
        /// true as well, so a caller that only cares "is there a usable value here" needs one check.
        /// </summary>
        public static JsonValue Missing { get { return s_missing; } }

        private static JsonValue MakeNull(bool missing)
        {
            var v = new JsonValue();
            v._kind = JsonKind.Null;
            v._missing = missing;
            return v;
        }

        private static JsonValue MakeBool(bool b)
        {
            var v = new JsonValue();
            v._kind = JsonKind.Bool;
            v._bool = b;
            return v;
        }

        internal static JsonValue FromBool(bool b) { return b ? s_true : s_false; }

        internal static JsonValue FromString(string s)
        {
            var v = new JsonValue();
            v._kind = JsonKind.String;
            v._str = s ?? "";
            return v;
        }

        internal static JsonValue FromNumber(double num, long integral, bool hasIntegral)
        {
            var v = new JsonValue();
            v._kind = JsonKind.Number;
            v._num = num;
            v._int = integral;
            v._hasInt = hasIntegral;
            return v;
        }

        internal static JsonValue FromArray(List<JsonValue> items)
        {
            var v = new JsonValue();
            v._kind = JsonKind.Array;
            v._items = items;
            return v;
        }

        internal static JsonValue FromObject(List<KeyValuePair<string, JsonValue>> members,
                                             Dictionary<string, int> index)
        {
            var v = new JsonValue();
            v._kind = JsonKind.Object;
            v._members = members;
            v._index = index;
            return v;
        }

        public JsonKind Kind { get { return _kind; } }

        public bool IsObject { get { return _kind == JsonKind.Object; } }
        public bool IsArray { get { return _kind == JsonKind.Array; } }
        public bool IsString { get { return _kind == JsonKind.String; } }
        public bool IsNumber { get { return _kind == JsonKind.Number; } }
        public bool IsBool { get { return _kind == JsonKind.Bool; } }
        public bool IsNull { get { return _kind == JsonKind.Null; } }

        /// <summary>True only for the sentinel returned by a failed lookup, never for a literal null.</summary>
        public bool IsMissing { get { return _missing; } }

        /// <summary>Members for an object, elements for an array, 0 for anything else.</summary>
        public int Count
        {
            get
            {
                if (_kind == JsonKind.Array) return _items == null ? 0 : _items.Count;
                if (_kind == JsonKind.Object) return _members == null ? 0 : _members.Count;
                return 0;
            }
        }

        /// <summary>Case-sensitive member lookup. Returns <see cref="Missing"/> when absent.</summary>
        public JsonValue this[string key]
        {
            get { return Get(key, false); }
        }

        public JsonValue this[int i]
        {
            get
            {
                if (_kind != JsonKind.Array || _items == null) return s_missing;
                if (i < 0 || i >= _items.Count) return s_missing;
                return _items[i];
            }
        }

        /// <summary>
        /// Member lookup, optionally case-insensitive. JSON itself is case-sensitive and the
        /// exact lookup is the default; the lenient form exists for hand-edited config, where
        /// "Version" instead of "version" should not silently lose a field.
        /// </summary>
        public JsonValue Get(string key, bool ignoreCase)
        {
            if (_kind != JsonKind.Object || _members == null || _index == null || key == null)
                return s_missing;

            int at;
            if (_index.TryGetValue(key, out at)) return _members[at].Value;

            if (ignoreCase)
            {
                for (int i = 0; i < _members.Count; i++)
                {
                    if (string.Equals(_members[i].Key, key, StringComparison.OrdinalIgnoreCase))
                        return _members[i].Value;
                }
            }
            return s_missing;
        }

        public bool Has(string key)
        {
            if (_kind != JsonKind.Object || _index == null || key == null) return false;
            return _index.ContainsKey(key);
        }

        /// <summary>Member names in document order. Empty for non-objects.</summary>
        public IEnumerable<string> Keys
        {
            get
            {
                if (_kind != JsonKind.Object || _members == null) return s_noKeys;
                var keys = new List<string>(_members.Count);
                for (int i = 0; i < _members.Count; i++) keys.Add(_members[i].Key);
                return keys;
            }
        }

        /// <summary>Array elements, or object member values, in document order.</summary>
        public IEnumerable<JsonValue> Items
        {
            get
            {
                if (_kind == JsonKind.Array && _items != null) return _items;
                if (_kind == JsonKind.Object && _members != null)
                {
                    var vals = new List<JsonValue>(_members.Count);
                    for (int i = 0; i < _members.Count; i++) vals.Add(_members[i].Value);
                    return vals;
                }
                return s_noItems;
            }
        }

        /// <summary>Object members in document order, for callers that need both name and value.</summary>
        public IEnumerable<KeyValuePair<string, JsonValue>> Members
        {
            get
            {
                if (_kind == JsonKind.Object && _members != null) return _members;
                return new KeyValuePair<string, JsonValue>[0];
            }
        }

        public string AsString(string def = "")
        {
            switch (_kind)
            {
                case JsonKind.String: return _str;
                case JsonKind.Number: return NumberText();
                case JsonKind.Bool: return _bool ? "true" : "false";
                default: return def;
            }
        }

        public bool AsBool(bool def = false)
        {
            switch (_kind)
            {
                case JsonKind.Bool:
                    return _bool;
                case JsonKind.Number:
                    return _hasInt ? _int != 0 : (_num != 0.0 && !double.IsNaN(_num));
                case JsonKind.String:
                    if (_str.Equals("true", StringComparison.OrdinalIgnoreCase) ||
                        _str.Equals("yes", StringComparison.OrdinalIgnoreCase) ||
                        _str == "1") return true;
                    if (_str.Equals("false", StringComparison.OrdinalIgnoreCase) ||
                        _str.Equals("no", StringComparison.OrdinalIgnoreCase) ||
                        _str == "0") return false;
                    return def;
                default:
                    return def;
            }
        }

        public long AsLong(long def = 0)
        {
            if (_kind == JsonKind.Number)
            {
                if (_hasInt) return _int;
                if (double.IsNaN(_num) || double.IsInfinity(_num)) return def;
                if (_num < -9.2233720368547758E18 || _num > 9.2233720368547758E18) return def;
                return (long)Math.Round(_num, MidpointRounding.AwayFromZero);
            }
            if (_kind == JsonKind.Bool) return _bool ? 1 : 0;
            if (_kind == JsonKind.String)
            {
                long r;
                if (long.TryParse(_str, NumberStyles.Integer, CultureInfo.InvariantCulture, out r)) return r;
            }
            return def;
        }

        public int AsInt(int def = 0)
        {
            long v = AsLong(long.MinValue);
            if (v == long.MinValue) return def;
            if (v < int.MinValue || v > int.MaxValue) return def;
            return (int)v;
        }

        public double AsDouble(double def = 0)
        {
            if (_kind == JsonKind.Number) return _hasInt ? (double)_int : _num;
            if (_kind == JsonKind.Bool) return _bool ? 1 : 0;
            if (_kind == JsonKind.String)
            {
                double r;
                if (double.TryParse(_str, NumberStyles.Float, CultureInfo.InvariantCulture, out r)) return r;
            }
            return def;
        }

        /// <summary>
        /// Array-of-strings convenience. A bare string is treated as a one-element list, since
        /// that is the mistake a human editing signatures.json actually makes. Empty strings are
        /// dropped; nothing is trimmed, because a signature value may legitimately BE a
        /// whitespace-class codepoint - that evasion is the entire reason this app exists.
        /// </summary>
        public List<string> AsStringList()
        {
            var list = new List<string>();
            if (_kind == JsonKind.String)
            {
                if (_str.Length > 0) list.Add(_str);
                return list;
            }
            if (_kind != JsonKind.Array || _items == null) return list;
            for (int i = 0; i < _items.Count; i++)
            {
                JsonValue item = _items[i];
                if (item.IsNull) continue;
                string s = item.AsString("");
                if (s.Length > 0) list.Add(s);
            }
            return list;
        }

        /// <summary>Array-of-ints convenience. Non-numeric elements are skipped.</summary>
        public List<int> AsIntList()
        {
            var list = new List<int>();
            if (_kind != JsonKind.Array || _items == null) return list;
            for (int i = 0; i < _items.Count; i++)
            {
                JsonValue item = _items[i];
                if (!item.IsNumber) continue;
                list.Add(item.AsInt());
            }
            return list;
        }

        private string NumberText()
        {
            if (_hasInt) return _int.ToString(CultureInfo.InvariantCulture);
            return MiniJson.FormatDouble(_num);
        }

        /// <summary>Re-serialise this node. Useful for echoing a sub-tree into an export.</summary>
        public string ToJson(bool pretty)
        {
            return MiniJson.Write(this, pretty);
        }

        public override string ToString()
        {
            return MiniJson.Write(this, false);
        }

        internal void WriteTo(StringBuilder sb, bool pretty, int indent, int depth)
        {
            switch (_kind)
            {
                case JsonKind.Null:
                    sb.Append("null");
                    return;
                case JsonKind.Bool:
                    sb.Append(_bool ? "true" : "false");
                    return;
                case JsonKind.Number:
                    sb.Append(NumberText());
                    return;
                case JsonKind.String:
                    MiniJson.WriteQuoted(sb, _str);
                    return;
                case JsonKind.Array:
                    MiniJson.WriteArray(sb, _items, pretty, indent, depth);
                    return;
                case JsonKind.Object:
                    MiniJson.WriteMembers(sb, _members, pretty, indent, depth);
                    return;
            }
        }
    }

    /// <summary>
    /// An insertion-ordered object for the writer. <c>Dictionary&lt;string,object&gt;</c> happens
    /// to enumerate in insertion order today, but that is an implementation detail and not a
    /// guarantee; this makes the ordering contractual, so an exported report diffs cleanly
    /// between two runs.
    /// </summary>
    public sealed class JsonObjectBuilder : IEnumerable<KeyValuePair<string, object?>>
    {
        private readonly List<KeyValuePair<string, object?>> _items =
            new List<KeyValuePair<string, object?>>();

        public int Count { get { return _items.Count; } }

        /// <summary>Appends a member. Duplicate keys are allowed; both are emitted, in order.</summary>
        public JsonObjectBuilder Add(string key, object? value)
        {
            _items.Add(new KeyValuePair<string, object?>(key ?? "", value));
            return this;
        }

        /// <summary>Appends only when <paramref name="condition"/> holds.</summary>
        public JsonObjectBuilder AddIf(bool condition, string key, object? value)
        {
            if (condition) Add(key, value);
            return this;
        }

        public IEnumerator<KeyValuePair<string, object?>> GetEnumerator() { return _items.GetEnumerator(); }

        IEnumerator IEnumerable.GetEnumerator() { return _items.GetEnumerator(); }
    }

    /// <summary>
    /// A dependency-free JSON reader and writer for net48, which has no System.Text.Json.
    ///
    /// WHY NOT <c>JavaScriptSerializer</c> (System.Web.Extensions, already referenced):
    ///   - it caps input at 2 MB (MaxJsonLength) and throws past it;
    ///   - it has no pretty-printer, so an exported evidence report is one unreadable line;
    ///   - it emits non-ASCII raw, so U+2800 lands in an export as invisible bytes that mail
    ///     clients, terminals and ticketing systems silently mangle - fatal for this app, whose
    ///     single most important datum is a filename made of U+2800;
    ///   - it reports syntax errors with no position, which is useless for a file users edit;
    ///   - it maps numbers to int/decimal/double by guesswork.
    /// For a tool that makes accusations about people, the serialiser has to be auditable.
    /// This one is about 400 lines and fully under our control.
    /// </summary>
    public static class MiniJson
    {
        /// <summary>Nesting ceiling. Guards against a crafted file causing an uncatchable StackOverflow.</summary>
        public const int MaxDepth = 128;

        // ---------------------------------------------------------------- reading

        /// <summary>Parses a complete JSON document. Throws <see cref="JsonParseException"/> on malformed input.</summary>
        public static JsonValue Parse(string text)
        {
            if (text == null) throw new ArgumentNullException("text");
            return new JsonParser(text).ParseDocument();
        }

        /// <summary>Non-throwing parse. Returns false and fills <paramref name="error"/> on malformed input.</summary>
        public static bool TryParse(string text, out JsonValue value, out string? error)
        {
            try
            {
                value = Parse(text);
                error = null;
                return true;
            }
            catch (JsonParseException ex)
            {
                value = JsonValue.Missing;
                error = ex.Message;
                return false;
            }
            catch (Exception ex)
            {
                value = JsonValue.Missing;
                error = ex.GetType().Name + ": " + ex.Message;
                return false;
            }
        }

        // ---------------------------------------------------------------- writing

        /// <summary>Starts an insertion-ordered object for <see cref="Write"/>.</summary>
        public static JsonObjectBuilder Obj() { return new JsonObjectBuilder(); }

        /// <summary>
        /// Serialises primitives, <see cref="JsonValue"/>, enums, DateTime, dictionaries,
        /// <see cref="JsonObjectBuilder"/> and any IEnumerable. Non-ASCII and control characters
        /// are escaped as \uXXXX, so the output is byte-for-byte portable.
        /// </summary>
        public static string Write(object? value, bool pretty)
        {
            var sb = new StringBuilder(512);
            WriteValue(sb, value, pretty, 0, 0);
            return sb.ToString();
        }

        private static void WriteValue(StringBuilder sb, object? value, bool pretty, int indent, int depth)
        {
            if (depth > MaxDepth)
                throw new InvalidOperationException("JSON nesting exceeded " + MaxDepth + " levels while writing.");

            if (value == null) { sb.Append("null"); return; }

            JsonValue? jv = value as JsonValue;
            if (jv != null) { jv.WriteTo(sb, pretty, indent, depth); return; }

            string? s = value as string;
            if (s != null) { WriteQuoted(sb, s); return; }

            if (value is bool) { sb.Append(((bool)value) ? "true" : "false"); return; }
            if (value is char) { WriteQuoted(sb, value.ToString()); return; }

            // Must precede the TypeCode switch: an enum's TypeCode is its underlying integer type.
            if (value is Enum) { WriteQuoted(sb, value.ToString() ?? ""); return; }

            if (value is DateTime) { WriteQuoted(sb, ((DateTime)value).ToString("o", CultureInfo.InvariantCulture)); return; }
            if (value is DateTimeOffset) { WriteQuoted(sb, ((DateTimeOffset)value).ToString("o", CultureInfo.InvariantCulture)); return; }
            if (value is TimeSpan) { WriteQuoted(sb, ((TimeSpan)value).ToString()); return; }
            if (value is Guid) { WriteQuoted(sb, ((Guid)value).ToString()); return; }

            switch (Type.GetTypeCode(value.GetType()))
            {
                case TypeCode.SByte:
                case TypeCode.Byte:
                case TypeCode.Int16:
                case TypeCode.UInt16:
                case TypeCode.Int32:
                case TypeCode.UInt32:
                case TypeCode.Int64:
                    sb.Append(Convert.ToInt64(value, CultureInfo.InvariantCulture)
                                     .ToString(CultureInfo.InvariantCulture));
                    return;
                case TypeCode.UInt64:
                    sb.Append(Convert.ToUInt64(value, CultureInfo.InvariantCulture)
                                     .ToString(CultureInfo.InvariantCulture));
                    return;
                case TypeCode.Single:
                case TypeCode.Double:
                    sb.Append(FormatDouble(Convert.ToDouble(value, CultureInfo.InvariantCulture)));
                    return;
                case TypeCode.Decimal:
                    sb.Append(((decimal)value).ToString(CultureInfo.InvariantCulture));
                    return;
            }

            // Dictionary<string,T> - including ScanReport.Timings - reaches here.
            IDictionary? dict = value as IDictionary;
            if (dict != null) { WriteDictionary(sb, dict, pretty, indent, depth); return; }

            // JsonObjectBuilder and any ordered pair sequence. Must precede plain IEnumerable.
            IEnumerable<KeyValuePair<string, object?>>? pairs = value as IEnumerable<KeyValuePair<string, object?>>;
            if (pairs != null) { WritePairs(sb, pairs, pretty, indent, depth); return; }

            IEnumerable<KeyValuePair<string, string>>? strPairs = value as IEnumerable<KeyValuePair<string, string>>;
            if (strPairs != null)
            {
                var boxed = new List<KeyValuePair<string, object?>>();
                foreach (KeyValuePair<string, string> kv in strPairs)
                    boxed.Add(new KeyValuePair<string, object?>(kv.Key, kv.Value));
                WritePairs(sb, boxed, pretty, indent, depth);
                return;
            }

            IEnumerable? seq = value as IEnumerable;
            if (seq != null) { WriteSequence(sb, seq, pretty, indent, depth); return; }

            WriteQuoted(sb, Convert.ToString(value, CultureInfo.InvariantCulture) ?? "");
        }

        private static void WriteDictionary(StringBuilder sb, IDictionary dict, bool pretty, int indent, int depth)
        {
            var pairs = new List<KeyValuePair<string, object?>>(dict.Count);
            foreach (DictionaryEntry e in dict)
            {
                string key = Convert.ToString(e.Key, CultureInfo.InvariantCulture) ?? "";
                pairs.Add(new KeyValuePair<string, object?>(key, e.Value));
            }
            WritePairs(sb, pairs, pretty, indent, depth);
        }

        private static void WritePairs(StringBuilder sb, IEnumerable<KeyValuePair<string, object?>> pairs,
                                       bool pretty, int indent, int depth)
        {
            bool first = true;
            int inner = indent + 1;
            foreach (KeyValuePair<string, object?> kv in pairs)
            {
                if (first) { sb.Append('{'); first = false; }
                else sb.Append(',');
                if (pretty) { sb.Append('\n'); Indent(sb, inner); }
                WriteQuoted(sb, kv.Key);
                sb.Append(':');
                if (pretty) sb.Append(' ');
                WriteValue(sb, kv.Value, pretty, inner, depth + 1);
            }
            if (first) { sb.Append("{}"); return; }
            if (pretty) { sb.Append('\n'); Indent(sb, indent); }
            sb.Append('}');
        }

        private static void WriteSequence(StringBuilder sb, IEnumerable seq, bool pretty, int indent, int depth)
        {
            bool first = true;
            int inner = indent + 1;
            foreach (object? item in seq)
            {
                if (first) { sb.Append('['); first = false; }
                else sb.Append(',');
                if (pretty) { sb.Append('\n'); Indent(sb, inner); }
                WriteValue(sb, item, pretty, inner, depth + 1);
            }
            if (first) { sb.Append("[]"); return; }
            if (pretty) { sb.Append('\n'); Indent(sb, indent); }
            sb.Append(']');
        }

        internal static void WriteArray(StringBuilder sb, List<JsonValue>? items, bool pretty, int indent, int depth)
        {
            if (items == null || items.Count == 0) { sb.Append("[]"); return; }
            int inner = indent + 1;
            sb.Append('[');
            for (int i = 0; i < items.Count; i++)
            {
                if (i > 0) sb.Append(',');
                if (pretty) { sb.Append('\n'); Indent(sb, inner); }
                items[i].WriteTo(sb, pretty, inner, depth + 1);
            }
            if (pretty) { sb.Append('\n'); Indent(sb, indent); }
            sb.Append(']');
        }

        internal static void WriteMembers(StringBuilder sb, List<KeyValuePair<string, JsonValue>>? members,
                                          bool pretty, int indent, int depth)
        {
            if (members == null || members.Count == 0) { sb.Append("{}"); return; }
            int inner = indent + 1;
            sb.Append('{');
            for (int i = 0; i < members.Count; i++)
            {
                if (i > 0) sb.Append(',');
                if (pretty) { sb.Append('\n'); Indent(sb, inner); }
                WriteQuoted(sb, members[i].Key);
                sb.Append(':');
                if (pretty) sb.Append(' ');
                members[i].Value.WriteTo(sb, pretty, inner, depth + 1);
            }
            if (pretty) { sb.Append('\n'); Indent(sb, indent); }
            sb.Append('}');
        }

        private static void Indent(StringBuilder sb, int levels)
        {
            for (int i = 0; i < levels; i++) sb.Append("  ");
        }

        private const string HexDigits = "0123456789abcdef";

        /// <summary>
        /// Quotes a string, escaping everything outside printable ASCII. U+2800 therefore leaves
        /// here as the six literal characters \u2800, which survives copy/paste into a bug report
        /// or an HR file - the whole point, given the target names its executable with it.
        /// </summary>
        internal static void WriteQuoted(StringBuilder sb, string? value)
        {
            sb.Append('"');
            if (value != null)
            {
                for (int i = 0; i < value.Length; i++)
                {
                    char c = value[i];
                    switch (c)
                    {
                        case '"': sb.Append("\\\""); continue;
                        case '\\': sb.Append("\\\\"); continue;
                        case '\b': sb.Append("\\b"); continue;
                        case '\f': sb.Append("\\f"); continue;
                        case '\n': sb.Append("\\n"); continue;
                        case '\r': sb.Append("\\r"); continue;
                        case '\t': sb.Append("\\t"); continue;
                    }
                    if (c >= 0x20 && c <= 0x7E)
                    {
                        sb.Append(c);
                    }
                    else
                    {
                        sb.Append("\\u");
                        sb.Append(HexDigits[(c >> 12) & 0xF]);
                        sb.Append(HexDigits[(c >> 8) & 0xF]);
                        sb.Append(HexDigits[(c >> 4) & 0xF]);
                        sb.Append(HexDigits[c & 0xF]);
                    }
                }
            }
            sb.Append('"');
        }

        /// <summary>
        /// Round-trip-safe double formatting. "R" is documented as round-trippable but is
        /// measurably broken for some values on .NET Framework; verify, and fall back to G17.
        /// </summary>
        internal static string FormatDouble(double d)
        {
            if (double.IsNaN(d) || double.IsInfinity(d)) return "null"; // JSON has no NaN/Infinity.
            string r = d.ToString("R", CultureInfo.InvariantCulture);
            double back;
            if (double.TryParse(r, NumberStyles.Float, CultureInfo.InvariantCulture, out back) && back == d)
                return r;
            return d.ToString("G17", CultureInfo.InvariantCulture);
        }

        // ---------------------------------------------------------------- self-test

        /// <summary>
        /// Returns the list of failures; an empty list means everything passed. Wired to the
        /// diagnostics menu so a tester can prove, on the machine in front of them, that the
        /// parser handles the one input that matters most here: a filename made of U+2800.
        /// </summary>
        public static List<string> SelfTest()
        {
            var fail = new List<string>();
            try { RunSelfTest(fail); }
            catch (Exception ex) { fail.Add("self-test aborted: " + ex.GetType().Name + ": " + ex.Message); }
            return fail;
        }

        private static void Check(List<string> fail, bool ok, string what)
        {
            if (!ok) fail.Add(what);
        }

        private static void RunSelfTest(List<string> fail)
        {
            const string Blank = "\u2800";

            // --- 1. U+2800 as an escape sequence, which is how a portable export encodes it.
            JsonValue v = Parse("{\"processNames\":[\"\\u2800.exe\"]}");
            string name = v["processNames"][0].AsString("");
            Check(fail, name.Length == 5, "U+2800 escape: expected 5 chars, got " + name.Length);
            Check(fail, name.Length > 0 && name[0] == '\u2800',
                  "U+2800 escape: first char is U+" + (name.Length > 0 ? ((int)name[0]).ToString("X4") : "??"));
            Check(fail, name == Blank + ".exe", "U+2800 escape: value mismatch");

            // --- 2. U+2800 as a raw UTF-8 character, which is how signatures.json stores it on disk.
            JsonValue raw = Parse("{\"processNames\":[\"" + Blank + ".exe\"]}");
            Check(fail, raw["processNames"][0].AsString("") == Blank + ".exe", "U+2800 raw: value mismatch");

            // --- 3. U+2800 survives write -> re-read, and leaves as an ASCII-safe escape.
            string written = Write(Obj().Add("n", Blank + ".exe"), false);
            Check(fail, written.IndexOf("\\u2800", StringComparison.Ordinal) >= 0,
                  "U+2800 write: expected a \\u2800 escape, got " + written);
            Check(fail, IsAscii(written), "U+2800 write: output contains non-ASCII characters");
            Check(fail, Parse(written)["n"].AsString("") == Blank + ".exe", "U+2800 write: round-trip mismatch");

            // --- 4. Surrogate pairs.
            JsonValue emoji = Parse("[\"\\uD83D\\uDE00\"]");
            string e = emoji[0].AsString("");
            Check(fail, e.Length == 2, "surrogate pair: expected 2 UTF-16 units, got " + e.Length);
            Check(fail, e.Length == 2 && char.IsSurrogatePair(e[0], e[1]) && char.ConvertToUtf32(e[0], e[1]) == 0x1F600,
                  "surrogate pair: did not decode to U+1F600");
            Check(fail, Parse(Write(new List<object?> { e }, false))[0].AsString("") == e,
                  "surrogate pair: round-trip mismatch");
            Check(fail, Parse("[\"\\ud83d\\ude00\"]")[0].AsString("") == e,
                  "surrogate pair: lowercase hex digits");

            // --- 5. All simple escapes, including the optional \/.
            string esc = Parse("[\"a\\\"b\\\\c\\/d\\be\\ff\\ng\\rh\\ti\"]")[0].AsString("");
            Check(fail, esc == "a\"b\\c/d\be\ff\ng\rh\ti", "escapes: got " + Write(esc, false));
            Check(fail, Parse(Write(esc, false)).AsString("") == esc, "escapes: round-trip mismatch");

            // Backslash-heavy path fragments are the single most common thing in signatures.json.
            Check(fail, Parse("[\"\\\\Programs\\\\parakeetai-desktop\\\\\"]")[0].AsString("")
                        == "\\Programs\\parakeetai-desktop\\", "escapes: Windows path fragment");

            // --- 6. Nested arrays and empty containers.
            JsonValue nest = Parse("[[1,[2,[3,[]]]],{},[]]");
            Check(fail, nest.Count == 3, "nested: outer count " + nest.Count);
            Check(fail, nest[0][1][1][0].AsInt(-1) == 3, "nested: deep element");
            Check(fail, nest[1].IsObject && nest[1].Count == 0, "nested: empty object");
            Check(fail, nest[2].IsArray && nest[2].Count == 0, "nested: empty array");
            Check(fail, Write(nest, false) == "[[1,[2,[3,[]]]],{},[]]", "nested: compact re-write mismatch");

            // --- 7. Numbers.
            JsonValue nums = Parse("[0,-0,1,-1,12345678901234,1.5,-2.25,1e3,1.5E-3,0.0,3.0]");
            Check(fail, nums[0].AsInt(-1) == 0, "number: 0");
            Check(fail, nums[3].AsInt(0) == -1, "number: -1");
            Check(fail, nums[4].AsLong(0) == 12345678901234L, "number: long precision");
            Check(fail, Math.Abs(nums[5].AsDouble(0) - 1.5) < 1e-12, "number: 1.5");
            Check(fail, Math.Abs(nums[6].AsDouble(0) + 2.25) < 1e-12, "number: -2.25");
            Check(fail, Math.Abs(nums[7].AsDouble(0) - 1000.0) < 1e-9, "number: exponent 1e3");
            Check(fail, Math.Abs(nums[8].AsDouble(0) - 0.0015) < 1e-12, "number: exponent 1.5E-3");
            Check(fail, nums[10].AsInt(-1) == 3, "number: 3.0 as int");
            Check(fail, Parse("[0.1]")[0].AsDouble(0) == 0.1, "number: 0.1 exact");
            Check(fail, Parse(Write(new List<object?> { 0.1, 1e300, -2.25 }, false))[1].AsDouble(0) == 1e300,
                  "number: large double round-trip");
            Check(fail, Parse("[10240]")[0].AsInt(0) == 10240, "number: 10240 (U+2800 codepoint)");

            // --- 8. Literals and missing-key tolerance.
            JsonValue lit = Parse("{\"t\":true,\"f\":false,\"n\":null}");
            Check(fail, lit["t"].AsBool(false) && !lit["f"].AsBool(true), "literals: true/false");
            Check(fail, lit["n"].IsNull && !lit["n"].IsMissing, "literals: explicit null");
            Check(fail, lit["absent"].IsMissing && lit["absent"].AsString("d") == "d", "missing key: not tolerated");
            Check(fail, lit["absent"]["deeper"][3].IsMissing, "missing key: chained access threw or returned a value");
            Check(fail, lit.Has("t") && !lit.Has("absent"), "Has()");
            Check(fail, Parse("[1]")["key"].IsMissing, "array indexed by string");
            Check(fail, Parse("{\"a\":1}")[7].IsMissing, "object indexed by int");
            Check(fail, Parse("{\"a\":1}").Get("A", true).AsInt(0) == 1, "case-insensitive Get()");
            Check(fail, Parse("{\"a\":1}").Get("A", false).IsMissing, "case-sensitive Get() must not match");

            // --- 9. Key order is preserved on read and on write.
            JsonValue ordered = Parse("{\"z\":1,\"a\":2,\"m\":3}");
            Check(fail, string.Join(",", new List<string>(ordered.Keys).ToArray()) == "z,a,m", "key order: read");
            Check(fail, Write(Obj().Add("z", 1).Add("a", 2).Add("m", 3), false) == "{\"z\":1,\"a\":2,\"m\":3}",
                  "key order: write");

            // --- 10. UTF-8 BOM and surrounding whitespace.
            Check(fail, Parse("\uFEFF{\"a\":1}")["a"].AsInt(0) == 1, "BOM: not tolerated");
            Check(fail, Parse("  \r\n\t{\"a\":1}\r\n ")["a"].AsInt(0) == 1, "leading/trailing whitespace");

            // --- 11. Unknown and "_"-prefixed documentation keys are ignored, never fatal.
            JsonValue unknown = Parse("{\"_comment\":\"doc\",\"version\":\"1\",\"future\":{\"x\":[1,2]}}");
            Check(fail, unknown["version"].AsString("") == "1", "unknown keys: sibling lost");

            // --- 12. Pretty output shape: 2-space indent.
            string pretty = Write(Obj().Add("a", 1).Add("b", new List<object?> { 1, 2 }), true);
            Check(fail, pretty == "{\n  \"a\": 1,\n  \"b\": [\n    1,\n    2\n  ]\n}",
                  "pretty: unexpected layout >>>" + pretty + "<<<");
            Check(fail, Write(Obj(), true) == "{}" && Write(new List<object?>(), true) == "[]",
                  "pretty: empty containers should stay on one line");

            // --- 13. Malformed input reports a position instead of throwing something opaque.
            CheckThrows(fail, "{\"a\":}", "malformed: missing value");
            CheckThrows(fail, "{\"a\":1,}", "malformed: trailing comma");
            CheckThrows(fail, "{\"a\" 1}", "malformed: missing colon");
            CheckThrows(fail, "[1,2", "malformed: unterminated array");
            CheckThrows(fail, "\"abc", "malformed: unterminated string");
            CheckThrows(fail, "{\"a\":1}{", "malformed: trailing content");
            CheckThrows(fail, "[tru]", "malformed: bad literal");
            CheckThrows(fail, "[truex]", "malformed: literal with a suffix");
            CheckThrows(fail, "[\"\\uZZZZ\"]", "malformed: bad unicode escape");
            CheckThrows(fail, "[\"\\q\"]", "malformed: unknown escape");
            CheckThrows(fail, "[01.]", "malformed: no digit after the decimal point");
            CheckThrows(fail, "[1e]", "malformed: no digit in the exponent");
            CheckThrows(fail, "", "malformed: empty input");
            CheckThrows(fail, "   ", "malformed: whitespace-only input");

            // Line/column must actually point at the offending line.
            try
            {
                Parse("{\n  \"a\": 1,\n  \"b\": @\n}");
                fail.Add("malformed: expected a throw for '@'");
            }
            catch (JsonParseException ex)
            {
                Check(fail, ex.Line == 3, "malformed: expected line 3, reported line " + ex.Line);
                Check(fail, ex.Column >= 8, "malformed: column " + ex.Column + " looks wrong for line 3");
            }

            // --- 14. Depth guard: a crafted file must raise a clean error, not a StackOverflow.
            CheckThrows(fail, new string('[', MaxDepth + 10), "malformed: depth guard");

            // --- 15. The built-in signature set survives write -> read, and so does the real
            //         signatures.json when one is deployed next to the exe.
            SelfTestSignatures(fail);
        }

        private static void SelfTestSignatures(List<string> fail)
        {
            const string Blank = "\u2800";

            try
            {
                SignatureSet builtIn = SignatureLoader.Embedded();
                string json = SignatureLoader.ToJson(builtIn, true);
                Check(fail, IsAscii(json), "embedded set: exported JSON is not pure ASCII");

                var warnings = new List<string>();
                SignatureSet back = SignatureLoader.FromJson(json, warnings);

                // Fixed point: re-serialising what we just read must reproduce the same bytes.
                // That proves losslessness far better than counting advisory warnings, which are
                // a property of the DATA (an allowlist row that pins no signer, say) and are
                // supposed to survive a round-trip unchanged rather than disappear.
                string json2 = SignatureLoader.ToJson(back, true);
                Check(fail, json2 == json, "embedded set: write -> read -> write is not a fixed point");

                var warningsAgain = new List<string>();
                SignatureLoader.FromJson(json2, warningsAgain);
                Check(fail, warningsAgain.Count == warnings.Count,
                      "embedded set: the round-trip changed the warning count from " +
                      warnings.Count + " to " + warningsAgain.Count);

                Check(fail, back.Version == builtIn.Version, "embedded set: version lost in round-trip");
                Check(fail, back.Vendors.Count == builtIn.Vendors.Count, "embedded set: vendor count changed");
                Check(fail, back.Allowlist.Count == builtIn.Allowlist.Count, "embedded set: allowlist count changed");
                Check(fail, back.InvisibleCodepoints.Contains(0x2800),
                      "embedded set: U+2800 missing from invisibleCodepoints");

                VendorSignature? p = back.Primary;
                Check(fail, p != null, "embedded set: no primary target after round-trip");
                if (p != null)
                {
                    Check(fail, p.ProcessNames.Contains(Blank + ".exe"),
                          "embedded set: the U+2800 process name did not survive the round-trip");
                    Check(fail, p.CertThumbprints.Contains("59C214EE88435D2AE141B6222519DD9204892F12"),
                          "embedded set: the verified signing thumbprint did not survive the round-trip");
                    Check(fail, p.IsVerified, "embedded set: the primary target lost confidence=verified");
                }
            }
            catch (Exception ex)
            {
                fail.Add("embedded set: " + ex.GetType().Name + ": " + ex.Message);
            }

            string? path = SignatureLoader.FindSignatureFile();
            if (path == null) return; // Nothing deployed yet; that is the loader's problem, not the parser's.

            try
            {
                string text = File.ReadAllText(path);
                JsonValue root = Parse(text);
                Check(fail, root.IsObject, "signatures.json: root is not an object");
                Check(fail, root["version"].AsString("").Length > 0, "signatures.json: no version");
                Check(fail, root["vendors"].Count > 0, "signatures.json: no vendors");
                Check(fail, root["allowlist"].Count >= 20,
                      "signatures.json: only " + root["allowlist"].Count + " allowlist entries");
                Check(fail, root["invisibleCodepoints"].AsIntList().Contains(0x2800),
                      "signatures.json: invisibleCodepoints is missing 10240 (U+2800)");

                bool foundPrimary = false;
                foreach (JsonValue vendor in root["vendors"].Items)
                {
                    if (!vendor["primaryTarget"].AsBool(false)) continue;
                    foundPrimary = true;
                    List<string> names = vendor["processNames"].AsStringList();
                    Check(fail, names.Contains(Blank + ".exe"),
                          "signatures.json: the primary target's U+2800 process name did not parse");
                    break;
                }
                Check(fail, foundPrimary, "signatures.json: no vendor is marked primaryTarget");

                // The whole real file must survive our own writer with its meaning intact.
                string reWritten = Write(root, true);
                Check(fail, IsAscii(reWritten), "signatures.json: re-written export is not pure ASCII");
                JsonValue reParsed = Parse(reWritten);
                Check(fail, Write(reParsed, false) == Write(root, false),
                      "signatures.json: the document is not stable across a write/read cycle");
            }
            catch (Exception ex)
            {
                fail.Add("signatures.json (" + path + "): " + ex.GetType().Name + ": " + ex.Message);
            }
        }

        private static void CheckThrows(List<string> fail, string text, string what)
        {
            try
            {
                Parse(text);
                fail.Add(what + ": expected a JsonParseException, none thrown");
            }
            catch (JsonParseException)
            {
                // expected
            }
            catch (Exception ex)
            {
                fail.Add(what + ": expected JsonParseException, got " + ex.GetType().Name + ": " + ex.Message);
            }
        }

        private static bool IsAscii(string s)
        {
            for (int i = 0; i < s.Length; i++) if (s[i] > 0x7E) return false;
            return true;
        }
    }

    /// <summary>Recursive-descent JSON reader. One instance per document; not thread-safe.</summary>
    internal sealed class JsonParser
    {
        private readonly string _s;
        private int _i;
        private int _line = 1;
        private int _lineStart;

        internal JsonParser(string text)
        {
            _s = text;
        }

        private int Column { get { return _i - _lineStart + 1; } }

        private bool Eof { get { return _i >= _s.Length; } }

        internal JsonValue ParseDocument()
        {
            // A UTF-8 BOM decodes to U+FEFF. File.ReadAllText usually strips it, but text that
            // arrived some other way - clipboard, stream, HTTP body - still carries it.
            if (_s.Length > 0 && _s[0] == '\uFEFF') _i = 1;

            SkipWhitespace();
            if (Eof) throw Error("the document is empty");

            JsonValue value = ParseValue(0);

            SkipWhitespace();
            if (!Eof) throw Error("unexpected content after the top-level value ('" + Describe(_s[_i]) + "')");
            return value;
        }

        private JsonValue ParseValue(int depth)
        {
            if (depth > MiniJson.MaxDepth)
                throw Error("nesting deeper than " + MiniJson.MaxDepth + " levels");

            if (Eof) throw Error("a value was expected");

            char c = _s[_i];
            switch (c)
            {
                case '{': return ParseObject(depth);
                case '[': return ParseArray(depth);
                case '"': return JsonValue.FromString(ParseString());
                case 't': ExpectWord("true"); return JsonValue.FromBool(true);
                case 'f': ExpectWord("false"); return JsonValue.FromBool(false);
                case 'n': ExpectWord("null"); return JsonValue.Null;
                default:
                    if (c == '-' || (c >= '0' && c <= '9')) return ParseNumber();
                    throw Error("a value was expected but found '" + Describe(c) + "'");
            }
        }

        private JsonValue ParseObject(int depth)
        {
            Advance(); // '{'
            var members = new List<KeyValuePair<string, JsonValue>>();
            var index = new Dictionary<string, int>(StringComparer.Ordinal);

            SkipWhitespace();
            if (!Eof && _s[_i] == '}') { Advance(); return JsonValue.FromObject(members, index); }

            while (true)
            {
                SkipWhitespace();
                if (Eof) throw Error("the object was never closed");
                if (_s[_i] != '"')
                    throw Error("a member name in double quotes was expected but found '" + Describe(_s[_i]) + "'");

                string key = ParseString();

                SkipWhitespace();
                if (Eof || _s[_i] != ':')
                    throw Error("':' was expected after the member name \"" + key + "\"");
                Advance();

                SkipWhitespace();
                JsonValue value = ParseValue(depth + 1);

                // Duplicate names: last one wins for lookup, both are kept in document order.
                members.Add(new KeyValuePair<string, JsonValue>(key, value));
                index[key] = members.Count - 1;

                SkipWhitespace();
                if (Eof) throw Error("the object was never closed");
                if (_s[_i] == ',') { Advance(); continue; }
                if (_s[_i] == '}') { Advance(); return JsonValue.FromObject(members, index); }
                throw Error("',' or '}' was expected but found '" + Describe(_s[_i]) + "'");
            }
        }

        private JsonValue ParseArray(int depth)
        {
            Advance(); // '['
            var items = new List<JsonValue>();

            SkipWhitespace();
            if (!Eof && _s[_i] == ']') { Advance(); return JsonValue.FromArray(items); }

            while (true)
            {
                SkipWhitespace();
                items.Add(ParseValue(depth + 1));

                SkipWhitespace();
                if (Eof) throw Error("the array was never closed");
                if (_s[_i] == ',') { Advance(); continue; }
                if (_s[_i] == ']') { Advance(); return JsonValue.FromArray(items); }
                throw Error("',' or ']' was expected but found '" + Describe(_s[_i]) + "'");
            }
        }

        private string ParseString()
        {
            Advance(); // opening quote
            var sb = new StringBuilder();

            while (true)
            {
                if (Eof) throw Error("the string was never closed");
                char c = _s[_i];

                if (c == '"') { Advance(); return sb.ToString(); }

                if (c != '\\')
                {
                    // Raw characters pass straight through, U+2800 included - which is exactly
                    // how signatures.json stores the primary target's executable name on disk.
                    sb.Append(c);
                    Advance();
                    continue;
                }

                Advance(); // backslash
                if (Eof) throw Error("the string ended inside an escape sequence");

                char esc = _s[_i];
                switch (esc)
                {
                    case '"': sb.Append('"'); Advance(); break;
                    case '\\': sb.Append('\\'); Advance(); break;
                    case '/': sb.Append('/'); Advance(); break;
                    case 'b': sb.Append('\b'); Advance(); break;
                    case 'f': sb.Append('\f'); Advance(); break;
                    case 'n': sb.Append('\n'); Advance(); break;
                    case 'r': sb.Append('\r'); Advance(); break;
                    case 't': sb.Append('\t'); Advance(); break;
                    case 'u':
                        {
                            Advance(); // 'u'
                            int cp = ParseHex4();
                            if (cp >= 0xD800 && cp <= 0xDBFF)
                            {
                                // Try to pair it with a following low surrogate.
                                int saveI = _i, saveLine = _line, saveStart = _lineStart;
                                if (_i + 1 < _s.Length && _s[_i] == '\\' && _s[_i + 1] == 'u')
                                {
                                    Advance(); Advance();
                                    int low = ParseHex4();
                                    if (low >= 0xDC00 && low <= 0xDFFF)
                                    {
                                        sb.Append((char)cp);
                                        sb.Append((char)low);
                                        break;
                                    }
                                    // Not a low surrogate: rewind and emit each independently.
                                    _i = saveI; _line = saveLine; _lineStart = saveStart;
                                }
                            }
                            // Lone surrogates and ordinary BMP codepoints alike: one UTF-16 unit.
                            sb.Append((char)cp);
                            break;
                        }
                    default:
                        throw Error("unknown escape sequence '\\" + Describe(esc) + "'");
                }
            }
        }

        private int ParseHex4()
        {
            if (_i + 4 > _s.Length) throw Error("a \\u escape needs four hexadecimal digits");
            int value = 0;
            for (int k = 0; k < 4; k++)
            {
                char c = _s[_i];
                int d;
                if (c >= '0' && c <= '9') d = c - '0';
                else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
                else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
                else throw Error("'" + Describe(c) + "' is not a hexadecimal digit in a \\u escape");
                value = (value << 4) | d;
                Advance();
            }
            return value;
        }

        private JsonValue ParseNumber()
        {
            int start = _i;

            if (!Eof && _s[_i] == '-') Advance();

            int intDigits = 0;
            while (!Eof && _s[_i] >= '0' && _s[_i] <= '9') { Advance(); intDigits++; }
            if (intDigits == 0) throw Error("a digit was expected in the number");

            bool isIntegral = true;

            if (!Eof && _s[_i] == '.')
            {
                isIntegral = false;
                Advance();
                int fracDigits = 0;
                while (!Eof && _s[_i] >= '0' && _s[_i] <= '9') { Advance(); fracDigits++; }
                if (fracDigits == 0) throw Error("a digit was expected after the decimal point");
            }

            if (!Eof && (_s[_i] == 'e' || _s[_i] == 'E'))
            {
                isIntegral = false;
                Advance();
                if (!Eof && (_s[_i] == '+' || _s[_i] == '-')) Advance();
                int expDigits = 0;
                while (!Eof && _s[_i] >= '0' && _s[_i] <= '9') { Advance(); expDigits++; }
                if (expDigits == 0) throw Error("a digit was expected in the exponent");
            }

            string text = _s.Substring(start, _i - start);

            if (isIntegral)
            {
                long l;
                if (long.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out l))
                    return JsonValue.FromNumber((double)l, l, true);
            }

            double d;
            if (!double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out d))
                throw Error("'" + text + "' is not a number this platform can represent");

            // An integer too wide for long still reports as integral if it is in range as a double.
            if (isIntegral && d >= -9.2233720368547758E18 && d <= 9.2233720368547758E18)
                return JsonValue.FromNumber(d, (long)d, true);

            return JsonValue.FromNumber(d, 0, false);
        }

        private void ExpectWord(string word)
        {
            for (int k = 0; k < word.Length; k++)
            {
                if (_i + k >= _s.Length || _s[_i + k] != word[k])
                    throw Error("'" + word + "' was expected");
            }
            for (int k = 0; k < word.Length; k++) Advance();

            // "trueX" must not parse as true.
            if (!Eof)
            {
                char c = _s[_i];
                if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_')
                    throw Error("'" + word + "' was expected");
            }
        }

        private void SkipWhitespace()
        {
            while (!Eof)
            {
                char c = _s[_i];
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') Advance();
                else return;
            }
        }

        private void Advance()
        {
            if (_i >= _s.Length) return;
            if (_s[_i] == '\n')
            {
                _line++;
                _i++;
                _lineStart = _i;
            }
            else
            {
                _i++;
            }
        }

        private static string Describe(char c)
        {
            if (c >= 0x20 && c <= 0x7E) return c.ToString();
            return "U+" + ((int)c).ToString("X4", CultureInfo.InvariantCulture);
        }

        private JsonParseException Error(string message)
        {
            return new JsonParseException(message, _line, Column);
        }
    }
}
