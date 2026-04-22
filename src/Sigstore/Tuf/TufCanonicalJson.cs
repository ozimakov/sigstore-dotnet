using System.Globalization;
using System.Text;
using System.Text.Json;

namespace Sigstore.Tuf;

/// <summary>
/// Produces a deterministic UTF-8 encoding of TUF <c>signed</c> metadata objects suitable for signature
/// verification. This follows the same structural rules as the secure-systems-lab reference
/// (<see href="https://github.com/secure-systems-lab/go-securesystemslib">go-securesystemslib</see> canonical JSON):
/// objects have lexicographically sorted keys, no insignificant whitespace, and stable array ordering.
/// </summary>
public static class TufCanonicalJson
{
    /// <summary>
    /// Canonicalizes the <c>signed</c> element of a TUF metadata document to UTF-8 bytes.
    /// </summary>
    /// <param name="signed">The <c>signed</c> JSON object.</param>
    /// <returns>Canonical UTF-8 payload hashed by TUF signatures.</returns>
    public static byte[] EncodeSigned(JsonElement signed)
    {
        if (signed.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidOperationException("TUF signed payload must be a JSON object.");
        }

        StringBuilder sb = new StringBuilder();
        WriteValue(signed, sb);
        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    private static void WriteValue(JsonElement element, StringBuilder sb)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                WriteObject(element, sb);
                break;
            case JsonValueKind.Array:
                WriteArray(element, sb);
                break;
            case JsonValueKind.String:
                WriteString(element.GetString() ?? string.Empty, sb);
                break;
            case JsonValueKind.Number:
                WriteNumber(element, sb);
                break;
            case JsonValueKind.True:
                sb.Append("true");
                break;
            case JsonValueKind.False:
                sb.Append("false");
                break;
            case JsonValueKind.Null:
                sb.Append("null");
                break;
            default:
                throw new InvalidOperationException("Unsupported JSON value kind for TUF canonical encoding.");
        }
    }

    private static void WriteObject(JsonElement obj, StringBuilder sb)
    {
        List<string> names = new List<string>();
        foreach (JsonProperty p in obj.EnumerateObject())
        {
            names.Add(p.Name);
        }

        names.Sort(StringComparer.Ordinal);

        sb.Append('{');
        for (int i = 0; i < names.Count; i++)
        {
            if (i > 0)
            {
                sb.Append(',');
            }

            WriteString(names[i], sb);
            sb.Append(':');
            WriteValue(obj.GetProperty(names[i]), sb);
        }

        sb.Append('}');
    }

    private static void WriteArray(JsonElement arr, StringBuilder sb)
    {
        sb.Append('[');
        int idx = 0;
        foreach (JsonElement child in arr.EnumerateArray())
        {
            if (idx++ > 0)
            {
                sb.Append(',');
            }

            WriteValue(child, sb);
        }

        sb.Append(']');
    }

    private static void WriteNumber(JsonElement number, StringBuilder sb)
    {
        if (number.TryGetInt64(out long l))
        {
            sb.Append(l.ToString(CultureInfo.InvariantCulture));
            return;
        }

        if (number.TryGetDouble(out double d))
        {
            sb.Append(d.ToString("G17", CultureInfo.InvariantCulture));
            return;
        }

        if (number.TryGetDecimal(out decimal m))
        {
            sb.Append(m.ToString(CultureInfo.InvariantCulture));
            return;
        }

        sb.Append(number.GetRawText());
    }

    private static void WriteString(string text, StringBuilder sb)
    {
        // securesystemslib canonical JSON only escapes \ and " in strings.
        // All other characters (including control chars like newline, tab) are literal.
        sb.Append('"');
        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            if (c == '\\')
            {
                sb.Append("\\\\");
            }
            else if (c == '"')
            {
                sb.Append("\\\"");
            }
            else
            {
                sb.Append(c);
            }
        }

        sb.Append('"');
    }
}
