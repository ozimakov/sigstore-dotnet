using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Sigstore.Crypto;

/// <summary>
/// Helpers for reading Sigstore / Fulcio-specific X.509 extensions.
/// OID semantics are documented in
/// <see href="https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md">fulcio oid-info</see>.
/// </summary>
public static class X509Extensions
{
    /// <summary>
    /// Fulcio OID for OIDC issuer (legacy string form).
    /// </summary>
    public const string OidcIssuerOidLegacy = "1.3.6.1.4.1.57264.1.1";

    /// <summary>
    /// Fulcio OID for OIDC issuer (RFC 5280 extension value, UTF-8 string).
    /// </summary>
    public const string OidcIssuerOid = "1.3.6.1.4.1.57264.1.8";

    /// <summary>
    /// Fulcio OID for raw OIDC token <c>sub</c> claim (UTF-8 string).
    /// </summary>
    public const string OidcTokenSubjectOid = "1.3.6.1.4.1.57264.1.24";

    /// <summary>
    /// OtherName SAN type OID used by Fulcio for workload identities.
    /// </summary>
    public const string FulcioOtherNameOid = "1.3.6.1.4.1.57264.1.7";

    /// <summary>
    /// Attempts to read a UTF-8 string from a Fulcio custom extension (OIDs ending in <c>.8</c> and <c>.24</c>).
    /// </summary>
    /// <param name="certificate">Certificate to inspect.</param>
    /// <param name="oidValue">Dot-notation OID.</param>
    /// <param name="value">Decoded string when present.</param>
    /// <returns><c>true</c> when the extension exists and could be decoded.</returns>
    public static bool TryGetFulcioStringExtension(X509Certificate2 certificate, string oidValue, out string value)
    {
        value = string.Empty;
        foreach (X509Extension extension in certificate.Extensions)
        {
            if (extension.Oid?.Value != oidValue)
            {
                continue;
            }

            if (TryDecodeDerUtf8String(extension.RawData, out string decoded))
            {
                value = decoded;
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Collects URI values from the Subject Alternative Name extension.
    /// Includes both standard URI SANs and Fulcio OtherName SANs (OID 1.3.6.1.4.1.57264.1.7).
    /// </summary>
    /// <param name="certificate">Certificate to inspect.</param>
    /// <returns>URIs present in the SAN extension.</returns>
    public static IReadOnlyList<string> GetSubjectAlternativeNameUris(X509Certificate2 certificate)
    {
        List<string> uris = new List<string>();
        foreach (X509Extension extension in certificate.Extensions)
        {
            if (extension.Oid?.Value != "2.5.29.17")
            {
                continue;
            }

            ParseSanExtension(extension.RawData, uris);
        }

        return uris;
    }

    private static void ParseSanExtension(byte[] rawData, List<string> uris)
    {
        try
        {
            // SubjectAlternativeName ::= SEQUENCE OF GeneralName
            AsnReader sanReader = new AsnReader(rawData, AsnEncodingRules.DER);
            AsnReader sequenceReader = sanReader.ReadSequence();

            while (sequenceReader.HasData)
            {
                Asn1Tag tag = sequenceReader.PeekTag();

                if (tag.TagClass == TagClass.ContextSpecific && tag.TagValue == 6)
                {
                    // [6] uniformResourceIdentifier — IA5String
                    string uri = sequenceReader.ReadCharacterString(UniversalTagNumber.IA5String, tag);
                    uris.Add(uri);
                }
                else if (tag.TagClass == TagClass.ContextSpecific && tag.TagValue == 0)
                {
                    // [0] otherName — SEQUENCE { type-id OID, value [0] EXPLICIT ANY }
                    ReadOnlyMemory<byte> otherNameBytes = sequenceReader.ReadEncodedValue();
                    TryParseOtherName(otherNameBytes, uris);
                }
                else
                {
                    // Skip other GeneralName types (rfc822Name, dNSName, etc.)
                    sequenceReader.ReadEncodedValue();
                }
            }
        }
        catch (CryptographicException)
        {
            // Fallback: use Format() for SANs we can't parse
            AsnEncodedData data = new AsnEncodedData("2.5.29.17", rawData);
            string formatted = data.Format(false);
            string[] parts = formatted.Split(new[] { '\n', '\r', ',' }, StringSplitOptions.RemoveEmptyEntries);
            for (int i = 0; i < parts.Length; i++)
            {
                string part = parts[i].Trim();
                if (part.StartsWith("URL=", StringComparison.OrdinalIgnoreCase))
                {
                    uris.Add(part.Substring(4).Trim());
                }
            }
        }
    }

    private static void TryParseOtherName(ReadOnlyMemory<byte> otherNameBytes, List<string> uris)
    {
        try
        {
            AsnReader otherNameReader = new AsnReader(otherNameBytes, AsnEncodingRules.DER);
            AsnReader inner = otherNameReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));

            // Read type-id OID
            string oid = inner.ReadObjectIdentifier();
            if (oid != FulcioOtherNameOid)
            {
                return;
            }

            // Read [0] EXPLICIT value
            AsnReader valueReader = inner.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
            string value = valueReader.ReadCharacterString(UniversalTagNumber.UTF8String);
            if (!string.IsNullOrEmpty(value))
            {
                uris.Add(value);
            }
        }
        catch (CryptographicException)
        {
            // Not a parseable OtherName — skip
        }
    }

    /// <summary>
    /// Returns the first URI identity string suitable for comparing against <c>--certificate-identity</c>.
    /// </summary>
    /// <param name="certificate">Leaf certificate.</param>
    /// <param name="identity">SAN URI or empty.</param>
    /// <returns><c>true</c> when a URI SAN exists.</returns>
    public static bool TryGetPrimaryIdentityUri(X509Certificate2 certificate, out string identity)
    {
        IReadOnlyList<string> uris = GetSubjectAlternativeNameUris(certificate);
        if (uris.Count > 0)
        {
            identity = uris[0];
            return true;
        }

        identity = string.Empty;
        return false;
    }

    private static bool TryDecodeDerUtf8String(byte[] rawData, out string value)
    {
        value = string.Empty;
        try
        {
            AsnReader outer = new AsnReader(rawData, AsnEncodingRules.DER);
            if (outer.PeekTag().HasSameClassAndValue(Asn1Tag.PrimitiveOctetString))
            {
                AsnReader inner = new AsnReader(outer.ReadOctetString(), AsnEncodingRules.DER);
                return TryReadUtf8String(inner, out value);
            }

            return TryReadUtf8String(outer, out value);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static bool TryReadUtf8String(AsnReader reader, out string value)
    {
        value = string.Empty;
        try
        {
            value = reader.ReadCharacterString(UniversalTagNumber.UTF8String);
            return true;
        }
        catch (CryptographicException)
        {
            try
            {
                value = reader.ReadCharacterString(UniversalTagNumber.PrintableString);
                return true;
            }
            catch (CryptographicException)
            {
                return false;
            }
        }
    }
}
