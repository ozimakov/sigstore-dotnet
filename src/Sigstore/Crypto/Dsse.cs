using System.Text;
using Sigstore.Exceptions;

namespace Sigstore.Crypto;

/// <summary>
/// DSSE pre-authentication encoding (PAE) per the DSSE envelope specification referenced by Sigstore bundles.
/// </summary>
public static class Dsse
{
    /// <summary>
    /// Computes PAE(payloadType, payload) bytes.
    /// </summary>
    /// <param name="payloadType">DSSE payload type string.</param>
    /// <param name="payload">Raw payload bytes.</param>
    /// <returns>PAE bytes that are signed by DSSE.</returns>
    public static byte[] PreAuthenticationEncoding(string payloadType, ReadOnlySpan<byte> payload)
    {
        const string label = "DSSEv1";
        if (payloadType is null)
        {
            throw new SignatureVerificationException("Step 8 (signature): DSSE payload type is required.");
        }

        byte[] typeUtf8 = Encoding.UTF8.GetBytes(payloadType);
        StringBuilder sb = new StringBuilder();
        sb.Append(label);
        sb.Append(' ');
        sb.Append(typeUtf8.Length.ToString());
        sb.Append(' ');
        sb.Append(payloadType);
        sb.Append(' ');
        sb.Append(payload.Length.ToString());
        sb.Append(' ');
        byte[] prefix = Encoding.UTF8.GetBytes(sb.ToString());
        byte[] result = new byte[prefix.Length + payload.Length];
        prefix.CopyTo(result, 0);
        payload.CopyTo(result.AsSpan(prefix.Length));
        return result;
    }
}
