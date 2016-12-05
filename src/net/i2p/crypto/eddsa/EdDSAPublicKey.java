/**
 * EdDSA-Java by str4d
 *
 * To the extent possible under law, the person who associated CC0 with
 * EdDSA-Java has waived all copyright and related or neighboring rights
 * to EdDSA-Java.
 *
 * You should have received a copy of the CC0 legalcode along with this
 * work. If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.
 *
 */
package net.i2p.crypto.eddsa;

import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import net.i2p.crypto.eddsa.math.GroupElement;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

/**
 * An EdDSA public key.
 *<p>
 * Warning: Public key encoding is is based on the current curdle WG draft,
 * and is subject to change. See getEncoded().
 *</p><p>
 * Ref: https://tools.ietf.org/html/draft-ietf-curdle-pkix-03
 *</p>
 * @author str4d
 *
 */
public class EdDSAPublicKey implements EdDSAKey, PublicKey {
    private static final long serialVersionUID = 9837459837498475L;
    private final GroupElement A;
    private final GroupElement Aneg;
    private final byte[] Abyte;
    private final EdDSAParameterSpec edDsaSpec;

    // OID 1.3.101.xxx
    private static final int OID_OLD = 100;
    private static final int OID_ED25519 = 112;
    private static final int OID_BYTE = 8;

    public EdDSAPublicKey(EdDSAPublicKeySpec spec) {
        this.A = spec.getA();
        this.Aneg = spec.getNegativeA();
        this.Abyte = this.A.toByteArray();
        this.edDsaSpec = spec.getParams();
    }

    public EdDSAPublicKey(X509EncodedKeySpec spec) throws InvalidKeySpecException {
        this(new EdDSAPublicKeySpec(decode(spec.getEncoded()),
                                    EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.CURVE_ED25519_SHA512)));
    }

    @Override
    public String getAlgorithm() {
        return KEY_ALGORITHM;
    }

    @Override
    public String getFormat() {
        return "X.509";
    }

    /**
     * This implements the following specs:
     *<ul><li>
     * General encoding: https://tools.ietf.org/html/draft-ietf-curdle-pkix-03
     *</li></li>
     * Key encoding: https://tools.ietf.org/html/draft-irtf-cfrg-eddsa-08
     *</li></ul>
     * quote:
     *<pre>
     *  In the X.509 certificate, the subjectPublicKeyInfo field has the
     *  SubjectPublicKeyInfo type, which has the following ASN.1 syntax:
     *
     *  SubjectPublicKeyInfo  ::=  SEQUENCE  {
     *    algorithm         AlgorithmIdentifier,
     *    subjectPublicKey  BIT STRING
     *  }
     *</pre>
     *
     *<pre>
     *  AlgorithmIdentifier  ::=  SEQUENCE  {
     *    algorithm   OBJECT IDENTIFIER,
     *    parameters  ANY DEFINED BY algorithm OPTIONAL
     *  }
     *
     *  For all of the OIDs, the parameters MUST be absent.
     *</pre>
     *
     *<pre>
     *  id-Ed25519   OBJECT IDENTIFIER ::= { 1 3 101 112 }
     *</pre>
     *
     * @return 44 bytes for Ed25519, null for other curves
     */
    @Override
    public byte[] getEncoded() {
        if (!edDsaSpec.equals(EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.CURVE_ED25519_SHA512)))
            return null;
        int totlen = 12 + Abyte.length;
        byte[] rv = new byte[totlen];
        int idx = 0;
        // sequence
        rv[idx++] = 0x30;
        rv[idx++] = (byte) (10 + Abyte.length);
        // Algorithm Identifier
        // sequence
        rv[idx++] = 0x30;
        rv[idx++] = 5;
        // OID
        // https://msdn.microsoft.com/en-us/library/windows/desktop/bb540809%28v=vs.85%29.aspx
        rv[idx++] = 0x06;
        rv[idx++] = 3;
        rv[idx++] = (1 * 40) + 3;
        rv[idx++] = 101;
        rv[idx++] = (byte) OID_ED25519;
        // params - absent
        // the key
        rv[idx++] = 0x03; // bit string
        rv[idx++] = (byte) (1 + Abyte.length);
        rv[idx++] = 0; // number of trailing unused bits
        System.arraycopy(Abyte, 0, rv, idx, Abyte.length);
        return rv;
    }

    /**
     * This will decode data conforming to the current spec at
     * https://tools.ietf.org/html/draft-ietf-curdle-pkix-03
     * or the old spec at
     * https://tools.ietf.org/html/draft-josefsson-pkix-eddsa-04.
     *
     * This is really dumb for now. It does not use a general-purpose ASN.1 decoder
     * See also getEncoded().
     *
     * @return 32 bytes for Ed25519, throws for other curves
     */
    private static byte[] decode(byte[] d) throws InvalidKeySpecException {
        try {
            int idx = 0;
            int totlen = 42;
            int idlen = 5;
            int doid = d[OID_BYTE];
            if (doid == OID_OLD) {
                totlen = 47;
                idlen = 8;
            } else if (doid != OID_ED25519) {
                throw new InvalidKeySpecException("unsupported key spec");
            }
            if (d[idx++] != 0x30 ||
                d[idx++] != totlen ||
                d[idx++] != 0x30 ||
                d[idx++] != idlen ||
                d[idx++] != 0x06 ||
                d[idx++] != 3 ||
                d[idx++] != (1 * 40) + 3 ||
                d[idx++] != 101) {
                throw new InvalidKeySpecException("unsupported key spec");
            }
            idx++; // oid, checked above
            // parameters only with old OID
            if (doid == OID_OLD) {
                if (d[idx++] != 0x0a ||
                    d[idx++] != 1 ||
                    d[idx++] != 1) {
                    throw new InvalidKeySpecException("unsupported key spec");
                }
            }
            if (d[idx++] != 0x03 ||
                d[idx++] != 33 ||
                d[idx++] != 0) {
                throw new InvalidKeySpecException("unsupported key spec");
            }
            byte[] rv = new byte[32];
            System.arraycopy(d, idx, rv, 0, 32);
            return rv;
        } catch (IndexOutOfBoundsException ioobe) {
            throw new InvalidKeySpecException(ioobe);
        }
    }

    @Override
    public EdDSAParameterSpec getParams() {
        return edDsaSpec;
    }

    public GroupElement getA() {
        return A;
    }

    public GroupElement getNegativeA() {
        return Aneg;
    }

    public byte[] getAbyte() {
        return Abyte;
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(Abyte);
    }

    @Override
    public boolean equals(Object o) {
        if (o == this)
            return true;
        if (!(o instanceof EdDSAPublicKey))
            return false;
        EdDSAPublicKey pk = (EdDSAPublicKey) o;
        return Arrays.equals(Abyte, pk.getAbyte()) &&
               edDsaSpec.equals(pk.getParams());
    }
}
