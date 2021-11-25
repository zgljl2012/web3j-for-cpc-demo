package io.cpchain;

import java.math.BigInteger;
import java.security.SignatureException;
import java.util.List;

import org.web3j.crypto.Hash;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;
import org.web3j.rlp.RlpDecoder;
import org.web3j.rlp.RlpEncoder;
import org.web3j.rlp.RlpList;
import org.web3j.rlp.RlpString;
import org.web3j.rlp.RlpType;
import org.web3j.utils.Numeric;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Unit test for simple App.
 */
public class AppTest extends TestCase {
    int CHAIN_ID_INC = 35;
    int LOWER_REAL_V = 27;

    /**
     * Create the test case
     *
     * @param testName name of the test case
     */
    public AppTest(String testName) {
        super(testName);
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite() {
        return new TestSuite(AppTest.class);
    }

    // Copy from
    // https://github.com/web3j/web3j/blob/49fe2c4e2d9d325ec465879736d6c384f41a4115/crypto/src/main/java/org/web3j/crypto/SignatureDataOperations.java#L46
    byte getRealV(BigInteger bv) {
        long v = bv.longValue();
        if (v == LOWER_REAL_V || v == (LOWER_REAL_V + 1)) {
            return (byte) v;
        }
        byte realV = (byte) LOWER_REAL_V;
        int inc = 0;
        if ((int) v % 2 == 0) {
            inc = 1;
        }
        return (byte) (realV + inc);
    }

    /**
     * Rigourous Test :-)
     * 
     * @throws SignatureException
     */
    public void testPraseFrom() throws SignatureException {
        String rawTxHex = "0xf86f" + "80" + "80" + "850430e23400" + "825208"
                + "9403fd5c822a7aba0c1684ce8b12bff78208a17d79" + "884563918244f40000" + "80" + "8202c5"
                + "a079d831dd0fcb7a2054e607b73a262b4a23a2824f1c91b3fe36b64dbb8f2becc9"
                + "a034ffbe277717bf8e93d0d7372f8f1bf988b40d3aa1115ee68d142167ecf93781";
        final byte[] transaction = Numeric.hexStringToByteArray(rawTxHex);
        final RlpList rlpList = RlpDecoder.decode(transaction);
        final RlpList values = (RlpList) rlpList.getValues().get(0);

        // Get parameters
        BigInteger type = ((RlpString) values.getValues().get(0)).asPositiveBigInteger();
        BigInteger nonce = ((RlpString) values.getValues().get(1)).asPositiveBigInteger();
        BigInteger gasPrice = ((RlpString) values.getValues().get(2)).asPositiveBigInteger();
        BigInteger gasLimit = ((RlpString) values.getValues().get(3)).asPositiveBigInteger();
        String to = ((RlpString) values.getValues().get(4)).asString();
        BigInteger value = ((RlpString) values.getValues().get(5)).asPositiveBigInteger();
        byte[] input = ((RlpString) values.getValues().get(6)).getBytes();
        String data = Numeric.toHexString(input);

        // Get R S V
        byte[] v = ((RlpString) values.getValues().get(7)).getBytes();
        BigInteger r = ((RlpString) values.getValues().get(8)).asPositiveBigInteger();
        BigInteger s = ((RlpString) values.getValues().get(9)).asPositiveBigInteger();
        System.out.println("v=" + ((RlpString) values.getValues().get(7)).asString());
        System.out.println("r=" + ((RlpString) values.getValues().get(8)).asString());
        System.out.println("s=" + ((RlpString) values.getValues().get(9)).asString());

        // Calculate the Hash of the Tx
        // Please read
        // https://github.com/ethereum/go-ethereum/blob/master/core/types/transaction_signing.go#L300
        List<RlpType> originTxParameters = values.getValues().subList(0, 7);
        originTxParameters.add(RlpString.create(BigInteger.valueOf((long)337))); // chainID
        originTxParameters.add(RlpString.create(BigInteger.valueOf((long)0)));
        originTxParameters.add(RlpString.create(BigInteger.valueOf((long)0)));
        RlpList originTx = new RlpList(originTxParameters);
        byte[] bOriginTx = RlpEncoder.encode(originTx);
        byte[] hashBytes = Hash.sha3(bOriginTx);
        String hash = Numeric.toHexString(hashBytes);

        // Output parameters of the Tx
        System.out.println("hash=" + hash);
        System.out.println("type=" + type);
        System.out.println("nonce=" + nonce);
        System.out.println("gasPrice=" + gasPrice);
        System.out.println("gasLimit=" + gasLimit);
        System.out.println("to=" + to);
        System.out.println("value=" + value);
        System.out.println("input=" + new String(input));
        System.out.println("data=" + data);

        // Build the signature
        Sign.SignatureData signatureData = new Sign.SignatureData(getRealV(Numeric.toBigInt(v)), Numeric.toBytesPadded(r, 32),
                Numeric.toBytesPadded(s, 32));

        // Get public key
        BigInteger publicKey = Sign.signedMessageHashToKey(Numeric.hexStringToByteArray(hash), signatureData);

        // Output the FROM address from public key
        System.out.println("\n---->>>FROM: 0x" + Keys.getAddress(publicKey));
    }
}
