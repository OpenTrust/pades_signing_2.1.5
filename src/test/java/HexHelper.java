import org.bouncycastle.util.encoders.Hex;


public class HexHelper {

	public static String encode(byte[] data) {
		return new String(Hex.encode(data));
	}

}
