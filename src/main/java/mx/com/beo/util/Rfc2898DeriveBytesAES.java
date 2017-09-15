package mx.com.beo.util;

import java.security.NoSuchAlgorithmException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;

import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Mac;


/**
* Copyright (c)  2017 Nova Solution Systems S.A. de C.V.
* Mexico D.F.
* Todos los derechos reservados.
*
* @author Angel Martínez León
*
* ESTE SOFTWARE ES INFORMACIÓN CONFIDENCIAL. PROPIEDAD DE NOVA SOLUTION SYSTEMS.
* ESTA INFORMACIÓN NO DEBE SER DIVULGADA Y PUEDE SOLAMENTE SER UTILIZADA DE ACUERDO CON LOS TÉRMINOS DETERMINADOS POR LA EMPRESA SÍ MISMA.
*/
public class Rfc2898DeriveBytesAES {

	// Atributos
    private Mac _hmacSha1;
    private byte[] _salt;
    private int _iterationCount;

    private byte[] _buffer = new byte[20];
    private int _bufferStartIndex = 0;
    private int _bufferEndIndex = 0;
    private int _block = 1;

    
    /**
     * Crea una nueva instancia.
     * @param contraseña La contraseña utilizada para derivar la clave.
     * @param salt El salto de clave utilizada para derivar la clave.
     * @param Iteraciones El número de iteraciones para la operación.
     * @throws NoSuchAlgorithmException HmacSHA1 Algoritmo no se puede encontrar.
     * @throws InvalidKeyException El salto debe ser de 8 bytes o mas. - o - La contraseña no puede ser null.
     */
    public Rfc2898DeriveBytesAES(byte[] password, byte[] salt, int iterations) throws NoSuchAlgorithmException, InvalidKeyException {
    	if ((salt == null) || (salt.length < 8)) { throw new InvalidKeyException("Salt must be 8 bytes or more."); }
    	if (password == null) { throw new InvalidKeyException("Password cannot be null."); }
        this._salt = salt;
        this._iterationCount = iterations;
        this._hmacSha1 = Mac.getInstance("HmacSHA1");
        this._hmacSha1.init(new SecretKeySpec(password, "HmacSHA1"));
    }
    
    /**
     * Crea una nueva instancia.
     * @param contraseña La contraseña utilizada para derivar la clave.
     * @param salt El salto de clave utilizada para derivar la clave.
     * @param Iteraciones El número de iteraciones para la operación.
     * @throws NoSuchAlgorithmException HmacSHA1 Algoritmo no se puede encontrar.
     * @throws InvalidKeyException El salto debe ser de 8 bytes o mas. - o - La contraseña no puede ser null.
     * @throws UnsupportedEncodingException UTF-8 encoding no es soportado. 
     */
    public Rfc2898DeriveBytesAES(String password, byte[] salt, int iterations) throws InvalidKeyException, NoSuchAlgorithmException, UnsupportedEncodingException  {
    	this(password.getBytes("UTF8"), salt, iterations);
    }

    /**
     * Crea una nueva instancia.
     * @param contraseña La contraseña utilizada para derivar la clave.
     * @param salt El salto de clave utilizada para derivar la clave.
     * @throws NoSuchAlgorithmException HmacSHA1 Algoritmo no se puede encontrar.
     * @throws InvalidKeyException El salto debe ser de 8 bytes o mas. - o - La contraseña no puede ser null.
     * @throws UnsupportedEncodingException UTF-8 encoding no es soportado. 
     */
    public Rfc2898DeriveBytesAES(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException {
    	this(password, salt, 0x3e8);
    }


    /**
     * Retorna un número aleatorio de la clave de la contraseña, salto e cuenta de iteración.
     * @param Cuenta del numero de bytes a devolver
     * @return Byte array.
     */
    public byte[] getBytes(int count) {
        byte[] result = new byte[count];
        int resultOffset = 0;
        int bufferCount = this._bufferEndIndex - this._bufferStartIndex;

        if (bufferCount > 0) { //if there is some data in buffer
            if (count < bufferCount) { //if there is enough data in buffer
            	System.arraycopy(this._buffer, this._bufferStartIndex, result, 0, count);
                this._bufferStartIndex += count;
                return result;
            }
            System.arraycopy(this._buffer, this._bufferStartIndex, result, 0, bufferCount);
            this._bufferStartIndex = this._bufferEndIndex = 0;
            resultOffset += bufferCount;
        }

        while (resultOffset < count) {
            int needCount = count - resultOffset;
            this._buffer = this.func();
            if (needCount > 20) { //we one (or more) additional passes
            	System.arraycopy(this._buffer, 0, result, resultOffset, 20);
                resultOffset += 20;
            } else {
            	System.arraycopy(this._buffer, 0, result, resultOffset, needCount);
                this._bufferStartIndex = needCount;
                this._bufferEndIndex = 20;
                return result;
            }
        }
        return result;
    }

    /**
     * Returns a finalHash key from a password, salt and iteration count.
     * Devuelve una clave finalHash de una contraseña, salto e iteración.
     * @return Byte array.
     */
    private byte[] func() {
        this._hmacSha1.update(this._salt, 0, this._salt.length);
        byte[] tempHash = this._hmacSha1.doFinal(getBytesFromInt(this._block));

        this._hmacSha1.reset();
        byte[] finalHash = tempHash;
        for (int i = 2; i <= this._iterationCount; i++) {
            tempHash = this._hmacSha1.doFinal(tempHash);
            for (int j = 0; j < 20; j++) {
                finalHash[j] = (byte)(finalHash[j] ^ tempHash[j]);
            }
        }
        if (this._block == 2147483647) {
            this._block = -2147483648;
        } else {
            this._block += 1;
        }

        return finalHash;
    }

    /**
     * Retorna una llave de array de Bytes.
     * @param un valor de tipo entero
     * @return Byte array.
     */
    private static byte[] getBytesFromInt(int i) {
    	return new byte[] { (byte)(i >>> 24), (byte)(i >>> 16), (byte)(i >>> 8), (byte)i };
    }
	
}