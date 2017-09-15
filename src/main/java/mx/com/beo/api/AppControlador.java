package mx.com.beo.api;

import java.util.Map;
import java.util.Date;
import java.util.HashMap;
import java.text.SimpleDateFormat;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import mx.com.beo.util.HeadersParser;
import mx.com.beo.util.PBKDF2AES;

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

@RestController
public class AppControlador {

	private static final Logger LOGGER = LoggerFactory.getLogger(AppControlador.class);

	/**
     * Servicio para encriptar la cadena con el estándar avanzanzado de encripción (AES).
     * @param numero-cliente es el número de cliente que sera utilizado para encriptar con el formato "fecha|cuenta|numero-cliente".
     * @param cuenta es el número de cuenta que sera utilizado para encriptar con el formato "fecha|cuenta|numero-cliente".
     * 
     * @return la cadena encriptada con AES en base64.
     * @throws si la encriptación falla.
     */
	@SuppressWarnings("unchecked")
	@RequestMapping(value = "/detalleFondos", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<Object> detalleFondos(RequestEntity<Object> request) {
		
		LOGGER.info("EndPoint detalleFondos");
		
		// Variables
		Map<String, Object> responseError = new HashMap<String, Object>();
		Map<String, Object> mapBody = (Map<String, Object>) request.getBody();
		Map<String, Object> responseEncryption = new HashMap<String, Object>();
		Map<String, Object> mapaHeadersAValidar = new HashMap<String, Object>();
		Map<String, String> mmapHeader = (Map<String, String>) request.getHeaders().toSingleValueMap();
		String cadenaCifrada = "";
		String cadenaOriginal = "";
		PBKDF2AES PBKDF2AES_128 = new PBKDF2AES();
		HeadersParser headersParser = new HeadersParser();
		SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		String fecha = simpleDateFormat.format(new Date());

		
		//ValidaHeaders
		mapaHeadersAValidar.put("numero-cliente", "idPersona");
				
		try{
			//ValidaHeaders
			headersParser.validaHeaders(mapaHeadersAValidar,request);
		} catch (Exception HeaderNotFoundException) {
			LOGGER.error(HeaderNotFoundException.getMessage());
			responseError = new HashMap<String, Object>();
			responseError.put("responseStatus", 400);
			responseError.put("responseError", HeaderNotFoundException.getMessage());
			return new ResponseEntity<>(responseError,HttpStatus.OK);
		}
		
		try {
			// Encriptar
			cadenaOriginal = fecha+"|"+mapBody.get("cuenta").toString()+"|"+mmapHeader.get("numero-cliente").toString();
			cadenaCifrada = PBKDF2AES_128.encrypt(cadenaOriginal);
			
			responseEncryption.put("encryption", cadenaCifrada);
			responseEncryption.put("responseStatus", 200);
			responseEncryption.put("responseError", "");
		} catch (Exception exception) {
			LOGGER.error(exception.getMessage());
			responseError = new HashMap<String, Object>();
			responseError.put("responseStatus", 500);
			responseError.put("responseError", exception.getMessage());
			return new ResponseEntity<>(responseError,HttpStatus.OK);
		}
		
		return new ResponseEntity<>(responseEncryption,HttpStatus.OK);
		
	}
}
