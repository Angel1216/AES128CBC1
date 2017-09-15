# Nombre de microservicio

Microservicio que propociona la función de llevar a cabo el proceso de encriptación de una cadena a través de un AES a 128 bits.
## Uso

Para poder ejecutar el microservicio, es necesario configurar el JDK con unas dependencias del Java Cryptography Extension (JCE), el cual se descarga directamente de la pagina de Oracle, a través de la siguiente liga:

```
http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html
```

Las dependencias son los siguientes:

```
local_policy.jar
US_export_policy.jar
```

Estás dependencias, se tendrán que colocar dentro de la carpeta /jre/lib/security dentro de tu JDK.


Instalar las dependencias mediante

En caso de que se quieran saltar las pruebas unitarias aplicar este comando con mvn 

```
mvn clean package -Dmaven.test.skip=true
```

En caso de que no requiera saltar pruebas unitarias realizar este comando

```
mvn clean package
```

## Variables de ambiente

Previo a la ejecucion del programa es necesario configurar variables de ambiente



```
PROTOCOLO=http
PUERTO=80
HOSTNAME=200.39.24.141
BASEPATH=/BEO
```

### Puerto donde se encuentra este microservicio

```
server.port=8080 
```

## Ejecucion
```
java -jar microservicio-0.0.1-SNAPSHOT.jar
```
