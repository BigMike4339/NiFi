// Version: 0.0.2

/*
Обязательный property: encrypted_pass
Обязательный property или атрибут: encrypted_fields

Пример конфига в атрибуте encrypted_fields:
[
    {
        "name": "phone",
        "type": 1
    },
    {
        "name": "birthdate",
        "type": 2
    },
    {
        "name": "name",
        "type": 3
    },
    {
        "name": "email",
        "type": 4
    }
]

*/

import org.apache.commons.io.IOUtils
import java.nio.charset.StandardCharsets
import groovy.json.*

import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import java.security.Key
import java.security.NoSuchAlgorithmException
import java.util.Base64

def flowFile = session.get()
if (!flowFile) return

public static String getDecryptedValue(String value, String encryptionKey) {
    //return value
    String decValue = null
    try {
        Key aesKey = new SecretKeySpec(encryptionKey.getBytes("UTF-8"), "AES")
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE, aesKey)
        decValue = new String(cipher.doFinal(Base64.decoder.decode(value)), StandardCharsets.UTF_8)
    } catch (NoSuchAlgorithmException e) {
        e.printStackTrace()
    }
    return decValue
}

try {
    flowFile = session.write(flowFile,
        { inputStream, outputStream ->
            def content = IOUtils.toString(inputStream, StandardCharsets.UTF_8)
            def content_list = new JsonSlurper().parseText(content)
            def result_list = []

            // get attributes and parameters
            def encrypted_fields = flowFile.getAttribute('encrypted_fields')
            if (!encrypted_fields) {
                encrypted_fields = context.getProperty('encrypted_fields').getValue()
            }
            if (!encrypted_fields) {
                log.error('encrypted_fields is null')
                return
            }
            def l = new JsonSlurper().parseText(encrypted_fields)

            // get sensitive parameter
            password = context.getProperty('encrypted_pass').evaluateAttributeExpressions().getValue()
            if (!password) {
                log.error('encrypted_pass is null')
                return
            }

            content_list.each { map ->
                map.each { entry ->
                    l.each { a ->
                        if (entry.key == a.name && (entry.value) ) {
                            entry.value = getDecryptedValue(entry.value, password)
                        }
                    }
                }
                result_list << map
            }

            json_out = new JsonGenerator.Options()
                                    .disableUnicodeEscaping()
                                    .build()
                                    .toJson(result_list)

            outputStream.write(json_out.getBytes(StandardCharsets.UTF_8))
        } as StreamCallback)
    session.transfer(flowFile, REL_SUCCESS)
} catch (Exception e) {
    log.error('Error during JSON operations', e)
    session.transfer(flowFile, REL_FAILURE)
}
