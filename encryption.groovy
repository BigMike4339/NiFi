// Version: 0.0.1

/*
Обязательный property: encrypted_pass
Обязательный property или атрибут: encrypted_fields

Необязательные property:
need_normalyze (false) - необходимость нормализация полей;
need_debug_phone (false) - в выходные данные добавляются поля с исходным значением и флагом успешности нормализации;
need_debug_email (false) - в выходные данные добавляются поля с исходным значением и флагом успешности нормализации.

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

def flowFile = session.get()
if (!flowFile) return

public static String getEncryptedValue(String value, String encryptionKey) {
    //return value
    String generatedValue = null
    try {
        Key aesKey = new SecretKeySpec(encryptionKey.getBytes('UTF-8'), 'AES')
        Cipher cipher = Cipher.getInstance('AES/ECB/PKCS5Padding')
        cipher.init(Cipher.ENCRYPT_MODE, aesKey)
        generatedValue = cipher.doFinal(value.getBytes('UTF-8')).encodeBase64()
    } catch (NoSuchAlgorithmException e) {
        e.printStackTrace()
    }
    return generatedValue
}

public static Map normalyze_type1(String text) {
    // Phone
    /*
    a) выставляем значение поля valid_phone_flg = 1;
    b) если длина входной строки менее 10 символов, выставляем значение поля valid_phone_flg = 0, заканчиваем обработку;
    c) если длина входной строки равна 10 символам и первый символ '9', добавляем '+7’, заканчиваем обработку;
    d) если длина входной строки равна 11 и первый символ ‘8', заменяем его на '+7’, заканчиваем обработку;
    e) если длина входной строки равна 11, добавляем '+’, заканчиваем обработку;
    f) если длина входной строки равна 12 и и первые два символа ‘+8', заменяем их на '+7’, заканчиваем обработку;
    g) если длина входной строки равна 12 и и первый символ ‘+', заканчиваем обработку;
    h) выставляем значение поля valid_phone_flg = 0, возвращаем невалидное значение
    */

    def valid_phone_flg = '1'
    text = text.replaceAll('[-()]', '')
    text = text.replaceAll(' ', '')
    String phone = text
    if (phone.length() < 10) { valid_phone_flg = '0' }
    else if (phone.length() == 10 && phone.substring(0, 1) == '9') { phone = '+7' + phone }
    else if (phone.length() == 11 && phone.substring(0, 1) == '8') { phone = '+7' + phone.substring(1, phone.length()) }
    else if (phone.length() == 11) { phone = '+' + phone }
    else if (phone.length() == 12 && phone.substring(0, 2) == '+8') { phone = '+7' + phone.substring(2, phone.length()) }
    else if (phone.length() == 12 && phone.substring(0, 1) == '+') { valid_phone_flg = '1' }
    else { valid_phone_flg = '0' }

    return [ph: phone, flg: valid_phone_flg]
}

public static String normalyze_type2(String text) {
    // Birthdate
    String birth = text
    if (birth.matches("[A-Za-zА-Яа-я]*")) { return null }
    else {
        if (birth ==~ /\d{4}\-\d{2}\-\d{2}/) { return birth }
        else if (birth ==~ /\d{1}\.\d{1}\.\d{4}/ || birth ==~ /\d{1}\.\d{2}\.\d{4}/ || birth ==~ /\d{2}\.\d{2}\.\d{4}/ || birth ==~ /\d{2}\.\d{1}\.\d{4}/) {
                birth = Date.parse("dd.MM.yy", birth).format("yyyy-MM-dd")
            }
            else {
                return null
            }
    }
    return birth 
}

public static String normalyze_type3(String text) {
    // Others
    text = text.replaceAll(' ', '')
    text = text.toLowerCase()
    return text
}

public static Map normalyze_type4(String text) {
    // Email
    def valid_email_flg = '0'
    text = text.replaceAll(' ', '').toLowerCase()
    String email = text
    if (email ==~ /(?:[a-z0-9!#$%&\'*+=?^_`{|}~-]+(?:\.[a-z0-9!#$%&\'*+=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])/) {
    valid_email_flg = '1' }
    return [em: email, flg: valid_email_flg]
}

try {
    flowFile = session.write(flowFile,
        { inputStream, outputStream ->

            def content = IOUtils.toString(inputStream, StandardCharsets.UTF_8)
            def content_list = new JsonSlurper().parseText(content)
            def result_list = []

            // ===== get attributes and parameters
            // encrypted_fields
            def encrypted_fields = flowFile.getAttribute('encrypted_fields')
            if (!encrypted_fields) {
                encrypted_fields = context.getProperty('encrypted_fields').getValue()
            }
            if (!encrypted_fields) {
                log.error('encrypted_fields is null')
                return
            }
            def l = new JsonSlurper().parseText(encrypted_fields)

            // need_normalyze
            def need_normalyze = context.getProperty('need_normalyze').getValue()
            if (need_normalyze) {
                need_normalyze = need_normalyze.toBoolean()
            }
            else { need_normalyze = false }

            // need_debug_phone
            def need_debug_phone = context.getProperty('need_debug_phone').getValue()
            if (need_debug_phone) {
                need_debug_phone = need_debug_phone.toBoolean()
            }
            else { need_debug_phone = false }

            // need_debug_email
            def need_debug_email = context.getProperty('need_debug_email').getValue()
            if (need_debug_email) {
                need_debug_email = need_debug_email.toBoolean()
            }
            else { need_debug_email = false }

            // get sensitive parameter
            def password = context.getProperty('encrypted_pass').evaluateAttributeExpressions().getValue()

            content_list.each { map ->

                def phone_flg = 0
                String phone_orig, phone_nrml
                def email_flg = 0
                String email_orig, email_nrml

                map.each { entry ->
                    l.each { a ->
                        // phone
                        if (entry.key == a.name && (entry.value) && a.type == 1) {
                            phone_orig = entry.value
                            if ((entry.value)) {
                                if (need_normalyze) {
                                    Map rv = normalyze_type1(entry.value)
                                    phone_flg = rv.flg
                                    phone_nrml = rv.ph
                                    entry.value = getEncryptedValue(phone_nrml, password)
                                }
                                else { entry.value = getEncryptedValue(entry.value, password) }
                            }
                            else {
                                phone_flg = 0
                            }
                        }
                        // birthdate
                        if (entry.key == a.name && (entry.value) && a.type == 2) {
                            if (need_normalyze) {
                                def rv = normalyze_type2(entry.value)
                                if (rv != null) {entry.value = getEncryptedValue(rv, password) }
                                else { entry.value = null }
                            }
                            else { entry.value = getEncryptedValue(entry.value, password) }
                        }
                        // name
                        if (entry.key == a.name && (entry.value) && a.type == 3) {
                            if (need_normalyze) {
                                def rv = normalyze_type3(entry.value)
                                //log.error('entry.value = {}, rv = {}.', entry.value, rv)
                                if (rv != null) {entry.value = getEncryptedValue(rv, password) }
                                else { entry.value = null }
                            }
                            else { entry.value = getEncryptedValue(entry.value, password) }
                        }
                        // email
                        if (entry.key == a.name && (entry.value) && a.type == 4) {
                            email_orig = entry.value
                            if ((entry.value)) {
                                if (need_normalyze) {
                                    Map rv = normalyze_type4(entry.value)
                                    email_flg = rv.flg
                                    email_nrml = rv.em
                                    //log.error('entry.value = {}, rv.em = {}, email_nrml = {}, email_flg = {}.', entry.value, rv.em, email_nrml, email_flg)
                                    entry.value = getEncryptedValue(email_nrml, password)
                                }
                                else { entry.value = getEncryptedValue(entry.value, password) }
                            }
                            else {
                                email_flg = 0
                            }
                        }
                    }
                }

                if (need_debug_phone) {
                    map.put('valid_phone_flg', phone_flg)
                    map.put('_phone_orig', phone_orig)
                    map.put('_phone_nrml', phone_nrml)
                }
                if (need_debug_email) {
                    map.put('valid_email_flg', email_flg)
                    map.put('_email_orig', email_orig)
                    map.put('_email_nrml', email_nrml)
                }

                def json = JsonOutput.toJson(map)
                result_list << JsonOutput.prettyPrint(json)
            }

            outputStream.write(result_list.toListString().getBytes(StandardCharsets.UTF_8))
        } as StreamCallback)
    session.transfer(flowFile, REL_SUCCESS)
} catch (Exception e) {
    log.error('Error during JSON operations', e)
    session.transfer(flowFile, REL_FAILURE)
}
