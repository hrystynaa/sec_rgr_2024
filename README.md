**1. Генерація приватного ключа Root CA**
```
openssl genrsa -out root_ca.key 2048
```
**2. Генерація самопідписаного сертифікату Root CA (дійсний 1 рік)**
```
openssl req -x509 -new -nodes -key root_ca.key -sha256 -days 365 -out root_ca.crt -subj "/C=UA/ST=Kyiv/L=Kyiv/O=Test Org/OU=Test CA Unit/CN=My Test Root CA"
```
**3. Генерація приватного ключа Сервера**
```
openssl genrsa -out server.key 2048
```
**4. Створення запиту на підпис сертифіката (CSR) для сервера (CN=localhost)**
```
openssl req -new -key server.key -out server.csr -subj "/C=UA/ST=Kyiv/L=Kyiv/O=Test Server Org/OU=Test Server Unit/CN=localhost"
```
**5. Підпис CSR сервера за допомогою Root CA -> створення сертифіката сервера**
```
openssl x509 -req -in server.csr -CA root_ca.crt -CAkey root_ca.key -CAcreateserial -out server.crt -days 365 -sha256
```
**Перевірка**
```
openssl verify -CAfile root_ca.crt server.crt
```
