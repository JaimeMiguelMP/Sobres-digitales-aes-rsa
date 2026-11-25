# Sobres Digitales con Cifrado Híbrido (AES y RSA)

Implementación en Python de sobres digitales para proteger la confidencialidad de archivos combinando cifrado simétrico (AES) y asimétrico (RSA).

## Funcionamiento
1. Generación de par de llaves RSA (pública y privada).
2. Cifrado del archivo original mediante una llave simétrica AES generada aleatoriamente.
3. Cifrado de la llave AES utilizando la llave pública RSA del destinatario.
4. Descifrado inverso recuperando primero la llave AES con la llave privada RSA y posteriormente el archivo.

## Requisitos
- Python 3.x
- Biblioteca Cryptography de Python

## Uso
```bash
pip install criptography
python main.py