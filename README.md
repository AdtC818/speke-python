# SPEKE en Python

Implementación del protocolo SPEKE (Simple Password Exponential Key Exchange, Jablon 1996) para que dos partes que comparten una contraseña se autentiquen mutuamente sin enviarla nunca por el canal. Electiva de Seguridad Computacional, UPTC.

## Cómo funciona
1. Alice y Bob derivan el generador de la contraseña: g = SHA-256(contraseña)² mod p, donde p es el primo seguro de 2048 bits del RFC 3526.
2. Cada uno escoge un secreto aleatorio y envía su valor público: A = g^a mod p y B = g^b mod p.
3. Los dos calculan el mismo secreto g^(ab) mod p y derivan de él la clave de sesión con SHA-256.
4. Intercambian tokens de autenticación y los comparan en tiempo constante para evitar ataques de tiempo.
5. Si las contraseñas no coinciden, las claves tampoco, y la autenticación falla.

## Cómo correrlo
Python 3.7 o superior, sin dependencias:

    python seguridad.py
