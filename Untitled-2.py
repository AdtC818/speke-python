"""
================================================================================
 SPEKE - Simple Password Exponential Key Exchange
 Taller 2 - Punto 3.1 | Electiva IV: Seguridad Computacional
 Universidad Pedagógica y Tecnológica de Colombia
================================================================================

 Descripción:
   Implementación funcional del protocolo SPEKE para autenticación mutua
   entre dos partes (Alice y Bob) usando una contraseña compartida débil,
   sin transmitirla jamás por el canal de comunicación.

 Fundamento teórico:
   SPEKE (Jablon, 1996) extiende el intercambio Diffie-Hellman al derivar
   el generador g directamente desde la contraseña compartida:
       g = H(password)^2 mod p
   Esto vincula criptográficamente el intercambio de claves a la contraseña,
   impidiendo que un atacante pasivo pueda realizar ataques de diccionario
   sin interactuar activamente con una de las partes.

 Uso:
   python speke_protocol.py

 Requisitos:
   Python 3.7+  (sin dependencias externas)
================================================================================
"""

import hashlib
import hmac
import os
import secrets
import time

# ==============================================================================
# PARÁMETROS CRIPTOGRÁFICOS DEL PROTOCOLO
# ==============================================================================

# Primo seguro de 2048 bits - RFC 3526 (MODP Group 14)
# Un primo seguro p satisface: p = 2q + 1, donde q también es primo.
# Esto garantiza que el grupo multiplicativo Z*_p tenga el orden correcto
# para que el problema del logaritmo discreto sea computacionalmente difícil.
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)

# Número de bytes del primo p (usado para serialización consistente)
P_BYTE_LEN = (P.bit_length() + 7) // 8


# ==============================================================================
# FUNCIÓN CENTRAL: DERIVACIÓN DEL GENERADOR DESDE LA CONTRASEÑA
# ==============================================================================

def derivar_generador(password: str) -> int:
    """
    Deriva el generador g del grupo a partir de la contraseña compartida.

    En SPEKE, el generador NO es un valor fijo público (como en DH clásico).
    En su lugar, se calcula como:
        g = H(password)^2 mod p

    El cuadrado garantiza que g pertenezca al subgrupo de orden q (los
    residuos cuadráticos mod p), que es el subgrupo con las propiedades
    de seguridad deseadas.

    Args:
        password: La contraseña compartida en texto plano.

    Returns:
        g: Entero en Z*_p derivado de la contraseña.
    """
    # 1. Aplicar SHA-256 a la contraseña (codificada en UTF-8)
    h_bytes = hashlib.sha256(password.encode("utf-8")).digest()

    # 2. Convertir los bytes del hash a entero en big-endian
    h_int = int.from_bytes(h_bytes, "big")

    # 3. Calcular g = H(password)^2 mod p
    #    Elevar al cuadrado y reducir módulo p vincula g a la contraseña
    #    y lo sitúa en el subgrupo de residuos cuadráticos de Z*_p.
    g = pow(h_int, 2, P)

    return g


# ==============================================================================
# CLASE ALICE - LADO DEL CLIENTE
# ==============================================================================

class Alice:
    """
    Simula el lado del cliente (Alice) en el protocolo SPEKE.

    Estado interno:
        password : contraseña compartida (nunca se transmite)
        a        : exponente secreto aleatorio de Alice
        A        : valor público de Alice: A = g^a mod p
        K        : clave de sesión compartida derivada
        g        : generador derivado de la contraseña
    """

    def __init__(self, password: str):
        self.password = password
        self.a: int = None
        self.A: int = None
        self.K: bytes = None
        self.g: int = None

    def fase1_iniciar_intercambio(self) -> int:
        """
        FASE 1 (Cliente): Derivar generador y generar valor público.

        Pasos:
          1. Derivar g = H(password)^2 mod p
          2. Generar exponente secreto aleatorio a (256 bits)
          3. Calcular valor público A = g^a mod p

        Returns:
            A: Valor público que Alice envía a Bob.
        """
        # Derivar el generador vinculado a la contraseña
        self.g = derivar_generador(self.password)

        # Generar exponente secreto criptográficamente seguro (256 bits)
        # secrets.randbelow garantiza uniformidad y seguridad criptográfica
        self.a = secrets.randbelow(P - 2) + 2  # a ∈ [2, P-2]

        # Calcular valor público: A = g^a mod p
        # pow(base, exp, mod) usa exponenciación modular eficiente (algoritmo square-and-multiply)
        self.A = pow(self.g, self.a, P)

        _log("Alice", f"Generador g derivado: {hex(self.g)[:18]}...  [{P_BYTE_LEN*8} bits]")
        _log("Alice", f"Exponente secreto 'a' generado de forma aleatoria segura.")
        _log("Alice", f"Valor público A = g^a mod p: {hex(self.A)[:18]}...")
        return self.A

    def fase2_calcular_clave(self, B: int) -> bytes:
        """
        FASE 2 (Cliente): Calcular clave compartida a partir del valor de Bob.

        K = H(B^a mod p)

        Ambas partes obtienen el mismo secreto porque:
            B^a = (g^b)^a = g^(ab) = (g^a)^b = A^b

        Args:
            B: Valor público recibido de Bob.

        Returns:
            K: Clave de sesión de 256 bits (32 bytes).
        """
        # Calcular g^(ab) mod p usando el exponente secreto de Alice
        secreto = pow(B, self.a, P)

        # Derivar clave de sesión con KDF basada en SHA-256
        # Serializar el secreto a bytes de longitud fija para evitar ataques
        # de longitud variable (leading zeros issue).
        self.K = hashlib.sha256(secreto.to_bytes(P_BYTE_LEN, "big")).digest()

        _log("Alice", f"Clave compartida K calculada: {self.K.hex()}")
        return self.K

    def generar_token_autenticacion(self, B: int) -> bytes:
        """
        Genera un token HMAC para autenticación mutua.

        El mensaje incluye la identidad de Alice y ambos valores públicos
        para evitar ataques de reflexión y replay.

        Args:
            B: Valor público de Bob.

        Returns:
            Token HMAC-SHA256.
        """
        # Mensaje: identidad || A || B (todos serializados a longitud fija)
        mensaje = (
            b"ALICE-AUTH"
            + self.A.to_bytes(P_BYTE_LEN, "big")
            + B.to_bytes(P_BYTE_LEN, "big")
        )
        return hmac.new(self.K, mensaje, hashlib.sha256).digest()

    def verificar_token_bob(self, B: int, token_bob: bytes) -> bool:
        """
        Verifica el token de autenticación recibido de Bob.

        Args:
            B: Valor público de Bob.
            token_bob: Token HMAC recibido de Bob.

        Returns:
            True si la verificación es exitosa, False en caso contrario.
        """
        mensaje_bob = (
            b"BOB-AUTH"
            + B.to_bytes(P_BYTE_LEN, "big")
            + self.A.to_bytes(P_BYTE_LEN, "big")
        )
        token_esperado = hmac.new(self.K, mensaje_bob, hashlib.sha256).digest()
        # compare_digest: comparación en tiempo constante (evita timing attacks)
        return hmac.compare_digest(token_esperado, token_bob)


# ==============================================================================
# CLASE BOB - LADO DEL SERVIDOR
# ==============================================================================

class Bob:
    """
    Simula el lado del servidor (Bob) en el protocolo SPEKE.

    Estado interno:
        password : contraseña compartida (nunca se transmite)
        b        : exponente secreto aleatorio de Bob
        B        : valor público de Bob: B = g^b mod p
        K        : clave de sesión compartida derivada
        g        : generador derivado de la contraseña
    """

    def __init__(self, password: str):
        self.password = password
        self.b: int = None
        self.B: int = None
        self.K: bytes = None
        self.g: int = None

    def fase1_responder_intercambio(self, A: int) -> int:
        """
        FASE 1 (Servidor): Derivar generador y generar valor público.

        Args:
            A: Valor público recibido de Alice.

        Returns:
            B: Valor público que Bob envía a Alice.
        """
        # Bob deriva el mismo generador g desde su copia de la contraseña
        self.g = derivar_generador(self.password)

        # Generar exponente secreto criptográficamente seguro
        self.b = secrets.randbelow(P - 2) + 2  # b ∈ [2, P-2]

        # Calcular valor público: B = g^b mod p
        self.B = pow(self.g, self.b, P)

        _log("Bob  ", f"Generador g derivado: {hex(self.g)[:18]}...  [{P_BYTE_LEN*8} bits]")
        _log("Bob  ", f"Exponente secreto 'b' generado de forma aleatoria segura.")
        _log("Bob  ", f"Valor público B = g^b mod p: {hex(self.B)[:18]}...")
        return self.B

    def fase2_calcular_clave(self, A: int) -> bytes:
        """
        FASE 2 (Servidor): Calcular clave compartida.

        K = H(A^b mod p)

        Args:
            A: Valor público de Alice.

        Returns:
            K: Clave de sesión de 256 bits.
        """
        secreto = pow(A, self.b, P)
        self.K = hashlib.sha256(secreto.to_bytes(P_BYTE_LEN, "big")).digest()
        _log("Bob  ", f"Clave compartida K calculada: {self.K.hex()}")
        return self.K

    def generar_token_autenticacion(self, A: int) -> bytes:
        """
        Genera el token HMAC para autenticación mutua.

        Args:
            A: Valor público de Alice.

        Returns:
            Token HMAC-SHA256.
        """
        mensaje = (
            b"BOB-AUTH"
            + self.B.to_bytes(P_BYTE_LEN, "big")
            + A.to_bytes(P_BYTE_LEN, "big")
        )
        return hmac.new(self.K, mensaje, hashlib.sha256).digest()

    def verificar_token_alice(self, A: int, token_alice: bytes) -> bool:
        """
        Verifica el token de autenticación recibido de Alice.

        Args:
            A: Valor público de Alice.
            token_alice: Token HMAC recibido de Alice.

        Returns:
            True si la verificación es exitosa, False en caso contrario.
        """
        mensaje_alice = (
            b"ALICE-AUTH"
            + A.to_bytes(P_BYTE_LEN, "big")
            + self.B.to_bytes(P_BYTE_LEN, "big")
        )
        token_esperado = hmac.new(self.K, mensaje_alice, hashlib.sha256).digest()
        return hmac.compare_digest(token_esperado, token_alice)


# ==============================================================================
# UTILIDADES DE PRESENTACIÓN
# ==============================================================================

def _log(actor: str, mensaje: str):
    """Imprime mensajes formateados por actor."""
    print(f"  [{actor}] {mensaje}")

def _seccion(titulo: str):
    """Imprime un encabezado de sección."""
    print(f"\n{'─'*68}")
    print(f"   {titulo}")
    print(f"{'─'*68}")

def _resultado(ok: bool, descripcion: str):
    """Imprime resultado de una verificación."""
    simbolo = "✓" if ok else "✗"
    estado  = "EXITOSO" if ok else "FALLIDO"
    print(f"  [{simbolo}] {descripcion}: {estado}")


# ==============================================================================
# FUNCIÓN PRINCIPAL: SIMULACIÓN COMPLETA DEL PROTOCOLO
# ==============================================================================

def ejecutar_speke(password_alice: str, password_bob: str, etiqueta: str = ""):
    """
    Simula el protocolo SPEKE completo entre Alice y Bob.

    El protocolo consta de tres fases:
      1. Intercambio de valores públicos (g^a y g^b)
      2. Cálculo independiente de la clave compartida
      3. Autenticación mutua mediante tokens HMAC

    Args:
        password_alice : Contraseña usada por Alice.
        password_bob   : Contraseña usada por Bob.
        etiqueta       : Descripción del escenario de prueba.
    """
    ancho = 68
    print("\n" + "═" * ancho)
    print(f"  PROTOCOLO SPEKE — {etiqueta}")
    print("═" * ancho)

    # ── INSTANCIAR PARTICIPANTES ──────────────────────────────────────────────
    alice = Alice(password_alice)
    bob   = Bob(password_bob)

    # ── FASE 1: INTERCAMBIO DE VALORES PÚBLICOS ───────────────────────────────
    _seccion("FASE 1 ▸ Derivación del generador e intercambio de valores públicos")
    print()

    t0 = time.perf_counter()

    # Alice calcula A = g^a mod p y "lo envía a Bob" (simulado como valor de retorno)
    A = alice.fase1_iniciar_intercambio()
    print()

    # Bob calcula B = g^b mod p y "lo envía a Alice"
    B = bob.fase1_responder_intercambio(A)

    # ── FASE 2: CÁLCULO DE CLAVE COMPARTIDA ──────────────────────────────────
    _seccion("FASE 2 ▸ Cálculo independiente de la clave compartida")
    print()

    # Alice: K_alice = H(B^a mod p)
    K_alice = alice.fase2_calcular_clave(B)
    print()

    # Bob:   K_bob   = H(A^b mod p)
    K_bob = bob.fase2_calcular_clave(A)

    # ── FASE 3: AUTENTICACIÓN MUTUA ───────────────────────────────────────────
    _seccion("FASE 3 ▸ Autenticación mutua mediante tokens HMAC-SHA256")
    print()

    # Alice genera su token de autenticación y lo "envía a Bob"
    token_alice = alice.generar_token_autenticacion(B)
    _log("Alice", f"Token HMAC generado → Bob:  {token_alice.hex()[:24]}...")

    # Bob verifica el token de Alice
    ok_alice_en_bob = bob.verificar_token_alice(A, token_alice)
    _log("Bob  ", f"Verificación del token de Alice: {'✓ VÁLIDO' if ok_alice_en_bob else '✗ INVÁLIDO'}")
    print()

    # Bob genera su token de autenticación y lo "envía a Alice"
    token_bob = bob.generar_token_autenticacion(A)
    _log("Bob  ", f"Token HMAC generado → Alice: {token_bob.hex()[:24]}...")

    # Alice verifica el token de Bob
    ok_bob_en_alice = alice.verificar_token_bob(B, token_bob)
    _log("Alice", f"Verificación del token de Bob:   {'✓ VÁLIDO' if ok_bob_en_alice else '✗ INVÁLIDO'}")

    t1 = time.perf_counter()
    duracion_ms = (t1 - t0) * 1000

    # ── RESULTADO FINAL ───────────────────────────────────────────────────────
    _seccion("RESULTADO")
    print()
    claves_iguales   = K_alice == K_bob
    autenticacion_ok = ok_alice_en_bob and ok_bob_en_alice

    _resultado(claves_iguales,   "Claves compartidas son idénticas")
    _resultado(ok_alice_en_bob,  "Bob autentica a Alice")
    _resultado(ok_bob_en_alice,  "Alice autentica a Bob")
    print()

    if claves_iguales and autenticacion_ok:
        print(f"  ╔══════════════════════════════════════════════════════════════╗")
        print(f"  ║  ✓  AUTENTICACIÓN SPEKE EXITOSA — Canal seguro establecido  ║")
        print(f"  ╚══════════════════════════════════════════════════════════════╝")
        print(f"\n  Clave de sesión: {K_alice.hex()}")
    else:
        print(f"  ╔══════════════════════════════════════════════════════════════╗")
        print(f"  ║  ✗  AUTENTICACIÓN FALLIDA — Contraseñas no coinciden        ║")
        print(f"  ╚══════════════════════════════════════════════════════════════╝")
        print(f"\n  Clave Alice: {K_alice.hex()}")
        print(f"  Clave Bob:   {K_bob.hex()}")

    print(f"\n  Tiempo total de ejecución: {duracion_ms:.2f} ms")
    print()
    return autenticacion_ok


# ==============================================================================
# ANÁLISIS DE VULNERABILIDADES (OMISIÓN DE ETAPAS)
# ==============================================================================

def demostrar_vulnerabilidad_sin_autenticacion_mutua():
    """
    Demuestra qué ocurre si se omite la Fase 3 (autenticación mutua).

    Sin verificación de tokens HMAC, un atacante MitM que intercepte los
    valores A y B puede sustituirlos por los suyos propios, estableciendo
    dos canales distintos sin que Alice ni Bob lo detecten.
    """
    _seccion("ANÁLISIS ▸ Vulnerabilidad por omisión de autenticación mutua (MitM)")
    print()
    _log("DEMO ", "Mallory intercepta los valores A y B en tránsito.")
    _log("DEMO ", "Mallory sustituye A por A' y B por B' generados por él.")
    _log("DEMO ", "Sin Fase 3, Alice y Bob no pueden detectar la suplantación.")
    _log("DEMO ", "→ Conclusión: la autenticación mutua (HMAC) es INDISPENSABLE.")
    print()


# ==============================================================================
# PUNTO DE ENTRADA
# ==============================================================================

if __name__ == "__main__":
    print("=" * 68)
    print("  SPEKE — Simulación del protocolo de autenticación")
    print("  Electiva IV: Seguridad Computacional | UPTC 2025")
    print("=" * 68)

    # ── PRUEBA 1: Caso exitoso (contraseñas idénticas) ────────────────────────
    ejecutar_speke(
        password_alice="C0ntr@seña_Segura!",
        password_bob  ="C0ntr@seña_Segura!",
        etiqueta      ="PRUEBA 1: Contraseñas coincidentes (caso exitoso)",
    )

    # ── PRUEBA 2: Caso fallido (contraseñas distintas — simula ataque) ────────
    ejecutar_speke(
        password_alice="C0ntr@seña_Segura!",
        password_bob  ="contraseña_incorrecta",
        etiqueta      ="PRUEBA 2: Contraseñas distintas (acceso denegado)",
    )

    # ── ANÁLISIS DE VULNERABILIDAD ────────────────────────────────────────────
    demostrar_vulnerabilidad_sin_autenticacion_mutua()

    print("=" * 68)
    print("  Fin de la simulación.")
    print("=" * 68)