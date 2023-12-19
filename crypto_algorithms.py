from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from cryptography.hazmat.primitives.ciphers import algorithms

def generate_key(key_type, **kwargs):
    """
    Genera una clave criptográfica basada en el tipo de algoritmo especificado.

    Args:
        key_type (str): Tipo de clave a generar ('rsa', 'dsa', 'ec', etc.).
        **kwargs: Argumentos adicionales dependiendo del tipo de clave.

    Returns:
        bytes: Clave privada serializada.
    """
    if key_type == 'rsa':
        key_size = kwargs.get('key_size', 2048)
        public_exponent = kwargs.get('public_exponent', 65537)
        
        key = rsa.generate_private_key(
            public_exponent=public_exponent,
            key_size=key_size
        )

    elif key_type == 'dsa':
        key_size = kwargs.get('key_size', 2048)
        
        key = dsa.generate_private_key(
            key_size=key_size
        )

    elif key_type == 'ec':
        curve = kwargs.get('curve', ec.SECP256R1())
        
        key = ec.generate_private_key(
            curve=curve
        )

    else:
        raise ValueError(f"Tipo de clave no soportado: {key_type}")

    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )