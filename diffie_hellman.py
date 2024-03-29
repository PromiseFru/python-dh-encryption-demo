import logging
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)


def generate_dh_parameters():
    logger.info("Generating Diffie-Hellman parameters...")
    p = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC"
        "74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F"
        "14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F"
        "406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007C"
        "B8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C6"
        "2F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C"
        "32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C"
        "52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A"
        "8AACAA68FFFFFFFFFFFFFFFF",
        16,
    )
    g = 2
    params_numbers = dh.DHParameterNumbers(p, g)
    parameters = params_numbers.parameters(default_backend())
    return parameters


def generate_keypair(parameters):
    logger.info("Generating key pair...")
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key.public_numbers().y


def generate_shared_key(private_key, peer_public_key):
    logger.info("Generating shared key...")
    p = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC"
        "74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F"
        "14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F"
        "406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007C"
        "B8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C6"
        "2F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C"
        "32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C"
        "52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A"
        "8AACAA68FFFFFFFFFFFFFFFF",
        16,
    )
    g = 2
    params_numbers = dh.DHParameterNumbers(p, g)
    peer_public_numbers = dh.DHPublicNumbers(peer_public_key, params_numbers)
    peer_public_key = peer_public_numbers.public_key()
    return private_key.exchange(peer_public_key)
