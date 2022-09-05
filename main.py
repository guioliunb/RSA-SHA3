import SHA3
import RSA3
import sys

class Key:
    def __init__(self, e = None, n = None, d = None):
        self.e = e
        self.n = n
        self.d = d

def save_keys(public, private):
    with open("private.key", 'w') as f:
        f.write('n:'+hex(private.n)+';')
        f.write('d:'+hex(private.d))

    with open('public.key', 'w') as f:
        f.write("n:"+hex(public.n)+';')
        f.write("e:"+hex(public.e))

def output_file(signature, filename):
    out_name = 'signature_' + filename

    with open(out_name, 'w') as f_out:
        f_out.write(hex(signature))

def gen_keys():
    while True:
        n = 512
        p = RSA3.getLowLevelPrime(n)
        if not RSA3.isMillerRabinPassed(p):
            continue
        else:
            #print(n, "p prime is: \n", p)
            break      
    while True:
        n = 512
        q = RSA3.getLowLevelPrime(n)
        if not RSA3.isMillerRabinPassed(q):
            continue
        else:
            #print(n, "q prime is: \n", q)
            break

    return RSA3.generate_keypair(p, q)

def verify_signature(sha_from_file, sign_filename, pubkey_filename):
    sign_hex = None
    with open(sign_filename, 'r') as f:
        sign_hex = f.read()

    with open(pubkey_filename, 'r') as f:
        keypair = f.read()

    div_tok = keypair.find(';')
    n = int(keypair[2:div_tok], 0)
    e = int(keypair[div_tok+3:], 0)

    print("\nPublic Key:")
    print("\te:", e)
    print("\tn:", n)
    print('')

    sign_dec = int(sign_hex, 0)
    sha_from_signature = pow(sign_dec, e, n)

    if int(sha_from_file, 16) == sha_from_signature:
        print("Signature is valid.")
    else:
        print("Signature is invalid.")


def main(argc, argv):
    if argc != 3 and argc != 4:
        print("Usage: {0} <input file> <s/v> <public key file>".format(argv[0]))
        return

    filename = argv[1]

    # Sign file
    if argv[2] == 's':
        # First Step: Calculate RSA Keys
        public, private = gen_keys()
        print("Public key:")
        print("\te:", public[0])
        print("\tn:", public[1])
        pub = Key(e=public[0], n=public[1])

        print("\nPrivate key:")
        print("\td:", private[0])
        print("\tn:", private[1])
        priv = Key(d=private[0], n=private[1])

        save_keys(pub, priv)

        # Second Step: Calculate SHA512 of the file
        sha512 = SHA3.SHA3(64)
        sha_byte, sha_hex, = sha512.calculate_from_file(filename)
        print("\nSHA512 of the file:", sha_hex)

        # Third Step: Sign the SHA512 of the file
        # signature = oaep_sign(sha_hex, public, private) #TODO oeap_sign
        signature = pow(int(sha_hex, 16), priv.d, priv.n)

        print("\nSignature:", hex(signature))

        # Fourth Step: Output the signature of the file
        output_file(signature, filename)

    # Verify signature
    elif argv[2] == 'v':
        # First Step: Calculate SHA512 to the file
        sha512 = SHA3.SHA3(64)
        sha_byte, sha_hex, = sha512.calculate_from_file(filename)
        print("\nSHA512 of the file:", sha_hex)

        # Third Step: Verify signature
        verify_signature(sha_hex, 'signature_' + filename, argv[3])

    else:
        print("Usage: {0} <input file> <s/v> <public key file>".format(argv[0]))
        return 

if __name__  == '__main__':
    main(len(sys.argv), sys.argv)