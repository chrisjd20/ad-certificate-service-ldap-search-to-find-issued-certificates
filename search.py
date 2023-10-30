#!/usr/bin/env python3
import ldap3
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def main():
    server = ldap3.Server('ldaps://dc01.test.local')
    conn = ldap3.Connection(server, 'administrator@test.local', 'SECRETPASSWORD', auto_bind=True)
    conn.search('DC=test,DC=local', '(userCertificate=*)', attributes=['usercertificate'])
    for entry in conn.entries:
        for cert_bin in entry['userCertificate']:
            cert = x509.load_der_x509_certificate(cert_bin, default_backend())
            serial_hex = hex(cert.serial_number)[2:]
            try:
                san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                for general_name in san.value:
                    if isinstance(general_name, x509.OtherName):
                        value = general_name.value.decode("ascii","ignore")
                        print(f"Cert with serial {serial_hex} has san {general_name} value of '{value}'")
            except x509.ExtensionNotFound:
                pass

if __name__ == "__main__":
    main()

