import random
import string
from blobfish.ejbca.client import Client


def random_string(string_length=10):
    letters_and_digits = string.ascii_letters + string.digits
    return "".join(random.choice(letters_and_digits) for i in range(string_length))


def print_cert_info(cert):
    print("Certificate generated successfully:")
    print("  - Serial number: " + cert.get_serial_number_hex())
    print("  - Issuer DN: " + cert.get_issuer_str())
    print("  - Subject DN: " + cert.get_subject_str())
    print("  - Valid from: {0}".format(cert.get_notBefore_datetime()))
    print("  - Valid to: {0}".format(cert.get_notAfter_datetime()))


e = Client.escape_dn_attr_value

tax_number = "20202020201"
company_name = "CONTOSO S.A."
title = "General manager"
nid = "20202020"
surname = "PEREZ VARGAS"
given_name = "JUAN CARLOS"
email_address = "jdoe@example.org"
street_address = "Av. Los Corales 123, San Isidro"
locality = "Lima"

ejbca_client = Client("https://localhost:8443/ejbca/ejbcaws/ejbcaws?wsdl", "cacerts_localhost.pem",
                      "client.cer",
                      "client.key")

ca_name = "MyCertificationAuthority"
cert_profile = "MyCertProfile"
ee_profile = "MyEndEntityProfile"
# TODO after migrating to Python 3.6+, use literal string interpolation (https://www.python.org/dev/peps/pep-0498/)
#  for making string concatenation cleaner all around.
ejbca_username = "{0}_{1}".format(tax_number, nid)
subject_dn = "CN=" + e(given_name) + " " + e(surname) + ",emailAddress=" + e(email_address) + ",serialNumber=" + \
             e(nid) + ",O=" + e(company_name) + ",OU=" + e(tax_number) + ",T=" + e(title) + ",L=" + e(locality) \
             + ",street=" + e(street_address) + ",C=PE "
subject_alt_name = "rfc822name={0}".format(email_address)


def write_pfx_to_file(data, validity_days):
    path = "{0}_{1}_{2}.pfx".format(tax_number, nid, validity_days)
    file = open(path, "wb")
    file.write(data)
    file.close()
    print(".pfx successfully saved in " + path)


def request_pfx_demo(validity_days):
    pfx_random_password = random_string(8)
    print(
        "Requesting EJBCA side PFX generation with the following random password {0} (Validity days: {1})...".format(
            pfx_random_password, validity_days))
    resp = ejbca_client.request_pfx(ca_name, cert_profile, ee_profile, ejbca_username, email_address, subject_dn,
                                    subject_alt_name, validity_days,
                                    pfx_random_password)
    cert = resp["cert"]
    print_cert_info(cert)
    write_pfx_to_file(resp["pfx"], validity_days)
    print()
    return cert


cert_1_year = request_pfx_demo(365)
cert_2_years = request_pfx_demo(730)
cert_3_years = request_pfx_demo(1095)

print("Requesting revocation for certificate with serial number " + cert_2_years.get_serial_number_hex() +
      " issued by " + cert_2_years.get_issuer_str() + "...")
ejbca_client.revoke_cert(cert_2_years)
print("Certificate revoked")
print()

print("Listing all certs for user {0}...".format(ejbca_username))
all_certs = ejbca_client.get_all_certs(ejbca_username)
for cert in all_certs:
    revocation_status = ejbca_client.get_revocation_status(cert)
    print("  - {0}, {1} => ".format(cert.get_issuer_str(), cert.get_serial_number_hex()), end="")
    if revocation_status is None:
        print(" not revoked")
    else:
        print(" revoked on {0}".format(revocation_status.revocationDate))
print()
