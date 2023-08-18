#!/usr/bin/env python
# Copyright Daniel Roesler, under MIT license, see LICENSE at github.com/diafygi/acme-tiny
import argparse
import subprocess
import json
import os
import sys
import base64
import binascii
import time
import hashlib
import re
import textwrap
import logging
import urllib

try:
    from urllib.request import urlopen, Request  # Python 3
except ImportError:
    from urllib2 import urlopen, Request  # Python 2

DEFAULT_CA = "https://acme-v02.api.letsencrypt.org"  # DEPRECATED! USE DEFAULT_DIRECTORY_URL INSTEAD
DEFAULT_DIRECTORY_URL = "https://acme-v02.api.letsencrypt.org/directory"

LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.INFO)


def get_crt(account_key, csr, acme_dir, log=LOGGER, CA=DEFAULT_CA, disable_check=False, directory_url=DEFAULT_DIRECTORY_URL,
            contact=None):
    directory, acct_headers, alg, jwk = None, None, None, None  # global variables

    # helper functions - base64 encode for jose spec
    def _b64(b):
        return base64.urlsafe_b64encode(b).decode('utf8').replace("=", "")

    # helper function - run external commands
    def _cmd(cmd_list, stdin=None, cmd_input=None, err_msg="Command Line Error"):
        proc = subprocess.Popen(cmd_list, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate(cmd_input)
        if proc.returncode != 0:
            raise IOError("{0}\n{1}".format(err_msg, err))
        return out

    # helper function - make request and automatically parse json response
    def _do_request(url, data=None, err_msg="Error", depth=0):
        try:
            resp = urlopen(Request(url, data=data,
                                   headers={"Content-Type": "application/jose+json", "User-Agent": "acme-tiny"}))
            resp_data, code, headers = resp.read().decode("utf8"), resp.getcode(), resp.headers
        except IOError as e:
            resp_data = e.read().decode("utf8") if hasattr(e, "read") else str(e)
            code, headers = getattr(e, "code", None), {}
        try:
            resp_data = json.loads(resp_data)  # try to parse json results
        except ValueError:
            pass  # ignore json parsing errors
        if depth < 100 and code == 400 and resp_data['type'] == "urn:ietf:params:acme:error:badNonce":
            raise IndexError(resp_data)  # allow 100 retrys for bad nonces
        if code not in [200, 201, 204]:
            raise ValueError("{0}:\nUrl: {1}\nData: {2}\nResponse Code: {3}\nResponse: {4}".format(err_msg, url, data, code,
                                                                                                   resp_data))
        return resp_data, code, headers

    # helper function - make signed requests
    def _send_signed_request(url, payload, err_msg, depth=0):
        payload64 = "" if payload is None else _b64(json.dumps(payload).encode('utf8'))
        new_nonce = _do_request(directory['newNonce'])[2]['Replay-Nonce']
        protected = {"url": url, "alg": alg, "nonce": new_nonce}
        protected.update({"jwk": jwk} if acct_headers is None else {"kid": acct_headers['Location']})
        protected64 = _b64(json.dumps(protected).encode('utf8'))
        protected_input = "{0}.{1}".format(protected64, payload64).encode('utf8')
        out = _cmd(["openssl", "dgst", "-sha256", "-sign", account_key], stdin=subprocess.PIPE, cmd_input=protected_input,
                   err_msg="OpenSSL Error")
        data = json.dumps({"protected": protected64, "payload": payload64, "signature": _b64(out)})
        try:
            return _do_request(url, data=data.encode('utf8'), err_msg=err_msg, depth=depth)
        except IndexError:  # retry bad nonces (they raise IndexError)
            return _send_signed_request(url, payload, err_msg, depth=(depth + 1))

    # helper function - poll until complete
    def _poll_until_not(url, pending_statuses, err_msg):
        result, t0 = None, time.time()
        while result is None or result['status'] in pending_statuses:
            assert (time.time() - t0 < 3600), "Polling timeout"  # 1 hour timeout
            time.sleep(0 if result is None else 2)
            result, _, _ = _send_signed_request(url, None, err_msg)
        return result

    # parse account key to get public key
    log.info("Parsing account key...")
    out = _cmd(["openssl", "rsa", "-in", account_key, "-noout", "-text"], err_msg="OpenSSL Error")
    pub_pattern = r"modulus:[\s]+?00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)"
    pub_hex, pub_exp = re.search(pub_pattern, out.decode('utf8'), re.MULTILINE | re.DOTALL).groups()
    pub_exp = "{0:x}".format(int(pub_exp))
    pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
    alg = "RS256"
    jwk = {
        "e": _b64(binascii.unhexlify(pub_exp.encode("utf-8"))),
        "kty": "RSA",
        "n": _b64(binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex).encode("utf-8"))),
    }
    accountkey_json = json.dumps(jwk, sort_keys=True, separators=(',', ':'))
    thumbprint = _b64(hashlib.sha256(accountkey_json.encode('utf8')).digest())

    # find domains
    log.info("Parsing CSR...")
    out = _cmd(["openssl", "req", "-in", csr, "-noout", "-text"], err_msg="Error loading {0}".format(csr))
    domains = set([])
    common_name = re.search(r"Subject:.*? CN\s?=\s?([^\s,;/]+)", out.decode('utf8'))
    if common_name is not None:
        domains.add(common_name.group(1))
    subject_alt_names = re.search(r"X509v3 Subject Alternative Name: (?:critical)?\n +([^\n]+)\n", out.decode('utf8'),
                                  re.MULTILINE | re.DOTALL)
    if subject_alt_names is not None:
        for san in subject_alt_names.group(1).split(", "):
            if san.startswith("DNS:"):
                domains.add(san[4:])
    log.info("Found domains: {0}".format(", ".join(domains)))

    # get the ACME directory of urls
    log.info("Getting directory...")
    directory_url = CA + "/directory" if CA != DEFAULT_CA else directory_url  # backwards compatibility with deprecated CA
    directory, _, _ = _do_request(directory_url, err_msg="Error getting directory")
    log.info("Directory found!")

    # create account, update contact details (if any), and set the global key identifier
    log.info("Registering account...")
    reg_payload = {"termsOfServiceAgreed": True}
    account, code, acct_headers = _send_signed_request(directory['newAccount'], reg_payload, "Error registering")
    log.info("Registered!" if code == 201 else "Already registered!")
    if contact is not None:
        account, _, _ = _send_signed_request(acct_headers['Location'], {"contact": contact}, "Error updating contact details")
        log.info("Updated contact details:\n{0}".format("\n".join(account['contact'])))

    # create a new order
    log.info("Creating new order...")
    order_payload = {"identifiers": [{"type": "dns", "value": d} for d in domains]}
    order, _, order_headers = _send_signed_request(directory['newOrder'], order_payload, "Error creating new order")
    log.info("Order created!")

    # get the authorizations that need to be completed
    for auth_url in order['authorizations']:
        authorization, _, _ = _send_signed_request(auth_url, None, "Error getting challenges")
        domain = authorization['identifier']['value']
        log.info("Verifying {0}...".format(domain))

        # find the http-01 challenge and write the challenge file
        challenge = [c for c in authorization['challenges'] if c['type'] == "http-01"][0]
        token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge['token'])
        keyauthorization = "{0}.{1}".format(token, thumbprint)
        wellknown_path = os.path.join(acme_dir, token)
        with open(wellknown_path, "w") as wellknown_file:
            wellknown_file.write(keyauthorization)

        # check that the file is in place
        try:
            wellknown_url = "http://{0}/.well-known/acme-challenge/{1}".format(domain, token)
            assert (disable_check or _do_request(wellknown_url)[0] == keyauthorization)
        except (AssertionError, ValueError) as e:
            raise ValueError("Wrote file to {0}, but couldn't download {1}: {2}".format(wellknown_path, wellknown_url, e))

        # say the challenge is done
        _send_signed_request(challenge['url'], {}, "Error submitting challenges: {0}".format(domain))
        authorization = _poll_until_not(auth_url, ["pending"], "Error checking challenge status for {0}".format(domain))
        if authorization['status'] != "valid":
            raise ValueError("Challenge did not pass for {0}: {1}".format(domain, authorization))
        os.remove(wellknown_path)
        log.info("{0} verified!".format(domain))

    # finalize the order with the csr
    log.info("Signing certificate...")
    csr_der = _cmd(["openssl", "req", "-in", csr, "-outform", "DER"], err_msg="DER Export Error")
    _send_signed_request(order['finalize'], {"csr": _b64(csr_der)}, "Error finalizing order")

    # poll the order to monitor when it's done
    order = _poll_until_not(order_headers['Location'], ["pending", "processing"], "Error checking order status")
    if order['status'] != "valid":
        raise ValueError("Order failed: {0}".format(order))

    # download the certificate
    certificate_pem, _, _ = _send_signed_request(order['certificate'], None, "Certificate download failed")
    log.info("Certificate signed!")
    return certificate_pem


def main(argv=None):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""
            This script automates the process of getting a signed TLS certificate from Let's Encrypt using
            the ACME protocol. Example Crontab Renewal (once per month):
            0 0 1 * * python /home/direeeti/letsencrypt/letsencrypt.py
            """)
    )
    parser.add_argument("--quiet", action="store_const", const=logging.ERROR, help="suppress output except for errors")
    parser.add_argument("--install-only", default=False, action="store_true", help="install existing certificate only")
    parser.add_argument("--disable-check", default=False, action="store_true",
                        help="disable checking if the challenge file is hosted correctly before telling the CA")

    args = parser.parse_args(argv)
    LOGGER.setLevel(args.quiet or LOGGER.level)

    os.chdir(sys.path[0])
    if not os.path.isfile('user.pub'):
        os.system('openssl genrsa 4096 > user.key')
        os.system('openssl rsa -in user.key -pubout > user.pub')
    if not os.path.isfile('domain.csr'):
        os.system('openssl genrsa 4096 > domain.key')
        os.system('openssl req -new -sha256 -key domain.key -subj "/O=directdemocracy/C=CH" -config openssl-san.cfg' +
                  ' > domain.csr')
    if args.install_only:
        f = open("signed_chain.crt", "r")
        signed_crt = urllib.quote_plus(f.read())
        f.close()
    else:
        signed_crt = get_crt('user.key', 'domain.csr',
                             '/home/direeeti/www.directdemocracy.vote/httpdocs/.well-known/acme-challenge',
                             log=LOGGER, CA=DEFAULT_CA, disable_check=args.disable_check,
                             directory_url=DEFAULT_DIRECTORY_URL)
        f = open("new_signed_chain.crt", "w")
        f.write(signed_crt)
        f.close()
        signed_crt = urllib.quote_plus(signed_crt)
    f = open("domain.key", "r")
    key = urllib.quote_plus(f.read())
    f.close()
    domain = 'directdemocracy.vote'
    subdomains = ['', 'www', 'app', 'judge', 'notary', 'station']
    for subdomain in subdomains:
        if subdomain != '':
            subdomain += '.'
        subdomain += domain
        os.system("uapi SSL install_ssl domain=" + subdomain + " cert=\"" + signed_crt + "\" key=\"" + key + "\"")


if __name__ == "__main__":
    main(sys.argv[1:])
