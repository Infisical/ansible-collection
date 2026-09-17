from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: issue_certificate
short_description: Issue a certificate from Infisical Certificate Manager
version_added: "1.2.0"
author:
  - Infisical Inc.
description:
  - Issue an X.509 certificate from Infisical Certificate Manager via API enrollment.
  - Supports two issuance modes. Managed mode (default) where Infisical generates the private key,
    and CSR mode where you provide your own Certificate Signing Request.
  - The certificate is issued against a Certificate Profile which defines the issuing CA,
    certificate policy, and default attributes.
  - Requires the Certificate Profile to have API enrollment enabled.
extends_documentation_fragment:
  - infisical.vault.auth

options:
  profile_id:
    description: The ID of the Certificate Profile to issue the certificate from.
    type: str
    required: true
  application_id:
    description: The ID of the PKI Application to associate the certificate with.
    type: str
  csr:
    description:
      - A PEM-encoded Certificate Signing Request (CSR).
      - When provided, Infisical signs the CSR instead of generating a new key pair.
      - Subject attributes and key algorithm are extracted from the CSR.
      - The private key is NOT returned in CSR mode (you already have it).
    type: str
  common_name:
    description: The Common Name (CN) for the certificate subject (e.g. C(api.example.com)).
    type: str
  organization:
    description: The Organization (O) for the certificate subject.
    type: str
  organizational_unit:
    description: The Organizational Unit (OU) for the certificate subject.
    type: str
  country:
    description: The Country (C) for the certificate subject.
    type: str
  state:
    description: The State or Province (ST) for the certificate subject.
    type: str
  locality:
    description: The Locality (L) for the certificate subject.
    type: str
  ttl:
    description:
      - The validity period of the certificate.
      - Example values are C(90d), C(1y), C(8760h).
      - Mutually exclusive with C(not_before)/C(not_after).
    type: str
  not_before:
    description:
      - The start of the certificate validity period as a date-time string.
      - Mutually exclusive with C(ttl).
    type: str
  not_after:
    description:
      - The end of the certificate validity period as a date-time string.
      - Mutually exclusive with C(ttl).
    type: str
  key_algorithm:
    description:
      - The key algorithm for the certificate key pair (managed mode only).
      - Mutually exclusive with C(csr) since the key algorithm is extracted from the CSR.
    type: str
    choices:
      - RSA_2048
      - RSA_3072
      - RSA_4096
      - EC_prime256v1
      - EC_secp384r1
      - EC_secp521r1
      - ML-DSA-44
      - ML-DSA-65
      - ML-DSA-87
      - SLH-DSA-SHA2-128f
      - SLH-DSA-SHA2-128s
      - SLH-DSA-SHA2-192f
      - SLH-DSA-SHA2-192s
      - SLH-DSA-SHA2-256f
      - SLH-DSA-SHA2-256s
      - SLH-DSA-SHAKE-128f
      - SLH-DSA-SHAKE-128s
      - SLH-DSA-SHAKE-192f
      - SLH-DSA-SHAKE-192s
      - SLH-DSA-SHAKE-256f
      - SLH-DSA-SHAKE-256s
  signature_algorithm:
    description: The signature algorithm used to sign the certificate.
    type: str
    choices:
      - RSA-SHA256
      - RSA-SHA384
      - RSA-SHA512
      - ECDSA-SHA256
      - ECDSA-SHA384
      - ECDSA-SHA512
      - ML-DSA-44
      - ML-DSA-65
      - ML-DSA-87
      - SLH-DSA-SHA2-128f
      - SLH-DSA-SHA2-128s
      - SLH-DSA-SHA2-192f
      - SLH-DSA-SHA2-192s
      - SLH-DSA-SHA2-256f
      - SLH-DSA-SHA2-256s
      - SLH-DSA-SHAKE-128f
      - SLH-DSA-SHAKE-128s
      - SLH-DSA-SHAKE-192f
      - SLH-DSA-SHAKE-192s
      - SLH-DSA-SHAKE-256f
      - SLH-DSA-SHAKE-256s
  alt_names:
    description:
      - A list of Subject Alternative Names (SANs) for the certificate.
      - Each item must have a C(type) and C(value).
    type: list
    elements: dict
    suboptions:
      type:
        description: The SAN type.
        type: str
        required: true
        choices:
          - DNS
          - EMAIL
          - IP
          - URI
      value:
        description: The SAN value (e.g. C(api.example.com), C(10.0.0.1)).
        type: str
        required: true
  key_usages:
    description: A list of key usage extensions for the certificate.
    type: list
    elements: str
  extended_key_usages:
    description: A list of extended key usage extensions for the certificate.
    type: list
    elements: str
  basic_constraints:
    description: Basic constraints extension for the certificate.
    type: dict
    suboptions:
      is_ca:
        description: Whether the certificate is a CA certificate.
        type: bool
        required: true
      path_length:
        description: Maximum number of intermediate CAs allowed below this CA.
        type: int
  remove_roots_from_chain:
    description: Whether to remove root CA certificates from the returned chain.
    type: bool
  metadata:
    description:
      - A list of metadata key-value pairs to attach to the certificate.
      - Metadata is preserved across renewals and can be used for filtering.
    type: list
    elements: dict
    suboptions:
      key:
        description: The metadata key.
        type: str
        required: true
      value:
        description: The metadata value.
        type: str
        required: true

seealso:
  - module: infisical.vault.login
    description: Use the login module to authenticate once and reuse the session.
"""

EXAMPLES = r"""
# Issue a managed certificate with Infisical-generated key
- name: Login to Infisical
  infisical.vault.login:
    url: "https://app.infisical.com"
    auth_method: universal_auth
    universal_auth_client_id: "{{ client_id }}"
    universal_auth_client_secret: "{{ client_secret }}"
  register: infisical_login

- name: Issue a TLS certificate
  infisical.vault.issue_certificate:
    login_data: "{{ infisical_login.login_data }}"
    profile_id: "your-profile-id"
    common_name: "api.example.com"
    ttl: "90d"
    alt_names:
      - type: DNS
        value: "api.example.com"
      - type: DNS
        value: "www.api.example.com"
  register: cert
  no_log: true

- name: Write certificate to file
  ansible.builtin.copy:
    content: "{{ cert.certificate }}"
    dest: /etc/ssl/certs/api.pem
    mode: '0644'

- name: Write private key to file
  ansible.builtin.copy:
    content: "{{ cert.private_key }}"
    dest: /etc/ssl/private/api.key
    mode: '0600'
  no_log: true

# Issue a certificate with a CSR (bring your own key)
- name: Issue certificate from CSR
  infisical.vault.issue_certificate:
    login_data: "{{ infisical_login.login_data }}"
    profile_id: "your-profile-id"
    csr: "{{ lookup('file', '/path/to/request.csr') }}"
    ttl: "90d"
  register: cert

# Issue a certificate with specific algorithms and metadata
- name: Issue certificate with options
  infisical.vault.issue_certificate:
    login_data: "{{ infisical_login.login_data }}"
    profile_id: "your-profile-id"
    common_name: "db.internal"
    ttl: "30d"
    key_algorithm: EC_prime256v1
    signature_algorithm: ECDSA-SHA256
    alt_names:
      - type: IP
        value: "10.0.1.5"
    metadata:
      - key: env
        value: production
      - key: service
        value: payments
  register: cert

# Issue a certificate scoped to an Application
- name: Issue certificate for application
  infisical.vault.issue_certificate:
    login_data: "{{ infisical_login.login_data }}"
    profile_id: "your-profile-id"
    application_id: "your-application-id"
    common_name: "payments-api.internal"
    ttl: "90d"
  register: cert
"""

RETURN = r"""
certificate:
  description: The PEM-encoded certificate body.
  returned: when status is 'issued'
  type: str
issuing_ca_certificate:
  description: The PEM-encoded issuing CA certificate.
  returned: when status is 'issued'
  type: str
certificate_chain:
  description: The PEM-encoded full certificate chain.
  returned: when status is 'issued'
  type: str
private_key:
  description:
    - The PEM-encoded private key (only returned for managed-key issuance, not CSR).
    - This value is sensitive. Use C(no_log=true) on the task to prevent it from appearing in Ansible logs.
  returned: when status is 'issued' and no CSR was provided
  type: str
serial_number:
  description: The serial number of the issued certificate.
  returned: when status is 'issued'
  type: str
certificate_id:
  description: The unique identifier of the certificate in Infisical.
  returned: when status is 'issued'
  type: str
certificate_request_id:
  description: The ID of the certificate request. Can be used to poll status for pending requests.
  returned: always
  type: str
status:
  description: >
    The status of the certificate request.
    C(issued) means the certificate is ready.
    C(pending_approval) means it requires human review.
    C(pending_validation) means the CA is validating the request.
  returned: always
  type: str
message:
  description: A human-readable message about the request status (for non-issued states).
  returned: when status is not 'issued'
  type: str
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.infisical.vault.plugins.module_utils._authenticator import (
    InfisicalAuthenticator,
    create_client_from_login_data,
)


def get_sdk_client(module, login_data=None):
    """Get an authenticated Infisical SDK client."""
    if login_data is not None:
        try:
            return create_client_from_login_data(login_data)
        except (ImportError, ValueError) as e:
            module.fail_json(msg=str(e))

    try:
        authenticator = InfisicalAuthenticator(
            url=module.params['url'],
            auth_method=module.params['auth_method'],
            client_id=module.params['universal_auth_client_id'],
            client_secret=module.params['universal_auth_client_secret'],
            identity_id=module.params['identity_id'],
            jwt=module.params['jwt'],
            token=module.params['token'],
            ldap_username=module.params['ldap_username'],
            ldap_password=module.params['ldap_password'],
        )
        return authenticator.authenticate()
    except (ImportError, ValueError) as e:
        module.fail_json(msg=str(e))


def build_request_body(params):
    """Build the API request body from module parameters."""
    body = {
        "profileId": params["profile_id"],
    }

    if params.get("application_id"):
        body["applicationId"] = params["application_id"]

    if params.get("csr"):
        body["csr"] = params["csr"]

    if params.get("remove_roots_from_chain") is not None:
        body["removeRootsFromChain"] = params["remove_roots_from_chain"]

    if params.get("metadata"):
        body["metadata"] = params["metadata"]

    # Build attributes object
    attributes = {}

    subject_field_map = {
        "common_name": "commonName",
        "organization": "organization",
        "organizational_unit": "organizationalUnit",
        "country": "country",
        "state": "state",
        "locality": "locality",
    }
    for param_key, api_key in subject_field_map.items():
        if params.get(param_key) is not None:
            attributes[api_key] = params[param_key]

    if params.get("ttl"):
        attributes["ttl"] = params["ttl"]

    if params.get("not_before"):
        attributes["notBefore"] = params["not_before"]

    if params.get("not_after"):
        attributes["notAfter"] = params["not_after"]

    if params.get("key_algorithm"):
        attributes["keyAlgorithm"] = params["key_algorithm"]

    if params.get("signature_algorithm"):
        attributes["signatureAlgorithm"] = params["signature_algorithm"]

    if params.get("alt_names"):
        attributes["altNames"] = params["alt_names"]

    if params.get("key_usages"):
        attributes["keyUsages"] = params["key_usages"]

    if params.get("extended_key_usages"):
        attributes["extendedKeyUsages"] = params["extended_key_usages"]

    if params.get("basic_constraints"):
        bc = params["basic_constraints"]
        if "is_ca" not in bc:
            raise ValueError("basic_constraints requires 'is_ca' to be set")
        attributes["basicConstraints"] = {
            "isCA": bc["is_ca"],
        }
        if bc.get("path_length") is not None:
            attributes["basicConstraints"]["pathLength"] = bc["path_length"]

    if attributes:
        body["attributes"] = attributes

    return body


def run_module():
    module_args = dict(
        # Auth options (same pattern as all other modules)
        login_data=dict(type='dict', no_log=True),
        url=dict(type='str', default='https://app.infisical.com'),
        auth_method=dict(
            type='str',
            default='universal_auth',
            choices=['universal_auth', 'oidc_auth', 'token_auth', 'ldap_auth']
        ),
        universal_auth_client_id=dict(type='str'),
        universal_auth_client_secret=dict(type='str', no_log=True),
        identity_id=dict(type='str'),
        jwt=dict(type='str', no_log=True),
        token=dict(type='str', no_log=True),
        ldap_username=dict(type='str'),
        ldap_password=dict(type='str', no_log=True),
        # Certificate options
        profile_id=dict(type='str', required=True),
        application_id=dict(type='str'),
        csr=dict(type='str'),
        common_name=dict(type='str'),
        organization=dict(type='str'),
        organizational_unit=dict(type='str'),
        country=dict(type='str'),
        state=dict(type='str'),
        locality=dict(type='str'),
        ttl=dict(type='str'),
        not_before=dict(type='str'),
        not_after=dict(type='str'),
        key_algorithm=dict(
            type='str',
            choices=[
                'RSA_2048', 'RSA_3072', 'RSA_4096',
                'EC_prime256v1', 'EC_secp384r1', 'EC_secp521r1',
                'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87',
                'SLH-DSA-SHA2-128f', 'SLH-DSA-SHA2-128s',
                'SLH-DSA-SHA2-192f', 'SLH-DSA-SHA2-192s',
                'SLH-DSA-SHA2-256f', 'SLH-DSA-SHA2-256s',
                'SLH-DSA-SHAKE-128f', 'SLH-DSA-SHAKE-128s',
                'SLH-DSA-SHAKE-192f', 'SLH-DSA-SHAKE-192s',
                'SLH-DSA-SHAKE-256f', 'SLH-DSA-SHAKE-256s',
            ]
        ),
        signature_algorithm=dict(
            type='str',
            choices=[
                'RSA-SHA256', 'RSA-SHA384', 'RSA-SHA512',
                'ECDSA-SHA256', 'ECDSA-SHA384', 'ECDSA-SHA512',
                'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87',
                'SLH-DSA-SHA2-128f', 'SLH-DSA-SHA2-128s',
                'SLH-DSA-SHA2-192f', 'SLH-DSA-SHA2-192s',
                'SLH-DSA-SHA2-256f', 'SLH-DSA-SHA2-256s',
                'SLH-DSA-SHAKE-128f', 'SLH-DSA-SHAKE-128s',
                'SLH-DSA-SHAKE-192f', 'SLH-DSA-SHAKE-192s',
                'SLH-DSA-SHAKE-256f', 'SLH-DSA-SHAKE-256s',
            ]
        ),
        alt_names=dict(type='list', elements='dict'),
        key_usages=dict(type='list', elements='str'),
        extended_key_usages=dict(type='list', elements='str'),
        basic_constraints=dict(type='dict'),
        remove_roots_from_chain=dict(type='bool'),
        metadata=dict(type='list', elements='dict'),
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
        mutually_exclusive=[
            ('ttl', 'not_before'),
            ('ttl', 'not_after'),
            ('csr', 'key_algorithm'),
        ],
        required_together=[
            ('not_before', 'not_after'),
        ],
    )

    if module.check_mode:
        module.exit_json(
            changed=True,
            certificate='<check_mode>',
            certificate_request_id='<check_mode>',
            status='issued',
        )

    try:
        login_data = module.params.get('login_data')
        client = get_sdk_client(module, login_data=login_data)

        request_body = build_request_body(module.params)

        response = client.api.post(
            "/api/v1/cert-manager/certificates",
            dict,
            json=request_body
        )

        data = response.data

        cert_data = data.get("certificate")
        request_id = data.get("certificateRequestId", "")
        status = data.get("status") or ("issued" if cert_data else "pending")
        message = data.get("message")

        result = dict(
            changed=True,
            certificate_request_id=request_id,
            status=status,
        )

        if cert_data:
            result["certificate"] = cert_data.get("certificate", "")
            result["issuing_ca_certificate"] = cert_data.get("issuingCaCertificate", "")
            result["certificate_chain"] = cert_data.get("certificateChain", "")
            result["serial_number"] = cert_data.get("serialNumber", "")
            result["certificate_id"] = cert_data.get("certificateId", "")

            private_key = cert_data.get("privateKey")
            if private_key:
                result["private_key"] = private_key

        if message:
            result["message"] = message

        module.exit_json(**result)
    except Exception as e:
        module.fail_json(msg="Error issuing certificate: %s: %s" % (type(e).__name__, e))


def main():
    run_module()


if __name__ == '__main__':
    main()
