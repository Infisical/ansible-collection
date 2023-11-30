from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase

HAS_INFISICAL = False
try:
    from infisical import InfisicalClient
    HAS_INFISICAL = True
except ImportError:
    HAS_INFISICAL = False

DOCUMENTATION = r"""
name: read_secrets
author:
  - Infisical Inc.

short_description: Look up secrets stored in Infisical
description:
  - Retrieve secrets from Infisical, granted the caller has the right permissions to access the secret.
  - Secrets can be located either by their name for individual secret loopups or by environment/folder path to return all secrets within the given scope.

options:
  token:
    description: The Infisical token used to authenticate 
    env:
      - name: INFISICAL_TOKEN
    required: True
    type: string
    version_added: 1.0.0
  url:
    description: Point to your self hosted instance of Infisical
    default: "https://app.infisical.com"
    env:
      - name: INFISICAL_URL
    required: False
    type: string
    version_added: 1.0.0
  path:
    description: "The folder path where the requested secret resides. For example: /services/backend"
    required: True
    type: string
    version_added: 1.0.0
  env_slug:
    description: "Used to select from which environment (environment slug) secrets should be fetched from. Environment slug is the short name of a given environment"
    required: True
    type: string
    version_added: 1.0.0
  secret_name:
    description: The name of the secret that should be fetched. The name should be exactly as it appears in Infisical
    required: False
    type: string
    version_added: 1.0.0
"""

EXAMPLES = r"""
vars:
  read_all_secrets_within_scope: "{{ lookup('infisical_vault', token='<>', path='/', env_slug='dev', url='https://spotify.infisical.com') }}"
  # [{ "key": "HOST", "value": "google.com" }, { "key": "SMTP", "value": "gmail.smtp.edu" }]

  read_secret_by_name_within_scope: "{{ lookup('infisical_vault', token='<>', path='/', env_slug='dev', secret_name='HOST', url='https://spotify.infisical.com') }}"
  # [{ "key": "HOST", "value": "google.com" }]
"""

class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs):
        self.set_options(var_options=variables, direct=kwargs)

        if not HAS_INFISICAL:
          raise AnsibleError("Please pip install infisical to use the infisical_vault lookup module.")

        infisical_token = self.get_option("token")
        url = self.get_option("url")

        if not infisical_token:
            raise AnsibleError("Infisical token is required")

        # Initialize the Infisical client
        client = InfisicalClient(token=infisical_token, site_url=url)

        secretName = kwargs.get('secret_name')
        envSlug = kwargs.get('env_slug')
        path = kwargs.get('path')

        if secretName:
            return self.get_single_secret(client, secretName, envSlug, path)
        else:
            return self.get_all_secrets(client, envSlug, path)

    def get_single_secret(self, client, secret_name, environment, path):
        try:
            secret = client.get_secret(secret_name=secret_name, environment=environment, path=path)
            return [{"value": secret.secret_value, "key": secret.secret_name}]
        except Exception as e:
            print(e)
            raise AnsibleError(f"Error fetching single secret {e}")

    def get_all_secrets(self, client, environment="dev", path="/"):
        try:
            secrets = client.get_all_secrets(environment=environment, path=path)
            return [{"value": s.secret_value, "key": s.secret_name} for s in secrets]
        except Exception as e:
            raise AnsibleError(f"Error fetching all secrets {e}")

