from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase

HAS_INFISICAL = False
try:
    from infisical_sdk import InfisicalSDKClient
    HAS_INFISICAL = True
except ImportError as e:
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
  universal_auth_client_id:
    description: The Machine Identity Client ID used to authenticate
    env:
      - name: UNIVERSAL_AUTH_MACHINE_IDENTITY_CLIENT_ID
    required: True
    type: string
    version_added: 1.0.0
  universal_auth_client_secret:
    description: The Machine Identity Client Secret used to authenticate
    env:
      - name: UNIVERSAL_AUTH_MACHINE_IDENTITY_CLIENT_SECRET
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
  project_id:
    description: "The ID of the project where the secrets are stored"
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
  read_all_secrets_within_scope: "{{ lookup('infisical_vault', universal_auth_client_id='<>', universal_auth_client_secret='<>', project_id='<>', path='/', env_slug='dev', url='https://spotify.infisical.com') }}"
  # [{ "key": "HOST", "value": "google.com" }, { "key": "SMTP", "value": "gmail.smtp.edu" }]

  read_secret_by_name_within_scope: "{{ lookup('infisical_vault', universal_auth_client_id='<>', universal_auth_client_secret='<>', project_id='<>', path='/', env_slug='dev', secret_name='HOST', url='https://spotify.infisical.com') }}"
  # [{ "key": "HOST", "value": "google.com" }]
"""


class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs):
        self.set_options(var_options=variables, direct=kwargs)
        if not HAS_INFISICAL:
            raise AnsibleError("Please pip install infisicalsdk to use the infisical_vault lookup module.")

        machine_identity_client_id = self.get_option("universal_auth_client_id")
        machine_identity_client_secret = self.get_option("universal_auth_client_secret")
        url = self.get_option("url")

        # Check if the required environment variables are set
        if not machine_identity_client_id or not machine_identity_client_secret:
            raise AnsibleError("Please provide the universal_auth_client_id and universal_auth_client_secret")

        client = InfisicalSDKClient(host=url)

        client.auth.universal_auth.login(
            machine_identity_client_id,
            machine_identity_client_secret
        )

        secretName = kwargs.get('secret_name')
        envSlug = kwargs.get('env_slug')
        path = kwargs.get('path')
        project_id = kwargs.get('project_id')

        if secretName:
            return self.get_single_secret(
                client,
                project_id,
                secretName,
                envSlug,
                path
            )
        else:
            return self.get_all_secrets(client, project_id, envSlug, path)

    def get_single_secret(
            self,
            client,
            project_id,
            secret_name,
            environment,
            path
    ):
        try:
            secret = client.secrets.get_secret_by_name(
                secret_name=secret_name,
                project_id=project_id,
                environment_slug=environment,
                secret_path=path
            )

            return [{"value": secret.secretValue, "key": secret.secretKey}]
        except Exception as e:
            print(e)
            raise AnsibleError(f"Error fetching single secret {e}")

    def get_all_secrets(self, client, project_id, environment="dev", path="/"):
        try:
            secrets = client.secrets.list_secrets(
                project_id=project_id,
                environment_slug=environment,
                secret_path=path
            )

            return [{"value": s.secretValue, "key": s.secretKey} for s in secrets.secrets]
        except Exception as e:
            raise AnsibleError(f"Error fetching all secrets {e}")

