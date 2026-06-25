from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: list_folders
short_description: List folders (directories) in Infisical
version_added: "1.2.0"
author:
  - Infisical Inc.
description:
  - List folders at the specified path within a given project and environment.
  - Optionally walks the folder tree recursively.
extends_documentation_fragment:
  - infisical.vault.auth

options:
  project_id:
    description: The ID of the project to list folders from.
    type: str
    required: true
  env_slug:
    description: >
      The environment slug to list folders from.
      Environment slug is the short name of a given environment.
    type: str
    required: true
  path:
    description: "The folder path to list folders under. For example: /services"
    type: str
    default: "/"
  recursive:
    description: Whether to list folders recursively under the given path.
    type: bool
    default: false

seealso:
  - module: infisical.vault.login
    description: Use the login module to authenticate once and reuse the session.
  - module: infisical.vault.create_folder
    description: Create a new folder.
  - module: infisical.vault.read_secrets
    description: Read secrets from a folder.
"""

EXAMPLES = r"""
# List top-level folders
- name: List folders at root
  infisical.vault.list_folders:
    login_data: "{{ infisical_login.login_data }}"
    project_id: "my-project-id"
    env_slug: "dev"
    path: "/"
  register: result

- name: Show folder names
  debug:
    msg: "{{ result.folders | map(attribute='name') | list }}"

# Recursive listing under /services
- name: List all folders under /services recursively
  infisical.vault.list_folders:
    login_data: "{{ infisical_login.login_data }}"
    project_id: "my-project-id"
    env_slug: "prod"
    path: "/services"
    recursive: true
  register: result
"""

RETURN = r"""
folders:
  description: The list of folders at the specified path.
  returned: success
  type: list
  elements: dict
  contains:
    id:
      description: The unique identifier of the folder.
      type: str
    name:
      description: The name of the folder.
      type: str
    envId:
      description: The ID of the environment the folder belongs to.
      type: str
    parentId:
      description: The ID of the parent folder.
      type: str
    version:
      description: The version number of the folder.
      type: int
    description:
      description: The folder description.
      type: str
    isReserved:
      description: Whether the folder is reserved by Infisical.
      type: bool
    relativePath:
      description: The relative path to the folder (when recursive listing).
      type: str
    createdAt:
      description: The creation timestamp.
      type: str
    updatedAt:
      description: The last update timestamp.
      type: str
    lastSecretModified:
      description: Timestamp when a secret in this folder was last modified.
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


def run_module():
    module_args = dict(
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
        project_id=dict(type='str', required=True),
        env_slug=dict(type='str', required=True),
        path=dict(type='str', default='/'),
        recursive=dict(type='bool', default=False),
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
    )

    if module.check_mode:
        module.exit_json(changed=False, folders=[])

    try:
        login_data = module.params.get('login_data')
        client = get_sdk_client(module, login_data=login_data)

        response = client.folders.list_folders(
            project_id=module.params['project_id'],
            environment_slug=module.params['env_slug'],
            path=module.params['path'],
            recursive=module.params['recursive'],
        )

        module.exit_json(
            changed=False,
            folders=[f.to_dict() for f in response.folders],
        )
    except Exception as e:
        module.fail_json(msg=f"Error listing folders: {type(e).__name__}: {e}")


def main():
    run_module()


if __name__ == '__main__':
    main()
