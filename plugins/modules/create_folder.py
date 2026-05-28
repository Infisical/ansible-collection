from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: create_folder
short_description: Create a folder (directory) in Infisical
version_added: "1.2.0"
author:
  - Infisical Inc.
description:
  - Create a new folder in Infisical at the specified path within a given project and environment.
  - Folders are used to organize secrets into hierarchical directories.
extends_documentation_fragment:
  - infisical.vault.auth

options:
  project_id:
    description: The ID of the project where the folder will be created.
    type: str
    required: true
  env_slug:
    description: >
      The environment slug where the folder will be created.
      Environment slug is the short name of a given environment.
    type: str
    required: true
  path:
    description: "The parent folder path where the new folder will be created. For example: /services/backend"
    type: str
    default: "/"
  name:
    description: The name of the folder to create.
    type: str
    required: true
  description:
    description: An optional description for the folder.
    type: str

seealso:
  - module: infisical.vault.login
    description: Use the login module to authenticate once and reuse the session.
  - module: infisical.vault.list_folders
    description: List folders at a given path.
  - module: infisical.vault.create_secret
    description: Create a secret inside a folder.
"""

EXAMPLES = r"""
# Create a folder with direct authentication
- name: Create a folder
  infisical.vault.create_folder:
    url: "https://app.infisical.com"
    auth_method: universal_auth
    universal_auth_client_id: "{{ client_id }}"
    universal_auth_client_secret: "{{ client_secret }}"
    project_id: "my-project-id"
    env_slug: "dev"
    path: "/"
    name: "services"
  register: created_folder

# Create a nested folder using login_data
- name: Login to Infisical
  infisical.vault.login:
    url: "https://app.infisical.com"
    auth_method: universal_auth
    universal_auth_client_id: "{{ client_id }}"
    universal_auth_client_secret: "{{ client_secret }}"
  register: infisical_login

- name: Create a backend folder under /services
  infisical.vault.create_folder:
    login_data: "{{ infisical_login.login_data }}"
    project_id: "my-project-id"
    env_slug: "prod"
    path: "/services"
    name: "backend"
    description: "Secrets for the backend service"
  register: created_folder
"""

RETURN = r"""
folder:
  description: The created folder.
  returned: success
  type: dict
  contains:
    id:
      description: The unique identifier of the folder.
      type: str
    name:
      description: The name of the folder.
      type: str
    path:
      description: The parent path where the folder was created.
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
        name=dict(type='str', required=True),
        description=dict(type='str'),
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
    )

    if module.check_mode:
        module.exit_json(
            changed=True,
            folder={'name': module.params['name'], 'path': module.params['path']},
        )

    try:
        login_data = module.params.get('login_data')
        client = get_sdk_client(module, login_data=login_data)

        folder = client.folders.create_folder(
            name=module.params['name'],
            environment_slug=module.params['env_slug'],
            project_id=module.params['project_id'],
            path=module.params['path'],
            description=module.params.get('description'),
        )

        module.exit_json(
            changed=True,
            folder=folder.to_dict(),
        )
    except Exception as e:
        module.fail_json(msg=f"Error creating folder: {type(e).__name__}: {e}")


def main():
    run_module()


if __name__ == '__main__':
    main()
