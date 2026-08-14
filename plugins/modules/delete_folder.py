from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: delete_folder
short_description: Delete a secret folder in Infisical
version_added: "1.2.0"
author:
  - Infisical Inc.
description:
  - Delete a secret folder from Infisical.
  - The folder must already exist and can be identified by either its ID or its name.
extends_documentation_fragment:
  - infisical.vault.auth

options:
  project_id:
    description: The ID of the project where the folder resides.
    type: str
    required: true
  env_slug:
    description: >
      The environment slug where the folder resides.
      Environment slug is the short name of a given environment.
    type: str
    required: true
  path:
    description: "The parent folder path the folder resides in. For example: /services"
    type: str
    required: true
  folder_id_or_name:
    description: The ID or the name of the folder to delete.
    type: str
    required: true
  force_delete:
    description:
      - Delete the folder even when it still contains secrets or subfolders.
      - Everything inside the folder is removed along with it.
    type: bool
    default: false

notes:
  - Requires a version of the C(infisicalsdk) Python package that supports folder deletion.

seealso:
  - module: infisical.vault.login
    description: Use the login module to authenticate once and reuse the session.
  - module: infisical.vault.create_folder
    description: Create a secret folder.
  - module: infisical.vault.read_folders
    description: Read secret folders from Infisical.
  - module: infisical.vault.update_folder
    description: Update an existing secret folder.
"""

EXAMPLES = r"""
# Delete a folder by name with direct authentication
- name: Delete a folder
  infisical.vault.delete_folder:
    url: "https://app.infisical.com"
    auth_method: universal_auth
    universal_auth_client_id: "{{ client_id }}"
    universal_auth_client_secret: "{{ client_secret }}"
    project_id: "my-project-id"
    env_slug: "dev"
    path: "/services"
    folder_id_or_name: "backend"
  register: deleted_folder

# Delete a folder using login_data
- name: Login to Infisical
  infisical.vault.login:
    url: "https://app.infisical.com"
    auth_method: universal_auth
    universal_auth_client_id: "{{ client_id }}"
    universal_auth_client_secret: "{{ client_secret }}"
  register: infisical_login

- name: Delete a folder along with everything inside it
  infisical.vault.delete_folder:
    login_data: "{{ infisical_login.login_data }}"
    project_id: "my-project-id"
    env_slug: "prod"
    path: "/services"
    folder_id_or_name: "backend"
    force_delete: true
  register: deleted_folder

- name: Delete a folder by ID
  infisical.vault.delete_folder:
    login_data: "{{ infisical_login.login_data }}"
    project_id: "my-project-id"
    env_slug: "prod"
    path: "/services"
    folder_id_or_name: "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
  register: deleted_folder
"""

RETURN = r"""
folder:
  description:
    - The deleted folder.
    - The delete response does not include the folder path.
  returned: success
  type: dict
  contains:
    id:
      description: The unique identifier of the folder.
      type: str
    name:
      description: The name of the folder.
      type: str
    description:
      description: The description of the folder.
      type: str
    envId:
      description: The ID of the environment the folder belonged to.
      type: str
    parentId:
      description: The ID of the parent folder.
      type: str
    version:
      description: The version number of the folder.
      type: int
    isReserved:
      description: Whether the folder is reserved by Infisical.
      type: bool
    lastSecretModified:
      description: Timestamp of the last secret modification within the folder.
      type: str
    createdAt:
      description: The creation timestamp.
      type: str
    updatedAt:
      description: The last update timestamp.
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
            choices=['universal_auth', 'oidc_auth', 'token_auth']
        ),
        universal_auth_client_id=dict(type='str'),
        universal_auth_client_secret=dict(type='str', no_log=True),
        identity_id=dict(type='str'),
        jwt=dict(type='str', no_log=True),
        token=dict(type='str', no_log=True),
        project_id=dict(type='str', required=True),
        env_slug=dict(type='str', required=True),
        path=dict(type='str', required=True),
        folder_id_or_name=dict(type='str', required=True),
        force_delete=dict(type='bool', default=False),
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
    )

    if module.check_mode:
        module.exit_json(
            changed=True,
            folder={'name': module.params['folder_id_or_name'], 'path': module.params['path']},
        )

    try:
        login_data = module.params.get('login_data')
        client = get_sdk_client(module, login_data=login_data)

        folder = client.folders.delete_folder(
            folder_id_or_name=module.params['folder_id_or_name'],
            project_id=module.params['project_id'],
            environment_slug=module.params['env_slug'],
            path=module.params['path'],
            force_delete=module.params['force_delete'],
        )

        module.exit_json(
            changed=True,
            folder=folder.to_dict(),
        )
    except Exception as e:
        module.fail_json(msg=f"Error deleting folder: {type(e).__name__}: {e}")


def main():
    run_module()


if __name__ == '__main__':
    main()
