# Infisical Collection
This Ansible Infisical collection includes a variety of Ansible content to help automate the management of Infisical services. This collection is maintained by the Infisical team.

[View full documentation](https://galaxy.ansible.com/ui/repo/published/infisical/vault/)

## Ansible version compatibility

Tested with the Ansible Core >= 2.12.0 versions, and the current development version of Ansible. Ansible Core versions prior to 2.12.0 have not been tested.

## Python version compatibility

This collection depends on the Infisical SDK for Python. 

Requires Python 3.7 or greater.

## Installing this collection

You can install the Infisical collection with the Ansible Galaxy CLI:

    ansible-galaxy collection install infisical.vault

The python module dependencies are not installed by `ansible-galaxy`.  They can
be manually installed using pip:

    pip install infisicalsdk

## Using this collection

You can either call modules by their Fully Qualified Collection Name (FQCN), such as `infisical.vault.read_secrets`, or you can call modules by their short name if you list the `infisical.vault` collection in the playbook's `collections` keyword.

### Authentication

The Infisical Ansible Collection supports Universal Auth and OIDC for authenticating against Infisical.

#### Universal Auth
Using Universal Auth for authentication is the most straight-forward way to get started with using the Ansible collection. 

To use Universal Auth, you need to provide the Client ID and Client Secret of your Infisical Machine Identity.

```yaml
lookup('infisical.vault.read_secrets', auth_method="universal-auth" universal_auth_client_id='<client-id>', universal_auth_client_secret='<client-secret>' ...rest)
```

You can also provide the `auth_method`, `universal_auth_client_id`, and `universal_auth_client_secret` parameters through environment variables:

| Parameter Name               | Environment Variable Name                |
| ---------------------------- | ---------------------------------------- |
| auth_method                  | `INFISICAL_AUTH_METHOD`                  |
| universal_auth_client_id     | `INFISICAL_UNIVERSAL_AUTH_CLIENT_ID`     |
| universal_auth_client_secret | `INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET` |


#### OIDC Auth
To use OIDC Auth, you'll need to provide the ID of your machine identity, and the OIDC JWT to be used for authentication.

```yaml
lookup('infisical.vault.read_secrets', auth_method="oidc-auth" identity_id='<identity-id>', jwt='<oidc-jwt>' ...rest)
```
You can also provide the `auth_method`, `identity_id`, and `jwt` parameters through environment variables:

| Parameter Name  | Environment Variable Name |
| --------------- | ------------------------- |
| auth_method     | `INFISICAL_AUTH_METHOD`   |
| identity_id     | `INFISICAL_IDENTITY_ID`   |
| jwt             | `INFISICAL_JWT`           |


### Examples

```yaml
---
vars:
  read_all_secrets_within_scope: "{{ lookup('infisical.vault.read_secrets', universal_auth_client_id='<>', universal_auth_client_secret='<>', project_id='<>', path='/', env_slug='dev', url='https://spotify.infisical.com') }}"
  # [{ "key": "HOST", "value": "google.com" }, { "key": "SMTP", "value": "gmail.smtp.edu" }]

   read_all_secrets_as_dict: "{{ lookup('infisical.vault.read_secrets', universal_auth_client_id='<>', universal_auth_client_secret='<>', project_id='<>', path='/', env_slug='dev', as_dict=True, url='https://spotify.infisical.com') }}"
  # {"SECRET_KEY_1": "secret-value-1", "SECRET_KEY_2": "secret-value-2"} -> Can be accessed as secrets.SECRET_KEY_1

  read_secret_by_name_within_scope: "{{ lookup('infisical.vault.read_secrets', universal_auth_client_id='<>', universal_auth_client_secret='<>', project_id='<>', path='/', env_slug='dev', secret_name='HOST', url='https://spotify.infisical.com') }}"
  # { "key": "HOST", "value": "google.com" }
```

