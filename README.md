# Infisical Collection
This Ansible Infisical collection includes a variety of Ansible content to help automate the management of Infisical services. This collection is maintained by the Infisical team.

[View full documentation](https://galaxy.ansible.com/ui/repo/published/infisical_inc/vault/)

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

    pip install infisical

## Using this collection

You can either call modules by their Fully Qualified Collection Name (FQCN), such as `infisical.vault.read_secrets`, or you can call modules by their short name if you list the `infisical.vault` collection in the playbook's `collections` keyword:

```yaml
---
vars:
  read_all_secrets_within_scope: "{{ lookup('infisical.vault.read_secrets', token='<>', path='/', env_slug='dev', url='https://spotify.infisical.com') }}"
  # [{ "key": "HOST", "value": "google.com" }, { "key": "SMTP", "value": "gmail.smtp.edu" }]

  read_secret_by_name_within_scope: "{{ lookup('infisical.vault.read_secrets', token='<>', path='/', env_slug='dev', secret_name='HOST', url='https://spotify.infisical.com') }}"
  # [{ "key": "HOST", "value": "google.com" }]
```

