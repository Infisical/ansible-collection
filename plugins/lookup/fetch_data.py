from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase
import requests

class LookupModule(LookupBase):
    
    def run(self, terms, variables=None, **kwargs):
        # URL from the terms or you can define it within the plugin
        url = terms[0]

        try:
            response = requests.get(url)
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx and 5xx)
            return [response.json()]
        except requests.RequestException as e:
            raise AnsibleError("Error fetching data from {}: {}".format(url, e))

